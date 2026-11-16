"""Filesystem adapter and delivery protocol.

Chunks and manifests are immutable content-addressed objects. Manifests are
authenticated with injected HMAC keys; ``resolve`` is the single trust gate
consumed by ``load``, ``verify`` and ``restore``, so every operation acts on
the same trust conclusion and a manifest that fails authentication is never
restored from.
"""
import hashlib
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path

from .formats import (
    AuthenticationError,
    IntegrityError,
    authenticate_manifest,
    decode_chunk,
    digest,
    encode,
    encode_chunk,
    relative_path,
    sign_manifest,
    valid_digest,
    valid_key_id,
    validate_legacy_manifest,
    validate_manifest,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None


class RestoreBusyError(ValueError):
    """Another restore session actively owns the destination."""


class SessionConflictError(ValueError):
    """The destination holds an incompatible interrupted session."""


_OBJECT_BLOCK = 1 << 16


def atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class TrustDecision:
    """The single trust conclusion consumed by load, verify and restore."""

    __slots__ = ("snapshot", "manifest", "authenticated", "legacy", "key_id")

    def __init__(self, snapshot, manifest, *, authenticated, legacy, key_id):
        self.snapshot = snapshot
        self.manifest = manifest
        self.authenticated = authenticated
        self.legacy = legacy
        self.key_id = key_id

    def summary(self):
        return {
            "snapshot": self.snapshot,
            "authenticated": self.authenticated,
            "legacy": self.legacy,
            "keyid": self.key_id,
        }


class Repository:
    def __init__(self, root, *, keys=None, sign_with=None, allow_legacy=False):
        """Open a repository.

        ``keys`` maps key ids to secret bytes (at least 16 bytes each); keys
        are injected by the caller and never persisted. ``sign_with`` is the
        default key id for new snapshots. ``allow_legacy`` explicitly opts in
        to reading unauthenticated format 1 manifests; they are still never
        reported as authenticated.
        """
        self.root = Path(root).resolve()
        (self.root / "chunks").mkdir(parents=True, exist_ok=True)
        (self.root / "manifests").mkdir(exist_ok=True)
        self.keys = {}
        for key_id, key in (keys or {}).items():
            valid_key_id(key_id)
            if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
                raise ValueError(f"key {key_id!r} must be at least 16 bytes")
            self.keys[key_id] = bytes(key)
        if sign_with is not None:
            valid_key_id(sign_with)
        self.sign_with = sign_with
        self.allow_legacy = allow_legacy

    # --- trust gate -----------------------------------------------------------

    def resolve(self, snapshot):
        """Authenticate and validate a manifest. The one trust gate.

        Returns a TrustDecision. Raises AuthenticationError when the manifest
        cannot be authenticated with the injected keys (or is legacy without
        an explicit legacy policy) and IntegrityError when the object itself
        is malformed or does not match its content address.
        """
        valid_digest(snapshot)
        try:
            content = (self.root / "manifests" / (snapshot + ".json")).read_bytes()
        except OSError as exc:
            raise IntegrityError(f"missing manifest {snapshot}") from exc
        if digest(content) != snapshot:
            raise IntegrityError("manifest checksum mismatch")
        try:
            manifest = json.loads(content)
        except json.JSONDecodeError as exc:
            raise IntegrityError("malformed manifest") from exc
        if not isinstance(manifest, dict):
            raise IntegrityError("malformed manifest")
        fmt = manifest.get("format")
        if fmt == 1:
            if not self.allow_legacy:
                raise AuthenticationError("legacy manifest requires an explicit legacy policy")
            try:
                validate_legacy_manifest(manifest)
            except TypeError as exc:
                raise IntegrityError("malformed manifest") from exc
            return TrustDecision(snapshot, manifest, authenticated=False, legacy=True, key_id=None)
        if fmt != 2:
            raise IntegrityError("unsupported manifest format")
        key_id = authenticate_manifest(manifest, self.keys)
        try:
            validate_manifest(manifest)
        except TypeError as exc:
            raise IntegrityError("malformed manifest") from exc
        return TrustDecision(snapshot, manifest, authenticated=True, legacy=False, key_id=key_id)

    def load(self, snapshot):
        return self.resolve(snapshot).manifest

    # --- object store -----------------------------------------------------------

    def _object_path(self, sha):
        return self.root / "chunks" / valid_digest(sha)

    def _read_object(self, sha, size):
        """Read one stored object, bounded by its declared encoded size.

        Reading stops as soon as the object grows past the declared size, so
        oversized objects are rejected within bounded memory.
        """
        path = self._object_path(sha)
        hasher = hashlib.sha256()
        parts = []
        total = 0
        try:
            stream = path.open("rb")
        except OSError as exc:
            raise IntegrityError(f"missing object {sha}") from exc
        with stream:
            while True:
                block = stream.read(min(_OBJECT_BLOCK, size + 1 - total))
                if not block:
                    break
                total += len(block)
                if total > size:
                    raise IntegrityError(f"object {sha} exceeds its declared size")
                hasher.update(block)
                parts.append(block)
        if total != size:
            raise IntegrityError(f"object {sha} size mismatch")
        if hasher.hexdigest() != sha:
            raise IntegrityError(f"corrupt object {sha}")
        return b"".join(parts)

    @staticmethod
    def _chunk_binding(chunk):
        """Logical/encoded binding for format 2 and legacy chunk records."""
        if "encoded_sha256" in chunk:
            return chunk["encoded_sha256"], chunk["encoded_size"], chunk["codec"], chunk["codec_version"]
        return chunk["sha256"], chunk["size"], "identity", 1

    def _load_chunk(self, chunk):
        """Read, decode and fully verify one chunk against its manifest record.

        The encoded object digest and size are checked before decoding, the
        decoder is bounded by the declared logical size, and the decoded
        logical digest is verified afterwards.
        """
        encoded_sha, encoded_size, codec, version = self._chunk_binding(chunk)
        encoded = self._read_object(encoded_sha, encoded_size)
        data = decode_chunk(codec, version, encoded, chunk["size"])
        if digest(data) != chunk["sha256"]:
            raise IntegrityError(f"chunk {chunk['sha256']} logical content mismatch")
        return data

    # --- snapshot ---------------------------------------------------------------

    def snapshot(self, source, *, chunk_size=1024 * 1024, base=None, metadata=None,
                 compress=False, key_id=None):
        if type(chunk_size) is not int or chunk_size < 1:
            raise ValueError("chunk size must be positive")
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("metadata must be an object")
        key_id = key_id or self.sign_with
        if key_id is None:
            raise ValueError("snapshot requires a signing key id")
        key = self.keys.get(key_id)
        if key is None:
            raise ValueError(f"unknown signing key id: {key_id}")
        source = Path(source).resolve()
        if not source.is_dir():
            raise ValueError("source must be a directory")
        if self.root == source or source in self.root.parents or self.root in source.parents:
            raise ValueError("source and repository must not overlap")
        baseline = self.resolve(base).manifest["files"] if base else {}
        files = {}
        before_names = sorted(source.rglob("*"))
        for path in before_names:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError(f"symlinks are not supported: {path}")
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("only regular files can be packaged")
            name = path.relative_to(source).as_posix()
            relative_path(name)
            chunks, size = [], 0
            file_hash = hashlib.sha256()
            # O_NOFOLLOW closes the final-component symlink replacement window.
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError("source replaced while snapshotting")
                while data := stream.read(chunk_size):
                    logical_sha = digest(data)
                    if compress:
                        packed = encode_chunk("zlib", 1, data)
                        if len(packed) < len(data):
                            codec, version, encoded = "zlib", 1, packed
                        else:
                            codec, version, encoded = "identity", 1, data
                    else:
                        codec, version, encoded = "identity", 1, data
                    encoded_sha = digest(encoded)
                    object_path = self._object_path(encoded_sha)
                    if not object_path.exists():
                        atomic_write(object_path, encoded)
                    else:
                        # Prove the pre-existing object matches its address.
                        self._read_object(encoded_sha, len(encoded))
                    chunks.append({
                        "sha256": logical_sha,
                        "size": len(data),
                        "codec": codec,
                        "codec_version": version,
                        "encoded_sha256": encoded_sha,
                        "encoded_size": len(encoded),
                    })
                    file_hash.update(data)
                    size += len(data)
                after = os.fstat(stream.fileno())
            current = path.lstat()
            signature = lambda s: (s.st_ino, s.st_dev, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if signature(info) != signature(after) or signature(info) != signature(current):
                raise ValueError("source changed while snapshotting")
            files[name] = {"sha256": file_hash.hexdigest(), "size": size, "chunks": chunks}
        if before_names != sorted(source.rglob("*")):
            raise ValueError("source file set changed while snapshotting")
        manifest = {
            "format": 2,
            "base": base,
            "files": files,
            "metadata": metadata or {},
            "changed": sorted(n for n, entry in files.items() if baseline.get(n) != entry),
            "deleted": sorted(set(baseline) - set(files)),
        }
        sign_manifest(manifest, key_id, key)
        content = encode(manifest)
        snapshot_id = digest(content)
        atomic_write(self.root / "manifests" / (snapshot_id + ".json"), content)
        return snapshot_id

    # --- verify -----------------------------------------------------------------

    def verify(self, snapshot):
        decision = self.resolve(snapshot)
        errors = []
        for name, entry in decision.manifest["files"].items():
            file_hash = hashlib.sha256()
            try:
                for chunk in entry["chunks"]:
                    file_hash.update(self._load_chunk(chunk))
                if file_hash.hexdigest() != entry["sha256"]:
                    raise IntegrityError("file checksum mismatch")
            except IntegrityError as exc:
                errors.append({"file": name, "error": str(exc)})
        return {
            **decision.summary(),
            "ok": not errors,
            "files": len(decision.manifest["files"]),
            "errors": errors,
        }

    # --- restore ------------------------------------------------------------------

    @staticmethod
    def _safe_target(root, name):
        path = root.joinpath(*relative_path(name).parts)
        for current in [path, *path.parents]:
            if current == root.parent:
                break
            if current.is_symlink():
                raise IntegrityError("restore path contains a symlink")
        return path

    @staticmethod
    def _session_params(decision, selected, names, required_metadata):
        """The contract a restore session pins: snapshot identity, file
        selection, metadata requirements and the codec contract."""
        manifest = decision.manifest
        codecs = sorted({
            f"{chunk.get('codec', 'identity')}@{chunk.get('codec_version', 1)}"
            for entry in manifest["files"].values()
            for chunk in entry["chunks"]
        })
        return {
            "protocol": 2,
            "snapshot": decision.snapshot,
            "selected": None if selected is None else names,
            "required_metadata": required_metadata,
            "format": manifest["format"],
            "codecs": codecs,
        }

    @staticmethod
    def _acquire_lock(state_root):
        lock_path = state_root / "lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        if fcntl is None:  # pragma: no cover - non-POSIX: no mutual exclusion
            return fd
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise RestoreBusyError("destination is owned by another active restore") from exc
        # The locked inode must still be the linked one, otherwise a finished
        # session cleaned up in between and this lock guards nothing.
        try:
            linked = os.stat(lock_path)
        except OSError:
            linked = None
        held = os.fstat(fd)
        if linked is None or (linked.st_dev, linked.st_ino) != (held.st_dev, held.st_ino):
            os.close(fd)
            raise RestoreBusyError("restore lock was replaced; destination is contended")
        return fd

    @staticmethod
    def _release_lock(state_root, fd):
        # Unlink while still holding the lock, and only if it is still ours.
        try:
            held = os.fstat(fd)
            linked = os.stat(state_root / "lock")
            if (linked.st_dev, linked.st_ino) == (held.st_dev, held.st_ino):
                os.unlink(state_root / "lock")
        except OSError:
            pass
        os.close(fd)
        try:
            state_root.rmdir()
        except OSError:
            pass

    @staticmethod
    def _wipe_session(state_root):
        for child in state_root.iterdir():
            if child.name == "lock":
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()

    def _restore_files(self, manifest, names, root, state_dir, progress):
        reused = written = 0
        verified = []
        for name in names:
            entry = manifest["files"][name]
            target = self._safe_target(root, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            part = state_dir / (digest(name.encode()) + ".part")
            if part.is_symlink():
                raise IntegrityError("partial file is a symlink")
            with part.open("r+b" if part.exists() else "w+b") as output:
                offset = 0
                for index, chunk in enumerate(entry["chunks"]):
                    output.seek(offset)
                    existing = output.read(chunk["size"])
                    if len(existing) == chunk["size"] and digest(existing) == chunk["sha256"]:
                        # The existing .part prefix is reused only after its
                        # logical chunk hash has been revalidated.
                        reused += 1
                    else:
                        data = self._load_chunk(chunk)
                        output.seek(offset)
                        output.write(data)
                        output.flush()
                        os.fsync(output.fileno())
                        written += 1
                    offset += chunk["size"]
                    if progress:
                        progress(name, index + 1)
                output.truncate(entry["size"])
                output.flush()
                os.fsync(output.fileno())
                output.seek(0)
                final_hash = hashlib.file_digest(output, "sha256").hexdigest()
                if final_hash != entry["sha256"]:
                    raise IntegrityError(f"restored file checksum mismatch: {name}")
            os.replace(part, target)
            verified.append({"file": name, "sha256": entry["sha256"], "size": entry["size"]})
        return reused, written, verified

    def restore(self, snapshot, destination, *, selected=None, progress=None,
                required_metadata=None, reset_session=False):
        """Restore selected files of an authenticated snapshot.

        A progress callback may interrupt after a verified chunk; rerunning
        the identical call resumes the session. The session pins the snapshot
        identity, file selection, metadata requirements and codec contract; a
        rerun with different parameters never borrows the interrupted
        session's state and fails with SessionConflictError unless
        ``reset_session`` explicitly discards it. Restore is atomic per file,
        existing files outside the selection are preserved, and the
        destination must be exclusively owned by one restore at a time.
        """
        decision = self.resolve(snapshot)
        manifest = decision.manifest
        if required_metadata is not None:
            if not isinstance(required_metadata, dict):
                raise ValueError("required metadata must be an object")
            for key, value in required_metadata.items():
                if key not in manifest["metadata"] or manifest["metadata"][key] != value:
                    raise ValueError(f"incompatible package metadata: {key}")
        requested_root = Path(destination).absolute()
        if requested_root.is_symlink():
            raise IntegrityError("restore root is a symlink")
        # Canonicalize OS aliases such as macOS /var -> /private/var. All
        # paths below this canonical root are still checked individually.
        root = requested_root.resolve()
        if root == self.root or root in self.root.parents or self.root in root.parents:
            raise ValueError("restore destination overlaps repository")
        names = sorted(manifest["files"] if selected is None else set(selected))
        if any(name not in manifest["files"] for name in names):
            raise KeyError("selected file is not in the snapshot")
        root.mkdir(parents=True, exist_ok=True)
        state_root = root / ".packsmith"
        state_dir = state_root / snapshot
        if state_root.is_symlink() or state_dir.is_symlink():
            raise IntegrityError("restore state contains a symlink")
        state_root.mkdir(parents=True, exist_ok=True)
        lock = self._acquire_lock(state_root)
        session_path = state_root / "session.json"
        try:
            params = self._session_params(decision, selected, names, required_metadata)
            resumed = False
            if session_path.exists():
                if session_path.is_symlink():
                    raise IntegrityError("restore session state is a symlink")
                if reset_session:
                    # Explicit reset discards the interrupted session's state
                    # even when the new request has identical parameters.
                    self._wipe_session(state_root)
                else:
                    try:
                        existing = json.loads(session_path.read_bytes())
                    except (OSError, json.JSONDecodeError) as exc:
                        raise SessionConflictError(
                            "unreadable restore session state; rerun with reset_session") from exc
                    if existing == params:
                        resumed = True
                    else:
                        raise SessionConflictError(
                            "destination holds an incompatible restore session; "
                            "use a fresh destination or rerun with reset_session")
            if not resumed:
                atomic_write(session_path, encode(params))
            state_dir.mkdir(parents=True, exist_ok=True)
            reused, written, verified = self._restore_files(manifest, names, root, state_dir, progress)
        except Exception:
            os.close(lock)  # interrupted: keep the session state for a resume
            raise
        # Success: drop the session state while still holding the lock, so no
        # later run can mistake this destination for an in-progress session.
        shutil.rmtree(state_dir, ignore_errors=True)
        try:
            session_path.unlink()
        except OSError:
            pass
        self._release_lock(state_root, lock)
        return {
            **decision.summary(),
            "files": len(names),
            "chunks_written": written,
            "chunks_reused": reused,
            "resumed": resumed,
            "verified": verified,
        }
