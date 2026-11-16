"""Filesystem adapter. Chunks and manifests are immutable content-addressed objects."""
import json
import os
import stat
import tempfile
from pathlib import Path
from .formats import IntegrityError, digest, encode, relative_path, valid_digest, validate_manifest


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


class Repository:
    def __init__(self, root):
        self.root = Path(root).resolve()
        (self.root / "chunks").mkdir(parents=True, exist_ok=True)
        (self.root / "manifests").mkdir(exist_ok=True)

    def _chunk_path(self, sha):
        return self.root / "chunks" / valid_digest(sha)

    def _read_chunk(self, entry):
        path = self._chunk_path(entry["sha256"])
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise IntegrityError(f"missing chunk {entry['sha256']}") from exc
        if len(data) != entry["size"] or digest(data) != entry["sha256"]:
            raise IntegrityError(f"corrupt chunk {entry['sha256']}")
        return data

    def load(self, snapshot):
        valid_digest(snapshot)
        try:
            content = (self.root / "manifests" / (snapshot + ".json")).read_bytes()
        except OSError as exc:
            raise IntegrityError(f"missing manifest {snapshot}") from exc
        if digest(content) != snapshot:
            raise IntegrityError("manifest checksum mismatch")
        try:
            manifest = json.loads(content)
            validate_manifest(manifest)
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError("malformed manifest") from exc
        return manifest

    def snapshot(self, source, *, chunk_size=1024 * 1024, base=None, metadata=None):
        if type(chunk_size) is not int or chunk_size < 1:
            raise ValueError("chunk size must be positive")
        if metadata is not None and not isinstance(metadata, dict): raise ValueError("metadata must be an object")
        source = Path(source).resolve()
        if not source.is_dir():
            raise ValueError("source must be a directory")
        if self.root == source or source in self.root.parents or self.root in source.parents:
            raise ValueError("source and repository must not overlap")
        baseline = self.load(base)["files"] if base else {}
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
            import hashlib
            file_hash = hashlib.sha256()
            # O_NOFOLLOW closes the final-component symlink replacement window.
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError("source replaced while snapshotting")
                while data := stream.read(chunk_size):
                    sha = digest(data)
                    chunk_path = self._chunk_path(sha)
                    if not chunk_path.exists():
                        atomic_write(chunk_path, data)
                    elif chunk_path.read_bytes() != data:
                        raise IntegrityError(f"existing chunk is corrupt: {sha}")
                    chunks.append({"sha256": sha, "size": len(data)})
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
        manifest = {"format": 1, "base": base, "files": files, "metadata": metadata or {},
                    "changed": sorted(n for n, entry in files.items() if baseline.get(n) != entry),
                    "deleted": sorted(set(baseline) - set(files))}
        content = encode(manifest)
        snapshot_id = digest(content)
        atomic_write(self.root / "manifests" / (snapshot_id + ".json"), content)
        return snapshot_id

    def verify(self, snapshot):
        manifest = self.load(snapshot)
        errors = []
        for name, entry in manifest["files"].items():
            import hashlib
            file_hash = hashlib.sha256()
            try:
                for chunk in entry["chunks"]:
                    file_hash.update(self._read_chunk(chunk))
                if file_hash.hexdigest() != entry["sha256"]:
                    raise IntegrityError("file checksum mismatch")
            except IntegrityError as exc:
                errors.append({"file": name, "error": str(exc)})
        return {"snapshot": snapshot, "ok": not errors, "files": len(manifest["files"]), "errors": errors}

    @staticmethod
    def _safe_target(root, name):
        path = root.joinpath(*relative_path(name).parts)
        for current in [path, *path.parents]:
            if current == root.parent:
                break
            if current.is_symlink():
                raise IntegrityError("restore path contains a symlink")
        return path

    def restore(self, snapshot, destination, *, selected=None, progress=None, required_metadata=None):
        """A progress callback may interrupt after a verified chunk; rerun to resume.

        Restore is atomic per file. Exclusive ownership of destination is required.
        Existing files outside the selected snapshot are deliberately preserved.
        """
        manifest = self.load(snapshot)
        if required_metadata is not None:
            if not isinstance(required_metadata, dict): raise ValueError("required metadata must be an object")
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
        state_root = root / ".packsmith" / snapshot
        if (root / ".packsmith").is_symlink() or state_root.is_symlink():
            raise IntegrityError("restore state contains a symlink")
        state_root.mkdir(parents=True, exist_ok=True)
        reused, written = 0, 0
        for name in names:
            entry = manifest["files"][name]
            target = self._safe_target(root, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            part = state_root / (digest(name.encode()) + ".part")
            if part.is_symlink():
                raise IntegrityError("partial file is a symlink")
            with part.open("r+b" if part.exists() else "w+b") as output:
                offset = 0
                for index, chunk in enumerate(entry["chunks"]):
                    output.seek(offset)
                    existing = output.read(chunk["size"])
                    if len(existing) == chunk["size"] and digest(existing) == chunk["sha256"]:
                        reused += 1
                    else:
                        data = self._read_chunk(chunk)
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
                import hashlib
                final_hash = hashlib.file_digest(output, "sha256").hexdigest()
                if final_hash != entry["sha256"]:
                    raise IntegrityError(f"restored file checksum mismatch: {name}")
            os.replace(part, target)
        return {"snapshot": snapshot, "files": len(names), "chunks_written": written, "chunks_reused": reused}
