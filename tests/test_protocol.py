import fcntl
import json
import os
import tempfile
import tracemalloc
import unittest
import zlib
from pathlib import Path

from packsmith import (
    AuthenticationError,
    IntegrityError,
    Repository,
    RestoreBusyError,
    SessionConflictError,
)
from packsmith.formats import digest, encode, sign_manifest

KEY = bytes.fromhex("aa" * 32)
OTHER_KEY = bytes.fromhex("bb" * 32)
KEYS = {"main": KEY}


def legacy_snapshot(repo_root, files):
    """Write a format 1 manifest plus its identity objects, as the old
    implementation would have produced them."""
    entries = {}
    for name, data in files.items():
        sha = digest(data)
        (repo_root / "chunks" / sha).write_bytes(data)
        entries[name] = {
            "sha256": sha,
            "size": len(data),
            "chunks": [{"sha256": sha, "size": len(data)}] if data else [],
        }
    manifest = {"format": 1, "base": None, "files": entries, "metadata": {},
                "changed": sorted(entries), "deleted": []}
    content = encode(manifest)
    sid = digest(content)
    (repo_root / "manifests" / (sid + ".json")).write_bytes(content)
    return sid


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "data.bin").write_bytes(b"abcdefghijklmnopqrstuvwx")
        (self.source / "empty").touch()
        (self.source / "nested").mkdir()
        (self.source / "nested" / "schema.json").write_text('{"v":1}')
        self.repo = Repository(self.root / "repo", keys=KEYS, sign_with="main")
        self.addCleanup(self.tmp.cleanup)

    # --- helpers ---------------------------------------------------------------

    def _tampered_id(self, sid, mutate):
        manifest = json.loads((self.repo.root / "manifests" / (sid + ".json")).read_bytes())
        mutate(manifest)
        content = encode(manifest)
        bad = digest(content)
        (self.repo.root / "manifests" / (bad + ".json")).write_bytes(content)
        return bad

    def _forge(self, files, **overrides):
        manifest = {"format": 2, "base": None, "files": files, "metadata": {},
                    "changed": sorted(files), "deleted": []}
        manifest.update(overrides)
        sign_manifest(manifest, "main", KEY)
        content = encode(manifest)
        sid = digest(content)
        (self.repo.root / "manifests" / (sid + ".json")).write_bytes(content)
        return sid

    def _store_object(self, data):
        sha = digest(data)
        (self.repo.root / "chunks" / sha).write_bytes(data)
        return sha

    # --- trust conclusion --------------------------------------------------------

    def test_untrusted_publisher_is_distinguished_from_corruption(self):
        sid = self.repo.snapshot(self.source, chunk_size=4)
        bad = self._tampered_id(sid, lambda m: m["metadata"].update({"schema": 9}))
        for operation in (self.repo.load, self.repo.verify):
            with self.assertRaises(AuthenticationError):
                operation(bad)
        with self.assertRaises(AuthenticationError):
            self.repo.restore(bad, self.root / "out")
        # Authentication failure leaves nothing a later run could mistake for success.
        self.assertFalse((self.root / "out").exists())
        # A corrupted object is a different conclusion: integrity, not authentication.
        sha = self.repo.load(sid)["files"]["data.bin"]["chunks"][0]["sha256"]
        (self.repo.root / "chunks" / sha).write_bytes(b"BAD!")
        report = self.repo.verify(sid)
        self.assertFalse(report["ok"])
        self.assertTrue(report["authenticated"])
        with self.assertRaises(IntegrityError) as caught:
            self.repo.restore(sid, self.root / "out2")
        self.assertNotIsInstance(caught.exception, AuthenticationError)
        self.assertFalse((self.root / "out2" / "data.bin").exists())

    def test_mac_covers_metadata_paths_chunk_order_and_base(self):
        base = self.repo.snapshot(self.source, chunk_size=4)
        (self.source / "extra").write_bytes(b"zz")
        sid = self.repo.snapshot(self.source, chunk_size=4, base=base,
                                 metadata={"schema_version": 2})
        cases = {
            "metadata": lambda m: m["metadata"].update(schema_version=3),
            "file path": lambda m: m["files"].__setitem__("renamed", m["files"].pop("data.bin")),
            "chunk order": lambda m: m["files"]["data.bin"]["chunks"].reverse(),
            "base identity": lambda m: m.__setitem__("base", digest(b"other")),
            "mac algorithm": lambda m: m["mac"].__setitem__("alg", "sha256"),
            "mac key id": lambda m: m["mac"].__setitem__("keyid", "forged"),
        }
        for label, mutate in cases.items():
            with self.subTest(covered=label):
                bad = self._tampered_id(sid, mutate)
                with self.assertRaises(AuthenticationError):
                    self.repo.resolve(bad)

    def test_plain_hash_is_never_a_fallback(self):
        # An attacker who computes a correct *plain* SHA256 over the body and
        # labels it as the MAC must still be rejected.
        sid = self.repo.snapshot(self.source)
        def weaken(manifest):
            body = {k: v for k, v in manifest.items() if k != "mac"}
            manifest["mac"] = {"alg": "sha256", "keyid": "main", "value": digest(encode(body))}
        bad = self._tampered_id(sid, weaken)
        with self.assertRaises(AuthenticationError):
            self.repo.resolve(bad)

    def test_unknown_key_id_and_missing_keys_are_rejected(self):
        sid = self.repo.snapshot(self.source)
        stranger = Repository(self.root / "repo", keys={"other": OTHER_KEY})
        with self.assertRaises(AuthenticationError):
            stranger.resolve(sid)
        keyless = Repository(self.root / "repo")
        with self.assertRaises(AuthenticationError):
            keyless.resolve(sid)

    def test_mac_value_encoding_rules(self):
        sid = self.repo.snapshot(self.source)
        upper = self._tampered_id(sid, lambda m: m["mac"].__setitem__("value", m["mac"]["value"].upper()))
        with self.assertRaises(AuthenticationError):
            self.repo.resolve(upper)
        short = self._tampered_id(sid, lambda m: m["mac"].__setitem__("value", m["mac"]["value"][:32]))
        with self.assertRaises(AuthenticationError):
            self.repo.resolve(short)

    def test_same_canonical_input_has_stable_authentication(self):
        sid = self.repo.snapshot(self.source, metadata={"a": [1, 2], "b": {"c": True}})
        manifest = self.repo.load(sid)
        # Re-serialize with different formatting and key order: the canonical
        # MAC input is unchanged, so the same MAC still authenticates.
        content = json.dumps(manifest, indent=1, ensure_ascii=False).encode()
        alternate = digest(content)
        self.assertNotEqual(alternate, sid)
        (self.repo.root / "manifests" / (alternate + ".json")).write_bytes(content)
        decision = self.repo.resolve(alternate)
        self.assertTrue(decision.authenticated)
        self.assertEqual(decision.key_id, "main")

    def test_legacy_manifest_requires_policy_and_is_never_authenticated(self):
        sid = legacy_snapshot(self.repo.root, {"old.bin": b"legacy-data"})
        for operation in (self.repo.load, self.repo.verify):
            with self.assertRaises(AuthenticationError):
                operation(sid)
        with self.assertRaises(AuthenticationError):
            self.repo.restore(sid, self.root / "out")
        self.assertFalse((self.root / "out").exists())
        legacy_repo = Repository(self.root / "repo", keys=KEYS, allow_legacy=True)
        decision = legacy_repo.resolve(sid)
        self.assertFalse(decision.authenticated)
        self.assertTrue(decision.legacy)
        report = legacy_repo.verify(sid)
        self.assertTrue(report["ok"])
        self.assertFalse(report["authenticated"])
        result = legacy_repo.restore(sid, self.root / "out")
        self.assertFalse(result["authenticated"])
        self.assertEqual((self.root / "out" / "old.bin").read_bytes(), b"legacy-data")

    def test_legacy_manifest_with_mac_block_is_still_unauthenticated(self):
        sid = legacy_snapshot(self.repo.root, {"old.bin": b"legacy-data"})
        # Attach a valid MAC block to a format 1 body: still legacy, never authenticated.
        manifest = json.loads((self.repo.root / "manifests" / (sid + ".json")).read_bytes())
        sign_manifest(manifest, "main", KEY)
        content = encode(manifest)
        forged = digest(content)
        (self.repo.root / "manifests" / (forged + ".json")).write_bytes(content)
        legacy_repo = Repository(self.root / "repo", keys=KEYS, allow_legacy=True)
        decision = legacy_repo.resolve(forged)
        self.assertTrue(decision.legacy)
        self.assertFalse(decision.authenticated)

    # --- codecs ------------------------------------------------------------------

    def test_compression_roundtrip_and_codec_records(self):
        (self.source / "compressible.txt").write_bytes(b"A" * 5000 + b"B" * 5000)
        sid = self.repo.snapshot(self.source, chunk_size=1000, compress=True)
        manifest = self.repo.load(sid)
        chunks = manifest["files"]["compressible.txt"]["chunks"]
        self.assertTrue(any(c["codec"] == "zlib" for c in chunks))
        for chunk in chunks:
            self.assertEqual(chunk["codec_version"], 1)
            # The stored object is addressed by its encoded digest.
            stored = self.repo.root / "chunks" / chunk["encoded_sha256"]
            self.assertEqual(digest(stored.read_bytes()), chunk["encoded_sha256"])
            self.assertEqual(len(stored.read_bytes()), chunk["encoded_size"])
            if chunk["codec"] == "zlib":
                self.assertLess(chunk["encoded_size"], chunk["size"])
                self.assertNotEqual(chunk["encoded_sha256"], chunk["sha256"])
            else:
                self.assertEqual(chunk["encoded_sha256"], chunk["sha256"])
                self.assertEqual(chunk["encoded_size"], chunk["size"])
        self.assertTrue(self.repo.verify(sid)["ok"])
        result = self.repo.restore(sid, self.root / "out")
        self.assertEqual((self.root / "out" / "compressible.txt").read_bytes(), b"A" * 5000 + b"B" * 5000)
        self.assertEqual(len(result["verified"]), 4)
        # Same input, key and parameters: identical authenticated snapshot id.
        self.assertEqual(self.repo.snapshot(self.source, chunk_size=1000, compress=True), sid)

    def test_encoded_object_valid_but_decoded_content_is_rejected(self):
        # The stored object matches its encoded digest, yet decodes to bytes
        # that do not match the declared logical digest.
        blob = zlib.compress(b"WRONG")
        files = {"f": {"sha256": digest(b"RIGHT"), "size": 5, "chunks": [
            {"sha256": digest(b"RIGHT"), "size": 5, "codec": "zlib", "codec_version": 1,
             "encoded_sha256": digest(blob), "encoded_size": len(blob)}]}}
        sid = self._forge(files)
        self._store_object(blob)
        report = self.repo.verify(sid)
        self.assertFalse(report["ok"])
        self.assertIn("logical", report["errors"][0]["error"])
        with self.assertRaises(IntegrityError):
            self.repo.restore(sid, self.root / "out")
        self.assertFalse((self.root / "out" / "f").exists())

    def test_decompression_bomb_stops_within_declared_size(self):
        blob = zlib.compress(b"A" * 8_000_000)
        files = {"bomb": {"sha256": digest(b"x" * 4096), "size": 4096, "chunks": [
            {"sha256": digest(b"x" * 4096), "size": 4096, "codec": "zlib", "codec_version": 1,
             "encoded_sha256": digest(blob), "encoded_size": len(blob)}]}}
        sid = self._forge(files)
        self._store_object(blob)
        tracemalloc.start()
        try:
            report = self.repo.verify(sid)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertFalse(report["ok"])
        self.assertIn("exceeds declared size", report["errors"][0]["error"])
        # Bounded memory: nowhere near the 8 MB the payload would expand to.
        self.assertLess(peak, 2_000_000)
        with self.assertRaises(IntegrityError):
            self.repo.restore(sid, self.root / "out")
        self.assertFalse((self.root / "out" / "bomb").exists())

    def test_unknown_codec_and_version_are_rejected(self):
        chunk = {"sha256": digest(b"data"), "size": 4, "codec": "lz4", "codec_version": 1,
                 "encoded_sha256": digest(b"data"), "encoded_size": 4}
        sid = self._forge({"f": {"sha256": digest(b"data"), "size": 4, "chunks": [chunk]}})
        with self.assertRaises(IntegrityError):
            self.repo.load(sid)
        chunk["codec"] = "zlib"
        chunk["codec_version"] = 99
        sid = self._forge({"f": {"sha256": digest(b"data"), "size": 4, "chunks": [chunk]}})
        with self.assertRaises(IntegrityError):
            self.repo.load(sid)

    def test_identity_chunk_binding_is_enforced(self):
        chunk = {"sha256": digest(b"data"), "size": 4, "codec": "identity", "codec_version": 1,
                 "encoded_sha256": digest(b"other"), "encoded_size": 4}
        sid = self._forge({"f": {"sha256": digest(b"data"), "size": 4, "chunks": [chunk]}})
        with self.assertRaises(IntegrityError):
            self.repo.load(sid)

    # --- restore sessions ----------------------------------------------------------

    def test_session_pins_snapshot_selection_and_metadata(self):
        sid_a = self.repo.snapshot(self.source, chunk_size=4)
        (self.source / "data.bin").write_bytes(b"ABCDEFGHIJKLMNOPQRSTUVWX")
        sid_b = self.repo.snapshot(self.source, chunk_size=4)
        def stop(name, count):
            if name == "nested/schema.json":
                raise InterruptedError()
        with self.assertRaises(InterruptedError):
            self.repo.restore(sid_a, self.root / "out", progress=stop)
        # Different snapshot, different selection, different metadata
        # requirement: none may borrow the interrupted session.
        with self.assertRaises(SessionConflictError):
            self.repo.restore(sid_b, self.root / "out")
        with self.assertRaises(SessionConflictError):
            self.repo.restore(sid_a, self.root / "out", selected=["data.bin"])
        with self.assertRaises(SessionConflictError):
            self.repo.restore(sid_a, self.root / "out", required_metadata={})
        # The identical call resumes the same trusted snapshot.
        result = self.repo.restore(sid_a, self.root / "out")
        self.assertTrue(result["resumed"])
        self.assertGreaterEqual(result["chunks_reused"], 1)
        self.assertEqual((self.root / "out" / "data.bin").read_bytes(), b"abcdefghijklmnopqrstuvwx")
        # After completion the session is cleaned, so another snapshot may
        # start a fresh session in the same destination.
        result = self.repo.restore(sid_b, self.root / "out")
        self.assertFalse(result["resumed"])
        self.assertEqual((self.root / "out" / "data.bin").read_bytes(), b"ABCDEFGHIJKLMNOPQRSTUVWX")

    def test_reset_session_discards_interrupted_state(self):
        sid = self.repo.snapshot(self.source, chunk_size=4)
        def stop(name, count):
            if name == "data.bin" and count == 2:
                raise InterruptedError()
        with self.assertRaises(InterruptedError):
            self.repo.restore(sid, self.root / "out", progress=stop)
        result = self.repo.restore(sid, self.root / "out", reset_session=True)
        self.assertFalse(result["resumed"])
        self.assertEqual(result["chunks_reused"], 0)
        self.assertEqual((self.root / "out" / "data.bin").read_bytes(),
                         (self.source / "data.bin").read_bytes())

    def test_busy_destination_is_rejected(self):
        sid = self.repo.snapshot(self.source, chunk_size=4)
        def stop(name, count):
            raise InterruptedError()
        with self.assertRaises(InterruptedError):
            self.repo.restore(sid, self.root / "out", progress=stop)
        lock_path = self.root / "out" / ".packsmith" / "lock"
        fd = os.open(lock_path, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with self.assertRaises(RestoreBusyError):
                self.repo.restore(sid, self.root / "out")
        finally:
            os.close(fd)
        # Once the owner is gone the same session can resume.
        result = self.repo.restore(sid, self.root / "out")
        self.assertEqual(result["files"], 3)

    def test_crash_before_rename_leaves_no_partial_target(self):
        sid = self.repo.snapshot(self.source, chunk_size=4)
        def stop(name, count):
            if name == "data.bin" and count == 3:
                raise InterruptedError()
        with self.assertRaises(InterruptedError):
            self.repo.restore(sid, self.root / "out", progress=stop)
        self.assertFalse((self.root / "out" / "data.bin").exists())
        parts = list((self.root / "out" / ".packsmith" / sid).glob("*.part"))
        self.assertEqual(len(parts), 1)
        self.repo.restore(sid, self.root / "out")
        self.assertEqual((self.root / "out" / "data.bin").read_bytes(),
                         (self.source / "data.bin").read_bytes())
        # Successful delivery cleans up the session state.
        self.assertFalse((self.root / "out" / ".packsmith" / sid).exists())

    def test_unselected_and_foreign_files_are_preserved(self):
        sid = self.repo.snapshot(self.source)
        out = self.root / "out"
        out.mkdir()
        (out / "keep.txt").write_text("untouched")
        self.repo.restore(sid, out, selected=["empty"])
        self.assertEqual((out / "keep.txt").read_text(), "untouched")
        self.assertFalse((out / "data.bin").exists())
        # The deleted list of a delta snapshot never removes existing files.
        (self.source / "empty").unlink()
        child = self.repo.snapshot(self.source, base=sid)
        (out / "empty").write_bytes(b"local copy")
        self.repo.restore(child, out)
        self.assertEqual((out / "empty").read_bytes(), b"local copy")

    def test_success_result_proves_each_selected_file(self):
        sid = self.repo.snapshot(self.source, chunk_size=4)
        manifest = self.repo.load(sid)
        result = self.repo.restore(sid, self.root / "out", selected=["data.bin", "empty"])
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["keyid"], "main")
        proven = {item["file"]: item for item in result["verified"]}
        self.assertEqual(set(proven), {"data.bin", "empty"})
        for name, item in proven.items():
            self.assertEqual(item["sha256"], manifest["files"][name]["sha256"])
            self.assertEqual(item["size"], manifest["files"][name]["size"])

    # --- base identity ----------------------------------------------------------------

    def test_base_manifest_replacement_is_detected(self):
        base = self.repo.snapshot(self.source, chunk_size=4)
        (self.source / "extra").write_bytes(b"zz")
        child = self.repo.snapshot(self.source, chunk_size=4, base=base)
        # The child is self-contained: replacing the base object does not
        # affect verifying or restoring the child.
        (self.repo.root / "manifests" / (base + ".json")).write_bytes(b"garbage")
        self.assertTrue(self.repo.verify(child)["ok"])
        self.repo.restore(child, self.root / "out")
        self.assertTrue((self.root / "out" / "extra").exists())
        # But nothing new may be built on the replaced base.
        with self.assertRaises(IntegrityError):
            self.repo.snapshot(self.source, base=base)
        # And a child whose base field is rewritten fails authentication.
        other = self.repo.snapshot(self.source, chunk_size=4)
        bad = self._tampered_id(other, lambda m: m.__setitem__("base", digest(b"attacker")))
        with self.assertRaises(AuthenticationError):
            self.repo.resolve(bad)

    def test_different_keys_produce_different_snapshots(self):
        other_repo = Repository(self.root / "repo", keys={"other": OTHER_KEY}, sign_with="other")
        sid_main = self.repo.snapshot(self.source)
        sid_other = other_repo.snapshot(self.source)
        self.assertNotEqual(sid_main, sid_other)
        with self.assertRaises(AuthenticationError):
            self.repo.resolve(sid_other)
        self.assertTrue(other_repo.resolve(sid_other).authenticated)


if __name__ == "__main__":
    unittest.main()
