import json
import tempfile
import unittest
from pathlib import Path
from packsmith import AuthenticationError, IntegrityError, Repository
from packsmith.formats import digest, encode, sign_manifest

KEY = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
KEYS = {"main": KEY}


class PackageTests(unittest.TestCase):
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

    def test_roundtrip_and_integrity(self):
        sid = self.repo.snapshot(self.source, chunk_size=4)
        self.assertTrue(self.repo.verify(sid)["ok"])
        destination = self.root / "out"
        result = self.repo.restore(sid, destination)
        self.assertEqual(result["files"], 3)
        self.assertTrue(result["authenticated"])
        for path in self.source.rglob("*"):
            if path.is_file():
                self.assertEqual(path.read_bytes(), (destination / path.relative_to(self.source)).read_bytes())

    def test_interrupted_restore_resumes_verified_chunks(self):
        sid = self.repo.snapshot(self.source, chunk_size=4)
        def interrupt(name, count):
            if name == "data.bin" and count == 2:
                raise InterruptedError("simulated power interruption")
        with self.assertRaises(InterruptedError):
            self.repo.restore(sid, self.root / "out", progress=interrupt)
        self.assertFalse((self.root / "out" / "data.bin").exists())
        result = self.repo.restore(sid, self.root / "out")
        self.assertTrue(result["resumed"])
        self.assertEqual(result["chunks_reused"], 2)

    def test_delta_references_base_and_restores_full_snapshot(self):
        base = self.repo.snapshot(self.source, chunk_size=4)
        before = set((self.repo.root / "chunks").iterdir())
        (self.source / "empty").unlink()
        (self.source / "new").write_bytes(b"abcd")
        sid = self.repo.snapshot(self.source, chunk_size=4, base=base)
        manifest = self.repo.load(sid)
        self.assertEqual(manifest["changed"], ["new"])
        self.assertEqual(manifest["deleted"], ["empty"])
        self.assertEqual(before, set((self.repo.root / "chunks").iterdir()))
        self.repo.restore(sid, self.root / "out")
        self.assertFalse((self.root / "out" / "empty").exists())

    def test_corruption_identifies_chunk_and_file(self):
        sid = self.repo.snapshot(self.source, chunk_size=4)
        sha = self.repo.load(sid)["files"]["data.bin"]["chunks"][0]["sha256"]
        (self.repo.root / "chunks" / sha).write_bytes(b"BAD!")
        result = self.repo.verify(sid)
        self.assertFalse(result["ok"])
        self.assertEqual(result["errors"][0]["file"], "data.bin")
        self.assertIn(sha, result["errors"][0]["error"])
        with self.assertRaises(IntegrityError):
            self.repo.restore(sid, self.root / "out")

    def test_selected_files_only(self):
        sid = self.repo.snapshot(self.source)
        self.repo.restore(sid, self.root / "out", selected=["nested/schema.json"])
        self.assertFalse((self.root / "out" / "data.bin").exists())
        self.assertTrue((self.root / "out" / "nested" / "schema.json").exists())

    def test_tampered_manifest_is_rejected_even_with_valid_hash(self):
        sid = self.repo.snapshot(self.source)
        manifest = self.repo.load(sid)
        manifest["files"]["../escaped"] = manifest["files"].pop("data.bin")
        content = encode(manifest)
        bad_id = digest(content)
        (self.repo.root / "manifests" / (bad_id + ".json")).write_bytes(content)
        # The MAC no longer matches: authentication fails before any validation.
        with self.assertRaises(AuthenticationError):
            self.repo.restore(bad_id, self.root / "out")

    def test_signed_manifest_with_traversal_path_is_rejected(self):
        # Defense in depth: even a validly signed manifest (compromised or
        # buggy signer) must not smuggle unsafe paths through validation.
        sid = self.repo.snapshot(self.source)
        manifest = self.repo.load(sid)
        manifest["files"]["../escaped"] = manifest["files"].pop("data.bin")
        sign_manifest(manifest, "main", KEY)
        content = encode(manifest)
        bad_id = digest(content)
        (self.repo.root / "manifests" / (bad_id + ".json")).write_bytes(content)
        with self.assertRaises(IntegrityError):
            self.repo.restore(bad_id, self.root / "out")

    def test_symlinks_in_source_and_destination_are_rejected(self):
        (self.source / "link").symlink_to(self.source / "data.bin")
        with self.assertRaises(ValueError): self.repo.snapshot(self.source)
        (self.source / "link").unlink()
        sid = self.repo.snapshot(self.source)
        (self.root / "out").mkdir()
        (self.root / "out" / "nested").symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(IntegrityError): self.repo.restore(sid, self.root / "out")

    def test_bad_manifest_and_overlap(self):
        sid = self.repo.snapshot(self.source)
        (self.repo.root / "manifests" / (sid + ".json")).write_text("{}")
        with self.assertRaises(IntegrityError): self.repo.load(sid)
        with self.assertRaises(ValueError): self.repo.snapshot(self.repo.root)
        with self.assertRaises(ValueError): self.repo.snapshot(self.source, chunk_size=0)

    def test_deterministic_snapshot(self):
        self.assertEqual(self.repo.snapshot(self.source), self.repo.snapshot(self.source))

    def test_metadata_compatibility_precedes_restore(self):
        sid = self.repo.snapshot(self.source, metadata={"schema_version": 2, "tables": ["a", "b"]})
        with self.assertRaisesRegex(ValueError, "incompatible"):
            self.repo.restore(sid, self.root / "out", required_metadata={"schema_version": 1})
        self.assertFalse((self.root / "out").exists())
        self.repo.restore(sid, self.root / "out", required_metadata={"schema_version": 2})

    def test_bad_partial_chunk_is_repaired_on_resume(self):
        sid = self.repo.snapshot(self.source, chunk_size=4)
        def stop(name, count):
            if name == "data.bin" and count == 2: raise InterruptedError()
        with self.assertRaises(InterruptedError): self.repo.restore(sid, self.root / "out", progress=stop)
        part = next((self.root / "out" / ".packsmith" / sid).glob("*.part"))
        with part.open("r+b") as stream: stream.write(b"BAD!")
        result = self.repo.restore(sid, self.root / "out")
        self.assertEqual(result["chunks_reused"], 1)
        self.assertEqual((self.root / "out" / "data.bin").read_bytes(), (self.source / "data.bin").read_bytes())

    def test_non_object_manifest_is_rejected(self):
        content = b"[]"
        sid = digest(content)
        (self.repo.root / "manifests" / (sid + ".json")).write_bytes(content)
        with self.assertRaises(IntegrityError): self.repo.load(sid)


if __name__ == "__main__":
    unittest.main()
