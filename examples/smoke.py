import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

project = Path(__file__).resolve().parents[1]
env = dict(os.environ, PYTHONPATH=str(project / "src"))

processes = 0


def cli(repo, *args, expect=0):
    global processes
    processes += 1
    completed = subprocess.run([sys.executable, "-m", "packsmith.cli", "--repo", str(repo), *map(str, args)],
                               env=env, capture_output=True, text=True)
    if completed.returncode != expect:
        raise RuntimeError(f"exit {completed.returncode} != {expect}: {completed.stderr.strip()}")
    return json.loads(completed.stdout) if completed.stdout.strip() else None


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    source, repo, out = root / "source", root / "repo", root / "restored"
    shutil.copytree(project / "examples" / "dataset", source)
    keys = root / "keys.json"
    keys.write_text(json.dumps({"main": "cd" * 32}))

    base = cli(repo, "snapshot", source, "--chunk-size", "16", "--compress",
               "--key-id", "main", "--key-file", keys)["snapshot"]
    if not cli(repo, "verify", base, "--key-file", keys)["ok"]:
        raise RuntimeError("base verify failed")
    (source / "new.jsonl").write_text('{"id":"c3"}\n', encoding="utf-8")
    version = cli(repo, "snapshot", source, "--chunk-size", "16", "--compress",
                  "--key-id", "main", "--key-file", keys, "--base", base)["snapshot"]
    restored = cli(repo, "restore", version, out, "--key-file", keys)
    if not restored["authenticated"] or restored["keyid"] != "main":
        raise RuntimeError("delivery must be authenticated")
    for path in source.rglob("*"):
        if path.is_file() and path.read_bytes() != (out / path.relative_to(source)).read_bytes():
            raise RuntimeError("roundtrip mismatch")
    inspected = cli(repo, "inspect", version, "--key-file", keys)
    if not inspected["authenticated"] or inspected["manifest"]["changed"] != ["new.jsonl"]:
        raise RuntimeError("incremental change set incorrect")

    # Corrupted object -> integrity failure, exit 1, located to file and object.
    sha = inspected["manifest"]["files"]["new.jsonl"]["chunks"][0]["encoded_sha256"]
    (repo / "chunks" / sha).write_bytes(b"broken")
    corrupt = cli(repo, "verify", version, "--key-file", keys, expect=1)
    if corrupt["ok"] or corrupt["errors"][0]["file"] != "new.jsonl":
        raise RuntimeError("corruption not located")

    # Wrong publisher key -> authentication failure, exit 3 (never a hash fallback).
    wrong = root / "wrong-keys.json"
    wrong.write_text(json.dumps({"main": "ef" * 32}))
    cli(repo, "verify", version, "--key-file", wrong, expect=3)

    print(json.dumps({"ok": True, "files": 3, "incremental": True, "roundtrip": True,
                      "authenticated": True, "corruption_detected": True,
                      "untrusted_rejected": True, "cli_processes": processes}))
