import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

project = Path(__file__).resolve().parents[1]
env = dict(os.environ, PYTHONPATH=str(project / "src"))


def cli(repo, *args, success=True):
    completed = subprocess.run([sys.executable, "-m", "packsmith.cli", "--repo", str(repo), *map(str, args)],
                               env=env, capture_output=True, text=True)
    if success and completed.returncode: raise RuntimeError(completed.stderr)
    if not success and completed.returncode != 1: raise RuntimeError("corrupt package must return exit status 1")
    return json.loads(completed.stdout)


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    source, repo, out = root / "source", root / "repo", root / "restored"
    shutil.copytree(project / "examples" / "dataset", source)
    base = cli(repo, "snapshot", source, "--chunk-size", "16")["snapshot"]
    if not cli(repo, "verify", base)["ok"]: raise RuntimeError("base verify failed")
    (source / "new.jsonl").write_text('{"id":"c3"}\n', encoding="utf-8")
    version = cli(repo, "snapshot", source, "--chunk-size", "16", "--base", base)["snapshot"]
    cli(repo, "restore", version, out)
    for path in source.rglob("*"):
        if path.is_file() and path.read_bytes() != (out / path.relative_to(source)).read_bytes():
            raise RuntimeError("roundtrip mismatch")
    manifest = cli(repo, "inspect", version)
    if manifest["changed"] != ["new.jsonl"]: raise RuntimeError("incremental change set incorrect")
    sha = manifest["files"]["new.jsonl"]["chunks"][0]["sha256"]
    (repo / "chunks" / sha).write_bytes(b"broken")
    corrupt = cli(repo, "verify", version, success=False)
    if corrupt["ok"] or corrupt["errors"][0]["file"] != "new.jsonl": raise RuntimeError("corruption not located")
    print(json.dumps({"ok": True, "files": 3, "incremental": True, "roundtrip": True, "corruption_detected": True, "cli_processes": 6}))
