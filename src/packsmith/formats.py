import hashlib
import json
import re
from pathlib import PurePosixPath


class IntegrityError(ValueError):
    pass


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(content):
    return hashlib.sha256(content).hexdigest()


def valid_digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise IntegrityError("invalid SHA256 identifier")
    return value


def relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise IntegrityError("invalid relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ("..", ".packsmith") for p in path.parts) or str(path) != value or value == ".":
        raise IntegrityError(f"unsafe relative path: {value}")
    return path


def validate_manifest(manifest):
    if not isinstance(manifest, dict) or manifest.get("format") != 1 or not isinstance(manifest.get("files"), dict) or not isinstance(manifest.get("metadata"), dict):
        raise IntegrityError("unsupported manifest format")
    if manifest.get("base") is not None:
        valid_digest(manifest["base"])
    for name, entry in manifest["files"].items():
        relative_path(name)
        if not isinstance(entry, dict) or not isinstance(entry.get("chunks"), list):
            raise IntegrityError("invalid file entry")
        valid_digest(entry["sha256"])
        if type(entry["size"]) is not int or entry["size"] < 0:
            raise IntegrityError("invalid file size")
        size = 0
        for chunk in entry["chunks"]:
            if not isinstance(chunk, dict): raise IntegrityError("invalid chunk entry")
            valid_digest(chunk["sha256"])
            if type(chunk["size"]) is not int or chunk["size"] <= 0:
                raise IntegrityError("invalid chunk size")
            size += chunk["size"]
        if size != entry["size"]:
            raise IntegrityError("chunk sizes do not add up")
    paths = set(manifest["files"])
    for name in paths:
        if any(str(parent) in paths for parent in PurePosixPath(name).parents):
            raise IntegrityError("file/directory collision in manifest")
