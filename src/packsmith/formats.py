"""Delivery format contracts.

This module defines the authenticated package format (version 2):

* canonical JSON encoding used for manifest bytes and MAC input,
* relative-path rules for manifest entries,
* the versioned codec registry (identity and zlib) with bounded decoding,
* HMAC-SHA256 manifest authentication with injected keys,
* structural validation for format 2 and legacy format 1 manifests.

The MAC covers the canonical encoding of the whole manifest except
``mac.value`` itself, so the algorithm, key id, metadata, file paths, chunk
order and base identity are all authenticated. The MAC value is encoded as
64 lowercase hexadecimal characters of the raw 32-byte HMAC-SHA256 output.
"""
import hashlib
import hmac
import json
import re
import zlib
from pathlib import PurePosixPath


class IntegrityError(ValueError):
    """A manifest, object or path violates the format or its declared hashes."""


class AuthenticationError(IntegrityError):
    """A manifest cannot be authenticated with the injected keys.

    Raised for unknown MAC algorithms, unknown key ids, malformed MAC
    values, MAC mismatches and legacy manifests without an explicit legacy
    policy. There is never a fallback to accepting a plain hash.
    """


# --- canonical encoding -----------------------------------------------------

def encode(value):
    """Canonical JSON encoding: sorted keys, minimal separators, UTF-8.

    Equal logical values always encode to identical bytes, so the MAC input
    is stable regardless of incidental formatting of a manifest file.
    """
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


# --- codec registry -----------------------------------------------------------
#
# A codec transforms logical chunk plaintext into the stored object bytes.
# Codecs are versioned; each manifest chunk records (codec, codec_version)
# together with the logical digest/size and the encoded object digest/size.
# Decoding is bounded: a decoder never produces more than the declared
# logical size plus one byte (to detect overflow), no matter how large the
# compressed payload would expand.

def _identity_encode(data):
    return data


def _identity_decode(encoded, expected_size):
    if len(encoded) != expected_size:
        raise IntegrityError("identity chunk size mismatch")
    return encoded


def _zlib_encode(data):
    return zlib.compress(data, 6)


def _zlib_decode(encoded, expected_size):
    """Inflate ``encoded`` expecting exactly ``expected_size`` bytes.

    Output is capped at ``expected_size + 1`` bytes via ``max_length``, so a
    compressed bomb is rejected within bounded memory instead of being fully
    expanded first and checked afterwards.
    """
    decompressor = zlib.decompressobj()
    budget = expected_size + 1
    parts = []
    produced = 0
    try:
        data = decompressor.decompress(encoded, budget)
        while True:
            produced += len(data)
            if produced > expected_size:
                raise IntegrityError("decoded chunk exceeds declared size")
            parts.append(data)
            pending = decompressor.unconsumed_tail
            if not pending or decompressor.eof:
                break
            data = decompressor.decompress(pending, budget - produced)
        if not decompressor.eof:
            raise IntegrityError("truncated zlib stream")
        tail = decompressor.flush()
        produced += len(tail)
        if produced > expected_size:
            raise IntegrityError("decoded chunk exceeds declared size")
        parts.append(tail)
    except zlib.error as exc:
        raise IntegrityError("undecodable zlib chunk") from exc
    if decompressor.unused_data:
        raise IntegrityError("trailing data after zlib stream")
    if produced != expected_size:
        raise IntegrityError("decoded chunk size mismatch")
    return b"".join(parts)


class _Codec:
    def __init__(self, name, version, encode, decode):
        self.name = name
        self.version = version
        self.encode = encode
        self.decode = decode


_CODECS = {
    ("identity", 1): _Codec("identity", 1, _identity_encode, _identity_decode),
    ("zlib", 1): _Codec("zlib", 1, _zlib_encode, _zlib_decode),
}


def get_codec(name, version):
    codec = _CODECS.get((name, version))
    if codec is None:
        raise IntegrityError(f"unknown codec: {name!r} version {version!r}")
    return codec


def encode_chunk(name, version, data):
    return get_codec(name, version).encode(data)


def decode_chunk(name, version, encoded, expected_size):
    """Decode one chunk object, bounded by and checked against its declared size."""
    if type(expected_size) is not int or expected_size < 0:
        raise IntegrityError("invalid declared chunk size")
    return get_codec(name, version).decode(encoded, expected_size)


# --- manifest authentication ----------------------------------------------------
#
# Manifests are authenticated with HMAC-SHA256 over the canonical encoding of
# the manifest with ``mac.value`` removed (the algorithm and key id remain
# covered). Keys are injected by the caller and never persisted in the
# repository. Unknown algorithms or key ids are hard failures, never a
# fallback to plain hash checking.

MAC_ALGORITHM = "hmac-sha256"
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_MAC_VALUE = re.compile(r"[0-9a-f]{64}")  # lowercase hex of the 32-byte HMAC


def valid_key_id(value):
    if not isinstance(value, str) or not _KEY_ID.fullmatch(value):
        raise IntegrityError("invalid key id")
    return value


def _mac_message(manifest, algorithm, key_id):
    body = {key: value for key, value in manifest.items() if key != "mac"}
    body["mac"] = {"alg": algorithm, "keyid": key_id}
    return encode(body)


def sign_manifest(manifest, key_id, key):
    """Attach an HMAC-SHA256 authentication block to ``manifest``."""
    valid_key_id(key_id)
    manifest.pop("mac", None)
    message = _mac_message(manifest, MAC_ALGORITHM, key_id)
    manifest["mac"] = {
        "alg": MAC_ALGORITHM,
        "keyid": key_id,
        "value": hmac.new(key, message, hashlib.sha256).hexdigest(),
    }
    return manifest


def authenticate_manifest(manifest, keys):
    """Verify the manifest MAC and return the authenticated key id.

    ``keys`` maps key ids to secret bytes. Every failure raises
    AuthenticationError; there is no unauthenticated fallback.
    """
    if not isinstance(manifest, dict):
        raise AuthenticationError("malformed manifest")
    mac = manifest.get("mac")
    if not isinstance(mac, dict):
        raise AuthenticationError("manifest carries no authentication block")
    algorithm = mac.get("alg")
    if algorithm != MAC_ALGORITHM:
        raise AuthenticationError(f"unsupported manifest MAC algorithm: {algorithm!r}")
    key_id = mac.get("keyid")
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise AuthenticationError("malformed key id in manifest")
    key = keys.get(key_id)
    if key is None:
        raise AuthenticationError(f"no injected key for key id {key_id!r}")
    value = mac.get("value")
    if not isinstance(value, str) or not _MAC_VALUE.fullmatch(value):
        raise AuthenticationError("malformed MAC value: expected 64 lowercase hex characters")
    message = _mac_message(manifest, algorithm, key_id)
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, value):
        raise AuthenticationError("manifest authentication failed")
    return key_id


# --- structural validation ------------------------------------------------------

def _valid_size(value, *, allow_zero=False):
    return type(value) is int and (value >= 0 if allow_zero else value > 0)


def _validate_path_list(manifest, key):
    entries = manifest.get(key)
    if not isinstance(entries, list) or any(not isinstance(item, str) for item in entries):
        raise IntegrityError(f"invalid {key} list")
    for item in entries:
        relative_path(item)
    if entries != sorted(entries) or len(set(entries)) != len(entries):
        raise IntegrityError(f"{key} list must be sorted and unique")
    return entries


def _reject_path_collisions(files):
    paths = set(files)
    for name in paths:
        if any(str(parent) in paths for parent in PurePosixPath(name).parents):
            raise IntegrityError("file/directory collision in manifest")


def validate_manifest(manifest):
    """Structural validation for authenticated format 2 manifests."""
    if not isinstance(manifest, dict) or manifest.get("format") != 2:
        raise IntegrityError("unsupported manifest format")
    if not isinstance(manifest.get("files"), dict) or not isinstance(manifest.get("metadata"), dict):
        raise IntegrityError("unsupported manifest format")
    if manifest.get("base") is not None:
        valid_digest(manifest["base"])
    mac = manifest.get("mac")
    if not isinstance(mac, dict) or mac.get("alg") != MAC_ALGORITHM \
            or not isinstance(mac.get("keyid"), str) or not isinstance(mac.get("value"), str):
        raise IntegrityError("invalid authentication block")
    changed = _validate_path_list(manifest, "changed")
    deleted = _validate_path_list(manifest, "deleted")
    files = manifest["files"]
    if any(name in files for name in deleted):
        raise IntegrityError("deleted list names a present file")
    if any(name not in files for name in changed):
        raise IntegrityError("changed list names an absent file")
    for name, entry in files.items():
        relative_path(name)
        if not isinstance(entry, dict) or not isinstance(entry.get("chunks"), list):
            raise IntegrityError("invalid file entry")
        valid_digest(entry.get("sha256"))
        if not _valid_size(entry.get("size"), allow_zero=True):
            raise IntegrityError("invalid file size")
        total = 0
        for chunk in entry["chunks"]:
            if not isinstance(chunk, dict):
                raise IntegrityError("invalid chunk entry")
            valid_digest(chunk.get("sha256"))
            valid_digest(chunk.get("encoded_sha256"))
            if not _valid_size(chunk.get("size")) or not _valid_size(chunk.get("encoded_size")):
                raise IntegrityError("invalid chunk size")
            codec = chunk.get("codec")
            version = chunk.get("codec_version")
            if not isinstance(codec, str) or type(version) is not int or version < 1:
                raise IntegrityError("invalid chunk codec")
            get_codec(codec, version)  # unknown codecs are rejected, never skipped
            if codec == "identity" and (chunk["encoded_sha256"] != chunk["sha256"]
                                        or chunk["encoded_size"] != chunk["size"]):
                raise IntegrityError("identity chunk must record identical logical and encoded digests")
            total += chunk["size"]
        if total != entry["size"]:
            raise IntegrityError("chunk sizes do not add up")
    _reject_path_collisions(files)


def validate_legacy_manifest(manifest):
    """Structural validation for legacy format 1 manifests (read-only policy).

    Legacy manifests carry no authentication block and must never be
    reported as authenticated, however they were obtained.
    """
    if not isinstance(manifest, dict) or manifest.get("format") != 1 \
            or not isinstance(manifest.get("files"), dict) or not isinstance(manifest.get("metadata"), dict):
        raise IntegrityError("unsupported manifest format")
    if manifest.get("base") is not None:
        valid_digest(manifest["base"])
    for name, entry in manifest["files"].items():
        relative_path(name)
        if not isinstance(entry, dict) or not isinstance(entry.get("chunks"), list):
            raise IntegrityError("invalid file entry")
        valid_digest(entry.get("sha256"))
        if not _valid_size(entry.get("size"), allow_zero=True):
            raise IntegrityError("invalid file size")
        size = 0
        for chunk in entry["chunks"]:
            if not isinstance(chunk, dict):
                raise IntegrityError("invalid chunk entry")
            valid_digest(chunk.get("sha256"))
            if not _valid_size(chunk.get("size")):
                raise IntegrityError("invalid chunk size")
            size += chunk["size"]
        if size != entry["size"]:
            raise IntegrityError("chunk sizes do not add up")
    _reject_path_collisions(manifest["files"])
