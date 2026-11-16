import argparse
import json
import os

from .formats import AuthenticationError, IntegrityError
from .repository import Repository, RestoreBusyError, SessionConflictError

# Exit codes distinguish the three delivery outcomes:
#   0  success
#   1  integrity failure (an object was corrupted in transit/storage)
#   2  usage or input error
#   3  authentication failure (the manifest is not from a trusted publisher)
#   4  destination busy or incompatible interrupted session


def _load_keys(args):
    path = getattr(args, "key_file", None) or os.environ.get("PACKSMITH_KEY_FILE")
    if not path:
        return {}
    with open(path, encoding="utf-8") as stream:
        document = json.load(stream)
    if not isinstance(document, dict):
        raise ValueError("key file must map key ids to hex-encoded secrets")
    keys = {}
    for key_id, secret in document.items():
        if not isinstance(key_id, str) or not isinstance(secret, str):
            raise ValueError("key file must map key ids to hex-encoded secrets")
        try:
            keys[key_id] = bytes.fromhex(secret)
        except ValueError as exc:
            raise ValueError(f"invalid hex secret for key id {key_id!r}") from exc
    return keys


def main():
    parser = argparse.ArgumentParser(description="Authenticated, recoverable content-addressed packages")
    parser.add_argument("--repo", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    take = sub.add_parser("snapshot")
    take.add_argument("source")
    take.add_argument("--base")
    take.add_argument("--metadata", help="JSON metadata/schema contract file")
    take.add_argument("--chunk-size", type=int, default=1048576)
    take.add_argument("--compress", action="store_true", help="store chunks as zlib objects when smaller")
    take.add_argument("--key-id", required=True, help="key id from the key file used to sign the manifest")
    take.add_argument("--key-file", help="JSON file mapping key ids to hex secrets (or PACKSMITH_KEY_FILE)")
    take.add_argument("--allow-legacy", action="store_true", help="accept a legacy format 1 base manifest")
    for command in ("verify", "inspect", "restore"):
        item = sub.add_parser(command)
        item.add_argument("snapshot")
        item.add_argument("--key-file", help="JSON file mapping key ids to hex secrets (or PACKSMITH_KEY_FILE)")
        item.add_argument("--allow-legacy", action="store_true", help="read legacy format 1 manifests (never authenticated)")
        if command == "restore":
            item.add_argument("destination")
            item.add_argument("--file", action="append")
            item.add_argument("--require-metadata", help="Required top-level metadata values")
            item.add_argument("--reset", action="store_true", help="discard an incompatible interrupted session")
    args = parser.parse_args()
    try:
        repo = Repository(args.repo, keys=_load_keys(args),
                          sign_with=getattr(args, "key_id", None),
                          allow_legacy=getattr(args, "allow_legacy", False))
        if args.command == "snapshot":
            metadata = None
            if args.metadata:
                with open(args.metadata, encoding="utf-8") as stream:
                    metadata = json.load(stream)
            result = {"snapshot": repo.snapshot(args.source, base=args.base, chunk_size=args.chunk_size,
                                                metadata=metadata, compress=args.compress, key_id=args.key_id)}
        elif args.command == "restore":
            metadata = None
            if args.require_metadata:
                with open(args.require_metadata, encoding="utf-8") as stream:
                    metadata = json.load(stream)
            result = repo.restore(args.snapshot, args.destination, selected=args.file,
                                  required_metadata=metadata, reset_session=args.reset)
        elif args.command == "verify":
            result = repo.verify(args.snapshot)
        else:
            decision = repo.resolve(args.snapshot)
            result = {**decision.summary(), "manifest": decision.manifest}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result.get("ok") is False:
            raise SystemExit(1)
    except AuthenticationError as exc:
        parser.exit(3, f"error: {exc}\n")
    except (RestoreBusyError, SessionConflictError) as exc:
        parser.exit(4, f"error: {exc}\n")
    except IntegrityError as exc:
        parser.exit(1, f"error: {exc}\n")
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    main()
