import argparse
import json
from .repository import Repository


def main():
    parser = argparse.ArgumentParser(description="Recoverable content-addressed packages")
    parser.add_argument("--repo", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    take = sub.add_parser("snapshot")
    take.add_argument("source")
    take.add_argument("--base")
    take.add_argument("--metadata", help="JSON metadata/schema contract file")
    take.add_argument("--chunk-size", type=int, default=1048576)
    for command in ("verify", "inspect", "restore"):
        item = sub.add_parser(command)
        item.add_argument("snapshot")
        if command == "restore":
            item.add_argument("destination")
            item.add_argument("--file", action="append")
            item.add_argument("--require-metadata", help="Required top-level metadata values")
    args = parser.parse_args()
    try:
        repo = Repository(args.repo)
        if args.command == "snapshot":
            metadata = None
            if args.metadata:
                with open(args.metadata, encoding="utf-8") as stream: metadata = json.load(stream)
            result = {"snapshot": repo.snapshot(args.source, base=args.base, chunk_size=args.chunk_size, metadata=metadata)}
        elif args.command == "restore":
            metadata = None
            if args.require_metadata:
                with open(args.require_metadata, encoding="utf-8") as stream: metadata = json.load(stream)
            result = repo.restore(args.snapshot, args.destination, selected=args.file, required_metadata=metadata)
        elif args.command == "verify":
            result = repo.verify(args.snapshot)
        else:
            result = repo.load(args.snapshot)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result.get("ok") is False:
            raise SystemExit(1)
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    main()
