from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .batches import write_batches
from .findings import merge_findings
from .io import read_json, read_jsonl, write_jsonl
from .kev import DEFAULT_KEV_URL, fetch_kev_json, normalize_kev_feed
from .rank import rank_records
from .samples import create_sample
from .validate import validate_workspace


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kev-collector")
    parser.add_argument("--root", type=Path, default=Path("."), help="workspace root")
    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch = subparsers.add_parser("fetch", help="download and normalize the CISA KEV feed")
    fetch.add_argument("--url", default=DEFAULT_KEV_URL, help="CISA KEV JSON feed URL")
    fetch.add_argument("--input", type=Path, help="read KEV JSON from a local fixture instead of the network")
    fetch.add_argument("--output", type=Path, default=Path("data/kev.jsonl"))
    fetch.set_defaults(func=cmd_fetch)

    rank = subparsers.add_parser("rank", help="score KEV records for likely public-code availability")
    rank.add_argument("--input", type=Path, default=Path("data/kev.jsonl"))
    rank.add_argument("--output", type=Path, default=Path("data/candidates.jsonl"))
    rank.set_defaults(func=cmd_rank)

    batch = subparsers.add_parser("batch", help="write candidate research batches")
    batch.add_argument("--input", type=Path, default=Path("data/candidates.jsonl"))
    batch.add_argument("--output-dir", type=Path, default=Path("batches"))
    batch.add_argument("--size", type=int, default=20)
    batch.add_argument("--min-score", type=int, default=1)
    batch.set_defaults(func=cmd_batch)

    ingest = subparsers.add_parser("ingest", help="merge structured research findings")
    ingest.add_argument("input", type=Path, help="JSONL findings to ingest")
    ingest.add_argument("--output", type=Path, default=Path("data/findings.jsonl"))
    ingest.set_defaults(func=cmd_ingest)

    new_sample = subparsers.add_parser("new-sample", help="scaffold a triage-ready sample directory")
    new_sample.add_argument("cve_id")
    new_sample.add_argument("sample_id")
    new_sample.add_argument("--language", default="txt")
    new_sample.add_argument("--samples-root", type=Path, default=Path("samples"))
    new_sample.set_defaults(func=cmd_new_sample)

    validate = subparsers.add_parser("validate", help="validate JSONL files and sample directories")
    validate.set_defaults(func=cmd_validate)

    return parser


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def cmd_fetch(args: argparse.Namespace) -> int:
    root = args.root
    feed = read_json(resolve(root, args.input)) if args.input else fetch_kev_json(args.url)
    records = normalize_kev_feed(feed)
    output = resolve(root, args.output)
    count = write_jsonl(output, records)
    print(f"wrote {count} KEV records to {output}")
    return 0


def cmd_rank(args: argparse.Namespace) -> int:
    root = args.root
    records = read_jsonl(resolve(root, args.input))
    ranked = rank_records(records)
    output = resolve(root, args.output)
    count = write_jsonl(output, ranked)
    print(f"wrote {count} candidates to {output}")
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    root = args.root
    records = [
        record
        for record in read_jsonl(resolve(root, args.input))
        if int(record.get("score") or 0) >= args.min_score
        and record.get("research_status", "needs_research") == "needs_research"
    ]
    paths = write_batches(records, resolve(root, args.output_dir), batch_size=args.size)
    print(f"wrote {len(paths)} batch file(s) to {resolve(root, args.output_dir)}")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    root = args.root
    output = resolve(root, args.output)
    existing = read_jsonl(output)
    incoming = read_jsonl(resolve(root, args.input))
    merged = merge_findings(existing, incoming)
    count = write_jsonl(output, merged)
    print(f"wrote {count} finding(s) to {output}")
    return 0


def cmd_new_sample(args: argparse.Namespace) -> int:
    sample_dir = create_sample(resolve(args.root, args.samples_root), args.cve_id, args.sample_id, args.language)
    print(f"created sample scaffold at {sample_dir}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    errors = validate_workspace(args.root)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"validation failed with {len(errors)} error(s)", file=sys.stderr)
        return 1
    print("validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
