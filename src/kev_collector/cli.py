from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .batches import write_batches
from .findings import merge_findings
from .io import read_json, read_jsonl, write_jsonl
from .kev import DEFAULT_KEV_URL, fetch_kev_json, normalize_kev_feed
from .prompts import render_batch_prompt
from .rank import rank_records
from .sample_pipeline import (
    import_snippets,
    list_sample_candidates,
    list_sample_reviews,
    prepare_sample_candidates,
)
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

    prompt_batch = subparsers.add_parser("prompt-batch", help="render a ready-to-send worker prompt for a batch")
    prompt_batch.add_argument("input", type=Path, help="batch JSONL file")
    prompt_batch.add_argument("--output", type=Path, help="write prompt to this Markdown file")
    prompt_batch.set_defaults(func=cmd_prompt_batch)

    samples = subparsers.add_parser("samples", help="sample candidate and review workflow")
    sample_subparsers = samples.add_subparsers(dest="samples_command", required=True)

    sample_candidates = sample_subparsers.add_parser("candidates", help="list duplicate-safe sample candidates")
    add_sample_filter_args(sample_candidates)
    sample_candidates.add_argument("--include-skipped", action="store_true", help="include already-started candidates")
    sample_candidates.set_defaults(func=cmd_samples_candidates)

    sample_prepare = sample_subparsers.add_parser("prepare", help="prepare patch bundles and snippet prompts")
    add_sample_filter_args(sample_prepare)
    sample_prepare.add_argument("--force", action="store_true", help="rebuild existing bundles/prompts")
    sample_prepare.add_argument("--no-fetch-code", action="store_true", help="create bundles/prompts without git fetching")
    sample_prepare.set_defaults(func=cmd_samples_prepare)

    sample_import = sample_subparsers.add_parser("import", help="create review-ready samples from snippet JSON")
    sample_import.add_argument("snippets", nargs="+", type=Path, help="snippet JSON file(s)")
    sample_import.add_argument("--force", action="store_true", help="overwrite an existing sample with the same key")
    sample_import.set_defaults(func=cmd_samples_import)

    sample_review_list = sample_subparsers.add_parser("review-list", help="list samples awaiting human review")
    sample_review_list.add_argument(
        "--status",
        default="needs_review",
        choices=["needs_review", "accepted", "rejected", "needs_more_evidence", "all"],
    )
    sample_review_list.add_argument("--jsonl", action="store_true", help="emit JSONL records")
    sample_review_list.set_defaults(func=cmd_samples_review_list)

    new_sample = subparsers.add_parser("new-sample", help="scaffold a triage-ready sample directory")
    new_sample.add_argument("cve_id")
    new_sample.add_argument("sample_id")
    new_sample.add_argument("--language", default="txt")
    new_sample.add_argument("--samples-root", type=Path, default=Path("samples"))
    new_sample.set_defaults(func=cmd_new_sample)

    validate = subparsers.add_parser("validate", help="validate JSONL files and sample directories")
    validate.set_defaults(func=cmd_validate)

    return parser


def add_sample_filter_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--findings", type=Path, default=Path("data/findings.jsonl"))
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--level", default="official_patch")
    parser.add_argument("--min-confidence", type=float, default=0.85)


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


def cmd_prompt_batch(args: argparse.Namespace) -> int:
    root = args.root
    input_path = resolve(root, args.input)
    records = read_jsonl(input_path)
    prompt = render_batch_prompt(input_path, records)
    if args.output:
        output = resolve(root, args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(prompt, encoding="utf-8")
        print(f"wrote prompt to {output}")
    else:
        print(prompt, end="")
    return 0


def cmd_samples_candidates(args: argparse.Namespace) -> int:
    candidates = list_sample_candidates(
        args.root,
        findings_path=args.findings,
        level=args.level,
        min_confidence=args.min_confidence,
        limit=args.limit,
        include_skipped=args.include_skipped,
    )
    for candidate in candidates:
        public = {
            "cve_id": candidate["cve_id"],
            "sample_id": candidate["sample_id"],
            "sample_key": candidate["sample_key"],
            "repo_url": candidate["repo_url"],
            "patch_ref": candidate["patch_ref"],
            "file_path": candidate["file_path"],
        }
        if candidate.get("skip_reason"):
            public["skip_reason"] = candidate["skip_reason"]
        import json

        print(json.dumps(public, sort_keys=True, separators=(",", ":")))
    return 0


def cmd_samples_prepare(args: argparse.Namespace) -> int:
    prepared = prepare_sample_candidates(
        args.root,
        findings_path=args.findings,
        limit=args.limit,
        level=args.level,
        min_confidence=args.min_confidence,
        force=args.force,
        fetch_code=not args.no_fetch_code,
    )
    for item in prepared:
        print(f"prepared {item['cve_id']} {item['sample_id']} [{item['fetch_status']}] -> {item['bundle_dir']}")
        print(f"prompt {item['prompt_path']}")
    if not prepared:
        print("prepared 0 sample candidate(s)")
    return 0


def cmd_samples_import(args: argparse.Namespace) -> int:
    paths = import_snippets(args.root, args.snippets, force=args.force)
    for path in paths:
        print(f"imported {path}")
    if not paths:
        print("imported 0 sample(s)")
    return 0


def cmd_samples_review_list(args: argparse.Namespace) -> int:
    records = list_sample_reviews(args.root, status=args.status)
    if args.jsonl:
        import json

        for record in records:
            print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    else:
        for record in records:
            confidence = record["confidence"] if record["confidence"] != "" else "-"
            marker = " MISSING_REVIEW" if record["missing_review"] else ""
            print(
                f"{record['cve_id']} {record['sample_id']} {record['status']} "
                f"{record['evidence_level'] or '-'} {confidence} {record['review_path']}{marker}"
            )
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
