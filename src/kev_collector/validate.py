from __future__ import annotations

from pathlib import Path

from .findings import normalize_finding
from .io import read_jsonl
from .samples import validate_sample_dir


def validate_workspace(root: Path) -> list[str]:
    errors: list[str] = []
    errors.extend(validate_jsonl_file(root / "data" / "kev.jsonl", required_fields={"cve_id"}))
    errors.extend(
        validate_jsonl_file(
            root / "data" / "candidates.jsonl",
            required_fields={"cve_id", "score", "score_reasons", "research_status"},
        )
    )

    findings_path = root / "data" / "findings.jsonl"
    if findings_path.exists():
        for index, record in enumerate(read_jsonl(findings_path), start=1):
            try:
                normalize_finding(record)
            except ValueError as exc:
                errors.append(f"{findings_path}:{index}: {exc}")

    samples_root = root / "samples"
    if samples_root.exists():
        for metadata_path in sorted(samples_root.glob("**/metadata.json")):
            errors.extend(validate_sample_dir(metadata_path.parent))

    return errors


def validate_jsonl_file(path: Path, required_fields: set[str]) -> list[str]:
    if not path.exists():
        return []

    errors: list[str] = []
    try:
        records = read_jsonl(path)
    except ValueError as exc:
        return [str(exc)]

    for index, record in enumerate(records, start=1):
        missing = sorted(field for field in required_fields if field not in record)
        if missing:
            errors.append(f"{path}:{index}: missing fields: {', '.join(missing)}")
    return errors
