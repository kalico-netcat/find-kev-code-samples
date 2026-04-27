from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .io import write_json

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
SAMPLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


def create_sample(root: Path, cve_id: str, sample_id: str, language: str = "txt") -> Path:
    if not CVE_PATTERN.match(cve_id):
        raise ValueError(f"invalid CVE ID: {cve_id}")
    if not SAMPLE_ID_PATTERN.match(sample_id):
        raise ValueError(f"invalid sample ID: {sample_id}")

    extension = normalize_extension(language)
    sample_dir = root / cve_id / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)

    metadata_path = sample_dir / "metadata.json"
    if not metadata_path.exists():
        write_json(
            metadata_path,
            {
                "cve_id": cve_id,
                "sample_id": sample_id,
                "status": "needs_review",
                "language": language,
                "source_urls": [],
                "repo_urls": [],
                "patch_refs": [],
                "affected_files": [],
                "license": {
                    "name": "",
                    "url": "",
                    "notes": "",
                },
                "provenance": {
                    "preferred_source": "",
                    "extraction_notes": "",
                },
            },
        )

    evidence_path = sample_dir / "evidence.md"
    if not evidence_path.exists():
        evidence_path.write_text(
            f"# Evidence for {cve_id} / {sample_id}\n\n"
            "## Source Links\n\n"
            "- TODO\n\n"
            "## Rationale\n\n"
            "TODO\n",
            encoding="utf-8",
        )

    for name in ("vulnerable", "fixed"):
        snippet_path = sample_dir / f"{name}.{extension}"
        if not snippet_path.exists():
            snippet_path.write_text("", encoding="utf-8")

    return sample_dir


def normalize_extension(language: str) -> str:
    language = language.strip().lower().lstrip(".") or "txt"
    aliases = {
        "python": "py",
        "javascript": "js",
        "typescript": "ts",
        "ruby": "rb",
        "golang": "go",
        "shell": "sh",
        "bash": "sh",
        "c++": "cpp",
        "plaintext": "txt",
    }
    return aliases.get(language, language)


def validate_sample_dir(sample_dir: Path) -> list[str]:
    errors: list[str] = []
    metadata_path = sample_dir / "metadata.json"
    evidence_path = sample_dir / "evidence.md"

    if not metadata_path.exists():
        return [f"{sample_dir}: missing metadata.json"]

    import json

    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{metadata_path}: invalid JSON: {exc}"]

    cve_id = str(metadata.get("cve_id") or "")
    sample_id = str(metadata.get("sample_id") or "")
    status = str(metadata.get("status") or "")

    if not CVE_PATTERN.match(cve_id):
        errors.append(f"{metadata_path}: invalid or missing cve_id")
    if not sample_id:
        errors.append(f"{metadata_path}: missing sample_id")
    if status not in {"needs_review", "accepted", "rejected", "needs_more_evidence"}:
        errors.append(f"{metadata_path}: invalid status")

    vulnerable_files = sorted(sample_dir.glob("vulnerable.*"))
    fixed_files = sorted(sample_dir.glob("fixed.*"))
    if not vulnerable_files:
        errors.append(f"{sample_dir}: missing vulnerable.* snippet")
    if not fixed_files:
        errors.append(f"{sample_dir}: missing fixed.* snippet")

    if status == "accepted":
        errors.extend(validate_accepted_sample(sample_dir, metadata, vulnerable_files, fixed_files, evidence_path))

    return errors


def validate_accepted_sample(
    sample_dir: Path,
    metadata: dict[str, Any],
    vulnerable_files: list[Path],
    fixed_files: list[Path],
    evidence_path: Path,
) -> list[str]:
    errors: list[str] = []
    metadata_path = sample_dir / "metadata.json"

    if not metadata.get("source_urls"):
        errors.append(f"{metadata_path}: accepted sample missing source_urls")

    license_info = metadata.get("license")
    if not isinstance(license_info, dict) or not (license_info.get("name") or license_info.get("url")):
        errors.append(f"{metadata_path}: accepted sample missing license metadata")

    for snippet in vulnerable_files + fixed_files:
        if not snippet.read_text(encoding="utf-8").strip():
            errors.append(f"{snippet}: accepted sample snippet is empty")

    if not evidence_path.exists() or not evidence_path.read_text(encoding="utf-8").strip():
        errors.append(f"{evidence_path}: accepted sample missing evidence notes")

    return errors
