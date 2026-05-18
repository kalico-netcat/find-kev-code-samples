from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .io import write_json

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
SAMPLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
ALLOWED_STATUSES = {"needs_review", "accepted", "rejected", "needs_more_evidence"}
ALLOWED_SAMPLE_KINDS = {"positive", "negative"}
NEGATIVE_STRATEGY = "fixed-lookalike-v1"


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
                "sample_kind": "positive",
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
                "expected_responses": {
                    "vulnerable": {
                        "file": f"vulnerable.{extension}",
                        "is_vulnerable": True,
                        "label": "vulnerable",
                        "vulnerability_type": "",
                        "code_evidence": "",
                        "fix_evidence": "",
                    },
                    "fixed": {
                        "file": f"fixed.{extension}",
                        "is_vulnerable": False,
                        "label": "fixed",
                        "vulnerability_type": "",
                        "code_evidence": "",
                        "fix_evidence": "",
                    },
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
    sample_kind = normalize_sample_kind(metadata)

    if not CVE_PATTERN.match(cve_id):
        errors.append(f"{metadata_path}: invalid or missing cve_id")
    if not sample_id:
        errors.append(f"{metadata_path}: missing sample_id")
    if status not in ALLOWED_STATUSES:
        errors.append(f"{metadata_path}: invalid status")
    if sample_kind not in ALLOWED_SAMPLE_KINDS:
        errors.append(f"{metadata_path}: invalid sample_kind")
        return errors

    if sample_kind == "positive":
        vulnerable_files = sorted(sample_dir.glob("vulnerable.*"))
        fixed_files = sorted(sample_dir.glob("fixed.*"))
        if not vulnerable_files:
            errors.append(f"{sample_dir}: missing vulnerable.* snippet")
        if not fixed_files:
            errors.append(f"{sample_dir}: missing fixed.* snippet")

        if status == "accepted":
            errors.extend(validate_accepted_positive_sample(sample_dir, metadata, vulnerable_files, fixed_files, evidence_path))
            errors.extend(validate_expected_responses(metadata_path, metadata, {"vulnerable", "fixed"}))
    else:
        negative_files = sorted(sample_dir.glob("negative.*"))
        if not negative_files:
            errors.append(f"{sample_dir}: missing negative.* snippet")
        errors.extend(validate_negative_sample_metadata(metadata_path, metadata))
        if status == "accepted":
            errors.extend(validate_accepted_negative_sample(metadata_path, metadata, negative_files, evidence_path))
            errors.extend(validate_expected_responses(metadata_path, metadata, {"negative"}))

    return errors


def validate_accepted_positive_sample(
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


def validate_negative_sample_metadata(metadata_path: Path, metadata: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required_fields = {
        "derived_from_sample_id",
        "derived_from_sample_key",
        "negative_strategy",
    }
    missing = sorted(field for field in required_fields if not str(metadata.get(field) or "").strip())
    if missing:
        errors.append(f"{metadata_path}: negative sample missing fields: {', '.join(missing)}")
    elif str(metadata.get("negative_strategy") or "") != NEGATIVE_STRATEGY:
        errors.append(f"{metadata_path}: invalid negative_strategy")
    return errors


def validate_accepted_negative_sample(
    metadata_path: Path,
    metadata: dict[str, Any],
    negative_files: list[Path],
    evidence_path: Path,
) -> list[str]:
    errors: list[str] = []

    if not metadata.get("source_urls"):
        errors.append(f"{metadata_path}: accepted sample missing source_urls")

    license_info = metadata.get("license")
    if not isinstance(license_info, dict) or not (license_info.get("name") or license_info.get("url")):
        errors.append(f"{metadata_path}: accepted sample missing license metadata")

    for snippet in negative_files:
        if not snippet.read_text(encoding="utf-8").strip():
            errors.append(f"{snippet}: accepted sample snippet is empty")

    if not evidence_path.exists() or not evidence_path.read_text(encoding="utf-8").strip():
        errors.append(f"{evidence_path}: accepted sample missing evidence notes")

    return errors


def validate_expected_responses(metadata_path: Path, metadata: dict[str, Any], expected_keys: set[str]) -> list[str]:
    errors: list[str] = []
    responses = metadata.get("expected_responses")
    if not isinstance(responses, dict):
        return [f"{metadata_path}: accepted sample missing expected_responses"]

    missing_keys = sorted(key for key in expected_keys if not isinstance(responses.get(key), dict))
    if missing_keys:
        errors.append(f"{metadata_path}: expected_responses missing entries: {', '.join(missing_keys)}")
        return errors

    for key in sorted(expected_keys):
        response = responses[key]
        required = {"file", "is_vulnerable", "label", "vulnerability_type", "code_evidence"}
        missing_fields = sorted(field for field in required if field not in response)
        if missing_fields:
            errors.append(f"{metadata_path}: expected_responses.{key} missing fields: {', '.join(missing_fields)}")
            continue
        empty_fields = sorted(
            field
            for field in ("vulnerability_type", "code_evidence")
            if not str(response.get(field) or "").strip()
        )
        if empty_fields:
            errors.append(f"{metadata_path}: expected_responses.{key} empty fields: {', '.join(empty_fields)}")
    return errors


def normalize_sample_kind(metadata: dict[str, Any]) -> str:
    value = str(metadata.get("sample_kind") or "positive").strip().lower()
    return value or "positive"
