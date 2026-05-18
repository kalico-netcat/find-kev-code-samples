from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .io import read_json, write_json
from .samples import normalize_extension, normalize_sample_kind

TRANSFORM_VERSION = "provenance-redaction-v1"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
COMMIT_RE = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)
ADVISORY_RE = re.compile(r"\b(?:GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}|[A-Z]+-\d{4}-\d{3,})\b")
TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9_]+")
COMMON_PROVENANCE_TOKENS = {
    "advisories",
    "commit",
    "commits",
    "fixed",
    "github",
    "https",
    "http",
    "lookalike",
    "negative",
    "security",
    "source",
    "src",
    "vulnerable",
}


@dataclass(frozen=True)
class CodePair:
    extension: str
    vulnerable_path: Path
    fixed_path: Path
    vulnerable_code: str
    fixed_code: str


@dataclass(frozen=True)
class NegativeCode:
    extension: str
    negative_path: Path
    negative_code: str


@dataclass(frozen=True)
class AnonymizedSample:
    source_fingerprint: str
    public_id: str
    source_sample_kind: str
    is_vulnerable: bool
    language: str
    extension: str
    vulnerable_code: str
    fixed_code: str
    sample_dir: Path
    status: str
    metadata: dict[str, Any]


def anonymize_samples(
    root: Path,
    status: str = "accepted",
    output_dir: Path = Path("anonymized-samples"),
    force: bool = False,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    sample_dirs = sample_dirs_for_status(root, status)
    output_root = resolve(root, output_dir)
    existing_ids = existing_public_ids(output_root)
    samples = build_anonymized_samples(sample_dirs, existing_ids=existing_ids)
    results: list[dict[str, Any]] = []
    for sample in samples:
        result = anonymize_sample_dir(
            sample,
            output_root,
            force=force,
            dry_run=dry_run,
        )
        results.append(result)
    return results


def sample_dirs_for_status(root: Path, status: str) -> list[Path]:
    allowed = {"needs_review", "accepted", "rejected", "needs_more_evidence", "all"}
    if status not in allowed:
        raise ValueError(f"invalid review status {status!r}; expected one of: {', '.join(sorted(allowed))}")

    samples_root = root / "samples"
    if not samples_root.exists():
        return []

    sample_dirs: list[Path] = []
    for metadata_path in sorted(samples_root.glob("**/metadata.json")):
        metadata = read_json(metadata_path)
        sample_status = str(metadata.get("status") or "") if isinstance(metadata, dict) else ""
        if status == "all" or sample_status == status:
            sample_dirs.append(metadata_path.parent)
    return sample_dirs


def anonymize_sample_dir(
    sample: AnonymizedSample,
    output_root: Path,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    destination = output_root / sample.public_id
    transform = anonymize_code_pair(sample.vulnerable_code, sample.fixed_code, sample.extension, sample.metadata)
    result = base_anonymize_result(sample, destination, dry_run)
    result["provenance_redactions"] = transform["provenance_redactions"]
    result["redaction_counts"] = transform["redaction_counts"]

    if dry_run:
        return result

    if destination.exists() and not force:
        existing_metadata = read_json(destination / "metadata.json") if (destination / "metadata.json").exists() else {}
        if (
            isinstance(existing_metadata, dict)
            and str(existing_metadata.get("source_fingerprint") or "") == result["source_fingerprint"]
        ):
            result["action"] = "skipped_existing"
            return result
        raise ValueError(f"{destination}: anonymized sample already exists; use --force to overwrite")

    destination.mkdir(parents=True, exist_ok=True)
    public_metadata = {
        "sample_id": sample.public_id,
        "status": result["status"],
        "sample_kind": sample.source_sample_kind,
        "is_vulnerable": sample.is_vulnerable,
        "language": sample.language,
        "source_fingerprint": sample.source_fingerprint,
        "transform_version": TRANSFORM_VERSION,
        "files": {
            "vulnerable": f"vulnerable.{sample.extension}",
            "fixed": f"fixed.{sample.extension}",
        },
        "expected_responses": public_expected_responses(sample),
    }
    write_json(destination / "metadata.json", public_metadata)
    (destination / f"vulnerable.{sample.extension}").write_text(transform["vulnerable_code"], encoding="utf-8")
    (destination / f"fixed.{sample.extension}").write_text(transform["fixed_code"], encoding="utf-8")
    write_json(
        destination / "mapping.json",
        {
            "transform_version": TRANSFORM_VERSION,
            "source_fingerprint": sample.source_fingerprint,
            "provenance_redactions": transform["provenance_redactions"],
            "redaction_counts": transform["redaction_counts"],
        },
    )
    (destination / "review.md").write_text(render_public_review(public_metadata, result), encoding="utf-8")
    result["action"] = "anonymized"
    return result


def base_anonymize_result(
    sample: AnonymizedSample,
    destination: Path,
    dry_run: bool,
) -> dict[str, Any]:
    return {
        "sample_id": sample.public_id,
        "source_fingerprint": sample.source_fingerprint,
        "status": sample.status,
        "sample_kind": sample.source_sample_kind,
        "is_vulnerable": sample.is_vulnerable,
        "language": sample.language,
        "destination": str(destination),
        "action": "planned" if dry_run else "",
        "dry_run": dry_run,
    }


def existing_public_ids(output_root: Path) -> dict[str, str]:
    ids: dict[str, str] = {}
    if not output_root.exists():
        return ids
    for metadata_path in sorted(output_root.glob("*/metadata.json")):
        metadata = read_json(metadata_path)
        if not isinstance(metadata, dict):
            continue
        fingerprint = str(metadata.get("source_fingerprint") or "").strip()
        sample_id = str(metadata.get("sample_id") or metadata_path.parent.name).strip()
        if fingerprint and sample_id:
            ids[fingerprint] = sample_id
    return ids


def build_anonymized_samples(sample_dirs: list[Path], existing_ids: dict[str, str]) -> list[AnonymizedSample]:
    samples: list[AnonymizedSample] = []
    for sample_dir in sample_dirs:
        metadata = read_json(sample_dir / "metadata.json")
        if not isinstance(metadata, dict):
            raise ValueError(f"{sample_dir / 'metadata.json'}: metadata must be an object")
        samples.append(build_sample_for_export(sample_dir, metadata, existing_ids))
    return samples


def build_sample_for_export(sample_dir: Path, metadata: dict[str, Any], existing_ids: dict[str, str]) -> AnonymizedSample:
    sample_kind = normalize_sample_kind(metadata)
    sample_language = str(metadata.get("language") or "txt")
    base_fingerprint = source_fingerprint(metadata, sample_dir)
    status = str(metadata.get("status") or "")
    if sample_kind == "negative":
        negative = read_negative_code(sample_dir, metadata)
        return AnonymizedSample(
            source_fingerprint=base_fingerprint,
            public_id=existing_ids.get(base_fingerprint, public_sample_id(base_fingerprint)),
            source_sample_kind=sample_kind,
            is_vulnerable=False,
            language=sample_language or negative.extension,
            extension=negative.extension,
            vulnerable_code=negative.negative_code,
            fixed_code=negative.negative_code,
            sample_dir=sample_dir,
            status=status,
            metadata=metadata,
        )

    pair = read_code_pair(sample_dir, metadata)
    return AnonymizedSample(
        source_fingerprint=base_fingerprint,
        public_id=existing_ids.get(base_fingerprint, public_sample_id(base_fingerprint)),
        source_sample_kind=sample_kind,
        is_vulnerable=True,
        language=sample_language or pair.extension,
        extension=pair.extension,
        vulnerable_code=pair.vulnerable_code,
        fixed_code=pair.fixed_code,
        sample_dir=sample_dir,
        status=status,
        metadata=metadata,
    )


def public_sample_id(source_fingerprint: str) -> str:
    token = source_fingerprint.removeprefix("sha256:").lower()
    return f"sample-{token[:20]}"


def read_code_pair(sample_dir: Path, metadata: dict[str, Any]) -> CodePair:
    vulnerable_files = sorted(sample_dir.glob("vulnerable.*"))
    fixed_files = sorted(sample_dir.glob("fixed.*"))
    if not vulnerable_files:
        raise ValueError(f"{sample_dir}: missing vulnerable.* snippet")
    if not fixed_files:
        raise ValueError(f"{sample_dir}: missing fixed.* snippet")

    vulnerable_path = vulnerable_files[0]
    fixed_path = fixed_files[0]
    extension = normalize_extension(str(metadata.get("language") or vulnerable_path.suffix.lstrip(".") or "txt"))
    if vulnerable_path.suffix:
        extension = vulnerable_path.suffix.lstrip(".")
    return CodePair(
        extension=extension,
        vulnerable_path=vulnerable_path,
        fixed_path=fixed_path,
        vulnerable_code=vulnerable_path.read_text(encoding="utf-8"),
        fixed_code=fixed_path.read_text(encoding="utf-8"),
    )


def read_negative_code(sample_dir: Path, metadata: dict[str, Any]) -> NegativeCode:
    negative_files = sorted(sample_dir.glob("negative.*"))
    if not negative_files:
        raise ValueError(f"{sample_dir}: missing negative.* snippet")

    negative_path = negative_files[0]
    extension = normalize_extension(str(metadata.get("language") or negative_path.suffix.lstrip(".") or "txt"))
    if negative_path.suffix:
        extension = negative_path.suffix.lstrip(".")
    return NegativeCode(
        extension=extension,
        negative_path=negative_path,
        negative_code=negative_path.read_text(encoding="utf-8"),
    )


def anonymize_code_pair(
    vulnerable_code: str,
    fixed_code: str,
    extension: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rules = provenance_redaction_rules(metadata or {})
    vulnerable_output, vulnerable_counts = redact_provenance(vulnerable_code, rules)
    fixed_output, fixed_counts = redact_provenance(fixed_code, rules)
    redaction_counts = merge_redaction_counts(vulnerable_counts, fixed_counts)
    return {
        "vulnerable_code": vulnerable_output,
        "fixed_code": fixed_output,
        "redaction_counts": redaction_counts,
        "provenance_redactions": sum(redaction_counts.values()),
    }


def anonymize_negative_code(
    negative_code: str,
    extension: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rules = provenance_redaction_rules(metadata or {})
    negative_output, redaction_counts = redact_provenance(negative_code, rules)
    return {
        "negative_code": negative_output,
        "redaction_counts": redaction_counts,
        "provenance_redactions": sum(redaction_counts.values()),
    }


def provenance_redaction_rules(metadata: dict[str, Any]) -> list[tuple[str, re.Pattern[str], str]]:
    rules: list[tuple[str, re.Pattern[str], str]] = [
        ("url", URL_RE, "URL_REDACTED"),
        ("cve", CVE_RE, "CVE_REDACTED"),
        ("advisory", ADVISORY_RE, "ADVISORY_REDACTED"),
        ("commit", COMMIT_RE, "COMMIT_REDACTED"),
    ]
    for path_fragment in sorted(source_path_fragments(metadata), key=len, reverse=True):
        rules.append(("path", re.compile(re.escape(path_fragment), re.IGNORECASE), "PATH_REDACTED"))
    for token in sorted(project_tokens(metadata), key=len, reverse=True):
        rules.append(("project", re.compile(rf"\b{re.escape(token)}\b", re.IGNORECASE), "PROJECT_REDACTED"))
    return rules


def redact_provenance(code: str, rules: list[tuple[str, re.Pattern[str], str]]) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}
    redacted = code
    for category, pattern, replacement in rules:
        redacted, count = pattern.subn(replacement, redacted)
        if count:
            counts[category] = counts.get(category, 0) + count
    return redacted, counts


def merge_redaction_counts(*counts: dict[str, int]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for count_by_category in counts:
        for category, count in count_by_category.items():
            merged[category] = merged.get(category, 0) + count
    return merged


def source_path_fragments(metadata: dict[str, Any]) -> set[str]:
    fragments: set[str] = set()
    for value in metadata_values(metadata, "sample_key", "derived_from_sample_key"):
        for part in str(value).split("|"):
            part = part.strip()
            if "/" in part and "." in part and not part.lower().startswith(("http://", "https://")):
                fragments.add(part)
    return fragments


def project_tokens(metadata: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for value in metadata_values(metadata, "repo_urls", "source_urls"):
        parsed = urlparse(str(value))
        path_parts = [part for part in parsed.path.split("/") if part]
        for part in path_parts[:2]:
            tokens.update(split_project_token(part))

    for value in metadata_values(metadata, "sample_key", "sample_id", "derived_from_sample_key", "derived_from_sample_id"):
        for token in split_project_token(str(value)):
            tokens.add(token)

    return {token for token in tokens if should_redact_project_token(token)}


def metadata_values(metadata: dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, list):
            values.extend(str(item) for item in value)
        elif value:
            values.append(str(value))
    return values


def split_project_token(value: str) -> set[str]:
    return {token.lower() for token in TOKEN_SPLIT_RE.split(value) if token}


def should_redact_project_token(token: str) -> bool:
    if len(token) < 4:
        return False
    if token in COMMON_PROVENANCE_TOKENS:
        return False
    if CVE_RE.fullmatch(token):
        return False
    if COMMIT_RE.fullmatch(token):
        return False
    if token.isdigit():
        return False
    return True


def source_fingerprint(metadata: dict[str, Any], sample_dir: Path) -> str:
    pieces = [
        str(metadata.get("sample_key") or ""),
        str(metadata.get("source_finding_key") or ""),
        str(metadata.get("cve_id") or ""),
        sample_dir.as_posix(),
    ]
    digest = hashlib.sha256("\n".join(pieces).encode("utf-8")).digest()
    return f"sha256:{base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')}"


def render_public_review(metadata: dict[str, Any], result: dict[str, Any]) -> str:
    file_summary = "vulnerable and fixed snippets"
    return f"""# {metadata['sample_id']}

Status: {metadata['status']}
Sample kind: {metadata.get('sample_kind', 'positive')}
Label: {"vulnerable sample" if metadata.get("is_vulnerable") else "non-vulnerable sample"}
Language: {metadata['language']}
Transform: {metadata['transform_version']}
Source fingerprint: `{metadata['source_fingerprint']}`

## Review Notes

This is a generated anonymized copy of a canonical KEV sample. Public provenance has been replaced with stable placeholders while comments, ordinary identifiers, formatting, and code structure were preserved across the exported {file_summary}.

## Transform Summary

- Provenance redactions: {result['provenance_redactions']}
- Redaction counts: {json.dumps(result['redaction_counts'], sort_keys=True)}
"""


def public_expected_responses(sample: AnonymizedSample) -> dict[str, Any]:
    expected = sample.metadata.get("expected_responses") if isinstance(sample.metadata.get("expected_responses"), dict) else {}
    if sample.source_sample_kind == "negative":
        source = expected.get("negative") if isinstance(expected.get("negative"), dict) else {}
        response = sanitize_expected_response(source, sample.metadata)
        response.update(
            {
                "file": f"vulnerable.{sample.extension}",
                "paired_file": f"fixed.{sample.extension}",
                "is_vulnerable": False,
                "label": "non_vulnerable",
            }
        )
        return {"vulnerable": response, "fixed": dict(response, file=f"fixed.{sample.extension}", paired_file=f"vulnerable.{sample.extension}")}

    vulnerable = sanitize_expected_response(
        expected.get("vulnerable") if isinstance(expected.get("vulnerable"), dict) else {},
        sample.metadata,
    )
    fixed = sanitize_expected_response(
        expected.get("fixed") if isinstance(expected.get("fixed"), dict) else {},
        sample.metadata,
    )
    vulnerable.update(
        {
            "file": f"vulnerable.{sample.extension}",
            "is_vulnerable": True,
            "label": "vulnerable",
        }
    )
    fixed.update(
        {
            "file": f"fixed.{sample.extension}",
            "is_vulnerable": False,
            "label": "fixed",
        }
    )
    return {"vulnerable": vulnerable, "fixed": fixed}


def sanitize_expected_response(response: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "vulnerability_type",
        "expected_behavior",
        "code_evidence",
        "fix_evidence",
        "negative_strategy",
    }
    rules = provenance_redaction_rules(metadata)
    sanitized: dict[str, Any] = {}
    for key in sorted(allowed):
        if key not in response:
            continue
        value = str(response.get(key) or "")
        sanitized[key] = redact_provenance(value, rules)[0]
    return sanitized


def validate_anonymized_output(root: Path) -> list[str]:
    errors: list[str] = []
    forbidden = [CVE_RE, re.compile(r"https?://", re.IGNORECASE), COMMIT_RE, ADVISORY_RE]
    if not root.exists():
        return errors
    for metadata_path in sorted(root.glob("*/metadata.json")):
        errors.extend(validate_anonymized_dir(metadata_path.parent))
    for path in sorted(root.glob("**/*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            if pattern.search(text):
                errors.append(f"{path}: contains public provenance marker matching {pattern.pattern}")
    return errors


def validate_anonymized_dir(item_dir: Path) -> list[str]:
    metadata_path = item_dir / "metadata.json"
    if not metadata_path.exists():
        return []

    try:
        metadata = read_json(metadata_path)
    except json.JSONDecodeError as exc:
        return [f"{metadata_path}: invalid JSON: {exc}"]
    if not isinstance(metadata, dict):
        return [f"{metadata_path}: metadata must be an object"]

    source_fingerprint = str(metadata.get("source_fingerprint") or "").strip()
    if not source_fingerprint:
        return []

    errors: list[str] = []
    files = metadata.get("files")
    if not isinstance(files, dict) or set(files.keys()) != {"vulnerable", "fixed"}:
        errors.append(f"{metadata_path}: anonymized sample must declare vulnerable and fixed snippet files")
        return errors

    for declared_name in files.values():
        snippet_path = item_dir / str(declared_name)
        if not snippet_path.exists():
            errors.append(f"{snippet_path}: missing anonymized snippet")

    snippet_files = [
        path
        for path in item_dir.iterdir()
        if path.is_file() and path.name not in {"metadata.json", "mapping.json", "review.md"}
    ]
    if len(snippet_files) != 2:
        errors.append(f"{item_dir}: anonymized sample must contain exactly two snippet files")

    if "is_vulnerable" not in metadata:
        errors.append(f"{metadata_path}: missing is_vulnerable")
    return errors


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path
