from __future__ import annotations

from typing import Any

FINDING_REQUIRED_FIELDS = {"cve_id", "source_urls", "evidence_level"}

EVIDENCE_LEVELS = {
    "official_patch",
    "official_advisory",
    "upstream_release",
    "third_party_analysis",
    "weak_lead",
    "no_public_code",
}


def normalize_finding(record: dict[str, Any]) -> dict[str, Any]:
    cve_id = str(record.get("cve_id") or record.get("cveID") or "").strip()
    if not cve_id:
        raise ValueError("finding missing cve_id")

    source_urls = normalize_string_list(record.get("source_urls") or record.get("sourceURLs"))
    if not source_urls:
        raise ValueError(f"{cve_id}: finding missing source_urls")

    return {
        "cve_id": cve_id,
        "source_urls": source_urls,
        "repo_urls": normalize_string_list(record.get("repo_urls") or record.get("repoURLs")),
        "patch_refs": normalize_string_list(record.get("patch_refs") or record.get("patchRefs")),
        "affected_files": normalize_string_list(record.get("affected_files") or record.get("affectedFiles")),
        "license": str(record.get("license") or "").strip(),
        "evidence_level": normalize_evidence_level(
            record.get("evidence_level") or record.get("evidenceLevel")
        ),
        "confidence": normalize_confidence(record.get("confidence")),
        "notes": str(record.get("notes") or "").strip(),
    }


def merge_findings(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = {finding_key(item): item for item in existing}
    for record in incoming:
        finding = normalize_finding(record)
        merged[finding_key(finding)] = finding
    return sorted(merged.values(), key=lambda item: (item["cve_id"], item["source_urls"], item["patch_refs"]))


def finding_key(record: dict[str, Any]) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    return (
        str(record.get("cve_id") or ""),
        tuple(normalize_string_list(record.get("source_urls"))),
        tuple(normalize_string_list(record.get("patch_refs"))),
    )


def normalize_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = [str(item) for item in value if item is not None]
    else:
        values = [str(value)]
    return sorted({item.strip() for item in values if item.strip()})


def normalize_evidence_level(value: Any) -> str:
    evidence_level = str(value or "").strip().lower()
    if not evidence_level:
        raise ValueError("finding missing evidence_level")
    if evidence_level not in EVIDENCE_LEVELS:
        allowed = ", ".join(sorted(EVIDENCE_LEVELS))
        raise ValueError(f"invalid evidence_level {evidence_level!r}; expected one of: {allowed}")
    return evidence_level


def normalize_confidence(value: Any) -> float:
    if value is None or value == "":
        return 0.0
    try:
        confidence = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid confidence value: {value!r}") from exc
    if confidence < 0 or confidence > 1:
        raise ValueError(f"confidence must be between 0 and 1: {confidence}")
    return confidence
