from __future__ import annotations

from typing import Any

OPEN_SOURCE_HINTS = {
    "apache",
    "git",
    "linux",
    "mozilla",
    "wordpress",
    "drupal",
    "jenkins",
    "jquery",
    "openssl",
    "openbsd",
    "imagemagick",
    "grafana",
    "elastic",
    "kubernetes",
    "gitlab",
    "django",
    "rails",
    "php",
    "perl",
    "python",
    "node",
    "npm",
    "go",
    "ruby",
}

CODE_FRIENDLY_CWES = {
    "CWE-20",
    "CWE-22",
    "CWE-59",
    "CWE-77",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-95",
    "CWE-120",
    "CWE-121",
    "CWE-125",
    "CWE-190",
    "CWE-200",
    "CWE-287",
    "CWE-352",
    "CWE-416",
    "CWE-502",
    "CWE-611",
    "CWE-918",
}

PROPRIETARY_HINTS = {
    "cisco",
    "microsoft",
    "oracle",
    "adobe",
    "apple",
    "vmware",
    "citrix",
    "ivanti",
    "fortinet",
    "palo alto",
    "sonicwall",
    "sap",
}


def rank_record(record: dict[str, Any]) -> dict[str, Any]:
    text = " ".join(
        str(record.get(field, ""))
        for field in ("vendor_project", "product", "vulnerability_name", "short_description")
    ).lower()
    cwes = set(record.get("cwes") or [])

    score = 0
    reasons: list[str] = []

    open_source_matches = sorted(hint for hint in OPEN_SOURCE_HINTS if hint in text)
    if open_source_matches:
        score += 45
        reasons.append(f"open-source ecosystem hint: {', '.join(open_source_matches[:3])}")

    cwe_matches = sorted(cwes & CODE_FRIENDLY_CWES)
    if cwe_matches:
        score += 20
        reasons.append(f"code-review-friendly CWE: {', '.join(cwe_matches[:4])}")

    if "github" in text or "gitlab" in text:
        score += 15
        reasons.append("source-hosting hint in KEV text")

    if any(word in text for word in ("command injection", "xss", "path traversal", "buffer overflow", "deserialization")):
        score += 10
        reasons.append("vulnerability class often visible in source patches")

    proprietary_matches = sorted(hint for hint in PROPRIETARY_HINTS if hint in text)
    if proprietary_matches:
        score -= 20
        reasons.append(f"likely proprietary vendor: {', '.join(proprietary_matches[:3])}")

    if not reasons:
        reasons.append("no strong public-code signal from KEV metadata")

    candidate = dict(record)
    candidate["score"] = max(score, 0)
    candidate["score_reasons"] = reasons
    candidate["research_status"] = "needs_research"
    return candidate


def rank_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted((rank_record(record) for record in records), key=lambda item: (-item["score"], item["cve_id"]))
