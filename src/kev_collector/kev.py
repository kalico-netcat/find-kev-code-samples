from __future__ import annotations

import datetime as dt
import urllib.request
from typing import Any

DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_json(url: str = DEFAULT_KEV_URL, timeout: int = 30) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "kev-code-sample-collector/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read().decode("utf-8")
    import json

    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("KEV feed response must be a JSON object")
    return data


def normalize_kev_feed(feed: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerabilities = feed.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("KEV feed missing vulnerabilities list")

    records = []
    catalog_version = feed.get("catalogVersion")
    catalog_date_released = feed.get("dateReleased")
    fetched_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = string_or_empty(item.get("cveID"))
        if not cve_id:
            continue
        records.append(
            {
                "cve_id": cve_id,
                "vendor_project": string_or_empty(item.get("vendorProject")),
                "product": string_or_empty(item.get("product")),
                "vulnerability_name": string_or_empty(item.get("vulnerabilityName")),
                "short_description": string_or_empty(item.get("shortDescription")),
                "required_action": string_or_empty(item.get("requiredAction")),
                "date_added": string_or_empty(item.get("dateAdded")),
                "due_date": string_or_empty(item.get("dueDate")),
                "known_ransomware_campaign_use": string_or_empty(
                    item.get("knownRansomwareCampaignUse")
                ),
                "notes": string_or_empty(item.get("notes")),
                "cwes": normalize_cwes(item.get("cwes") or item.get("cwe")),
                "source": {
                    "catalog": "CISA KEV",
                    "catalog_version": catalog_version,
                    "catalog_date_released": catalog_date_released,
                    "fetched_at": fetched_at,
                },
            }
        )
    return records


def normalize_cwes(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = value.replace("|", ",").split(",")
    elif isinstance(value, list):
        parts = []
        for entry in value:
            if isinstance(entry, str):
                parts.extend(entry.replace("|", ",").split(","))
            elif entry is not None:
                parts.append(str(entry))
    else:
        parts = [str(value)]
    return sorted({part.strip() for part in parts if part and part.strip()})


def string_or_empty(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()
