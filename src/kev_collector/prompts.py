from __future__ import annotations

import json
from pathlib import Path
from typing import Any

OUTPUT_SCHEMA = {
    "cve_id": "CVE-YYYY-NNNN",
    "source_urls": ["https://..."],
    "repo_urls": ["https://..."],
    "patch_refs": ["commit/tag/release/advisory ref"],
    "affected_files": ["path/or/component"],
    "license": "MIT/Apache-2.0/GPL/unknown/etc",
    "evidence_level": "official_patch",
    "confidence": 0.0,
    "notes": "Short evidence summary and uncertainty.",
}


def render_batch_prompt(batch_path: Path, records: list[dict[str, Any]]) -> str:
    batch_name = batch_path.name
    suggested_output = f"findings/{batch_path.stem}.jsonl"
    batch_jsonl = "\n".join(json.dumps(record, sort_keys=True) for record in records)
    schema = json.dumps(OUTPUT_SCHEMA, sort_keys=True, separators=(",", ":"))

    return f"""# KEV Batch Research Task

You are a worker research agent for the KEV code sample collector.

## Role Boundaries

- You receive exactly one batch file: `{batch_name}`.
- Research every CVE in this batch.
- Return findings JSONL only, suitable to save as `{suggested_output}`.
- Do not edit `data/findings.jsonl`.
- Do not create accepted samples.
- Do not modify unrelated project files.

The orchestrator owns repo state, ingests findings, and runs validation after your work.

## Research Goal

For each CVE, find public evidence that can help later collect a minimal vulnerable/fixed code sample. Prefer official project repositories, vendor advisories, project release notes, and official patch commits. Use public web sources only when official sources do not provide enough evidence.

Clearly distinguish confirmed patch refs from speculative references. If no reliable source-code evidence is found, use `weak_lead` or `no_public_code` with notes explaining the blocker.

## Evidence Levels

- `official_patch`: official project repository commit, patch, pull request, or comparable source ref explicitly tied to the CVE.
- `official_advisory`: official vendor/project advisory identifies affected versions or remediation, but no exact source patch is confirmed.
- `upstream_release`: upstream release notes, changelog, tag, or version diff strongly indicate the fix.
- `third_party_analysis`: credible public analysis, advisory database, blog, exploit writeup, or mirror provides useful source leads.
- `weak_lead`: possible repo, file, patch, or source trail exists, but CVE-to-code linkage is incomplete or speculative.
- `no_public_code`: research found no usable public source trail, or the product appears closed source.

Use both fields:

- `evidence_level` describes the kind of source evidence found.
- `confidence` describes how sure you are that the evidence is correctly linked to this CVE and useful for later source/sample extraction.

These fields are independent. For example, use `official_patch` with low confidence when the patch is official but the CVE-to-commit linkage is inferred from a release window, internal bug ID, or ambiguous advisory.

## Required Output

Return newline-delimited JSON only. Do not wrap it in Markdown. Each line must be one JSON object with this shape:

```json
{schema}
```

Required fields are `cve_id`, `source_urls`, `evidence_level`, `confidence`, and `notes`. Prefer empty arrays or `unknown` over omitted optional fields.

## Batch Records

```jsonl
{batch_jsonl}
```
"""
