from __future__ import annotations

import json
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .findings import normalize_finding
from .io import read_json, read_jsonl, write_json
from .samples import normalize_extension

COMMIT_RE = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)
SLUG_RE = re.compile(r"[^a-z0-9_.-]+")


@dataclass(frozen=True)
class ExistingWork:
    sample_keys: set[str]
    bundle_keys: set[str]
    proposal_keys: set[str]

    @property
    def all_keys(self) -> set[str]:
        return self.sample_keys | self.bundle_keys | self.proposal_keys

    def reason_for(self, sample_key: str) -> str:
        reasons = []
        if sample_key in self.sample_keys:
            reasons.append("sample")
        if sample_key in self.bundle_keys:
            reasons.append("bundle")
        if sample_key in self.proposal_keys:
            reasons.append("proposal")
        return "already_exists:" + ",".join(reasons) if reasons else ""


def list_sample_candidates(
    root: Path,
    findings_path: Path = Path("data/findings.jsonl"),
    level: str = "official_patch",
    min_confidence: float = 0.85,
    limit: int = 5,
    include_skipped: bool = False,
) -> list[dict[str, Any]]:
    existing = scan_existing_work(root)
    records: list[dict[str, Any]] = []

    for raw in read_jsonl(resolve(root, findings_path)):
        finding = normalize_finding(raw)
        if finding["evidence_level"] != level:
            continue
        if finding["confidence"] < min_confidence:
            continue

        candidate = build_sample_candidate(finding)
        skip_reason = existing.reason_for(candidate["sample_key"])
        if skip_reason:
            candidate["skip_reason"] = skip_reason
            if include_skipped:
                records.append(candidate)
            continue

        records.append(candidate)
        if limit and not include_skipped and len(records) >= limit:
            break

    if include_skipped and limit:
        unskipped = [record for record in records if not record.get("skip_reason")]
        skipped = [record for record in records if record.get("skip_reason")]
        records = unskipped[:limit] + skipped

    return records


def prepare_sample_candidates(
    root: Path,
    findings_path: Path = Path("data/findings.jsonl"),
    limit: int = 5,
    level: str = "official_patch",
    min_confidence: float = 0.85,
    force: bool = False,
) -> list[dict[str, str]]:
    if force:
        candidates = [
            candidate
            for candidate in list_sample_candidates(
                root,
                findings_path=findings_path,
                level=level,
                min_confidence=min_confidence,
                limit=0,
                include_skipped=True,
            )
            if candidate.get("skip_reason", "").startswith("already_exists:bundle")
            or not candidate.get("skip_reason")
        ][:limit]
    else:
        candidates = list_sample_candidates(
            root,
            findings_path=findings_path,
            level=level,
            min_confidence=min_confidence,
            limit=limit,
        )

    prepared: list[dict[str, str]] = []
    for candidate in candidates:
        bundle_dir = root / "work" / candidate["cve_id"] / candidate["sample_id"]
        prompt_path = root / "prompts" / "snippets" / f"{candidate['cve_id']}-{candidate['sample_id']}.md"
        write_patch_bundle(bundle_dir, candidate, force=force)
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        if force or not prompt_path.exists():
            prompt_path.write_text(render_snippet_prompt(candidate, bundle_dir), encoding="utf-8")
        prepared.append(
            {
                "cve_id": candidate["cve_id"],
                "sample_id": candidate["sample_id"],
                "sample_key": candidate["sample_key"],
                "bundle_dir": str(bundle_dir),
                "prompt_path": str(prompt_path),
            }
        )
    return prepared


def materialize_proposals(root: Path, proposal_paths: list[Path], force: bool = False) -> list[Path]:
    existing = scan_existing_work(root)
    materialized: list[Path] = []
    for proposal_path in proposal_paths:
        proposal = read_json(resolve(root, proposal_path))
        validate_proposal(proposal)
        sample_key = str(proposal["sample_key"])
        if sample_key in existing.sample_keys and not force:
            raise ValueError(f"{proposal_path}: sample_key already materialized: {sample_key}")

        cve_id = str(proposal["cve_id"])
        sample_id = str(proposal["sample_id"])
        language = str(proposal.get("language") or "txt")
        extension = normalize_extension(language)
        sample_dir = root / "samples" / cve_id / sample_id
        sample_dir.mkdir(parents=True, exist_ok=True)

        metadata = {
            "cve_id": cve_id,
            "sample_id": sample_id,
            "sample_key": sample_key,
            "source_finding_key": proposal["source_finding_key"],
            "status": "needs_review",
            "language": language,
            "source_urls": proposal.get("source_urls", []),
            "repo_urls": proposal.get("repo_urls", []),
            "patch_refs": proposal.get("patch_refs", []),
            "affected_files": [proposal["file_path"]],
            "license": {
                "name": proposal.get("license", ""),
                "url": "",
                "notes": "",
            },
            "provenance": {
                "preferred_source": proposal.get("evidence_level", ""),
                "extraction_notes": proposal.get("rationale", ""),
            },
        }
        write_json(sample_dir / "metadata.json", metadata)
        (sample_dir / f"vulnerable.{extension}").write_text(proposal["vulnerable_code"], encoding="utf-8")
        (sample_dir / f"fixed.{extension}").write_text(proposal["fixed_code"], encoding="utf-8")
        (sample_dir / "evidence.md").write_text(render_evidence(proposal), encoding="utf-8")
        (sample_dir / "review.md").write_text(render_review(proposal), encoding="utf-8")
        materialized.append(sample_dir)
        existing.sample_keys.add(sample_key)
    return materialized


def list_sample_reviews(root: Path, status: str = "needs_review") -> list[dict[str, Any]]:
    allowed_statuses = {"needs_review", "accepted", "rejected", "needs_more_evidence", "all"}
    if status not in allowed_statuses:
        raise ValueError(f"invalid review status {status!r}; expected one of: {', '.join(sorted(allowed_statuses))}")

    samples_root = root / "samples"
    records: list[dict[str, Any]] = []
    if not samples_root.exists():
        return records

    for metadata_path in sorted(samples_root.glob("**/metadata.json")):
        metadata = read_json(metadata_path)
        if not isinstance(metadata, dict):
            continue
        sample_status = str(metadata.get("status") or "")
        if status != "all" and sample_status != status:
            continue

        sample_dir = metadata_path.parent
        review_path = sample_dir / "review.md"
        provenance = metadata.get("provenance") if isinstance(metadata.get("provenance"), dict) else {}
        records.append(
            {
                "cve_id": str(metadata.get("cve_id") or ""),
                "sample_id": str(metadata.get("sample_id") or ""),
                "status": sample_status,
                "evidence_level": str(provenance.get("preferred_source") or metadata.get("evidence_level") or ""),
                "confidence": metadata.get("confidence", ""),
                "review_path": str(review_path),
                "missing_review": not review_path.exists(),
            }
        )
    return records


def write_patch_bundle(bundle_dir: Path, candidate: dict[str, Any], force: bool = False) -> None:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = bundle_dir / "metadata.json"
    if metadata_path.exists() and not force:
        return
    write_json(metadata_path, patch_bundle_metadata(candidate))
    write_json(bundle_dir / "finding.json", candidate["finding"])
    (bundle_dir / "patch.diff").write_text("", encoding="utf-8")
    (bundle_dir / "candidate_hunks.jsonl").write_text("", encoding="utf-8")
    (bundle_dir / "vulnerable").mkdir(exist_ok=True)
    (bundle_dir / "fixed").mkdir(exist_ok=True)


def patch_bundle_metadata(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": candidate["cve_id"],
        "sample_id": candidate["sample_id"],
        "sample_key": candidate["sample_key"],
        "source_finding_key": candidate["source_finding_key"],
        "repo_url": candidate["repo_url"],
        "patch_ref": candidate["patch_ref"],
        "file_path": candidate["file_path"],
        "status": "prepared",
    }


def build_sample_candidate(finding: dict[str, Any]) -> dict[str, Any]:
    repo_url = normalize_repo_url(first_or_unknown(finding.get("repo_urls")))
    patch_ref = normalize_patch_ref(first_commit_ref(finding) or first_or_unknown(finding.get("patch_refs")))
    file_path = normalize_file_path(first_file_path(finding.get("affected_files")))
    cve_id = finding["cve_id"]
    sample_key = "|".join([cve_id, repo_url, patch_ref, file_path])
    source_finding_key = "|".join(
        [
            cve_id,
            ",".join(finding.get("source_urls") or []),
            ",".join(finding.get("patch_refs") or []),
        ]
    )
    sample_id = derive_sample_id(repo_url, patch_ref, file_path)
    return {
        "cve_id": cve_id,
        "sample_id": sample_id,
        "sample_key": sample_key,
        "source_finding_key": source_finding_key,
        "repo_url": repo_url,
        "patch_ref": patch_ref,
        "file_path": file_path,
        "finding": finding,
    }


def derive_sample_id(repo_url: str, patch_ref: str, file_path: str) -> str:
    repo_slug = repo_slug_from_url(repo_url)
    patch_slug = patch_ref[:12] if COMMIT_RE.fullmatch(patch_ref) else slugify(patch_ref)[:24]
    file_stem = slugify(Path(file_path).stem or "sample")[:24]
    return "-".join(part for part in (repo_slug, patch_slug, file_stem) if part)[:96]


def repo_slug_from_url(repo_url: str) -> str:
    parsed = urlparse(repo_url)
    path = parsed.path.strip("/") if parsed.scheme else repo_url.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = [slugify(part) for part in path.split("/") if part]
    return "-".join(parts[-2:]) if len(parts) >= 2 else (parts[0] if parts else "unknown-repo")


def normalize_repo_url(value: str) -> str:
    value = value.strip()
    if not value:
        return "unknown-repo"
    if value.endswith(".git"):
        value = value[:-4]
    return value.rstrip("/").lower()


def normalize_patch_ref(value: str) -> str:
    value = value.strip()
    match = COMMIT_RE.search(value)
    return match.group(0).lower() if match else slugify(value or "unknown-ref")


def normalize_file_path(value: str) -> str:
    return value.strip().replace("\\", "/") or "unknown-file"


def first_commit_ref(finding: dict[str, Any]) -> str:
    for value in list(finding.get("patch_refs") or []) + list(finding.get("source_urls") or []):
        match = COMMIT_RE.search(str(value))
        if match:
            return match.group(0)
    return ""


def first_file_path(values: Any) -> str:
    for value in values or []:
        text = str(value).strip()
        if "/" in text and " " not in text:
            return text
    for value in values or []:
        text = str(value).strip()
        if "." in text and " " not in text:
            return text
    return first_or_unknown(values, default="unknown-file")


def first_or_unknown(values: Any, default: str = "unknown") -> str:
    if isinstance(values, list) and values:
        return str(values[0])
    if isinstance(values, str) and values:
        return values
    return default


def slugify(value: str) -> str:
    value = value.lower().strip()
    value = SLUG_RE.sub("-", value)
    return value.strip("-") or "unknown"


def scan_existing_work(root: Path) -> ExistingWork:
    return ExistingWork(
        sample_keys=scan_metadata_keys(root / "samples"),
        bundle_keys=scan_metadata_keys(root / "work"),
        proposal_keys=scan_proposal_keys(root / "proposals"),
    )


def scan_metadata_keys(root: Path) -> set[str]:
    keys: set[str] = set()
    if not root.exists():
        return keys
    for path in root.glob("**/metadata.json"):
        try:
            value = read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        sample_key = value.get("sample_key") if isinstance(value, dict) else None
        if sample_key:
            keys.add(str(sample_key))
    return keys


def scan_proposal_keys(root: Path) -> set[str]:
    keys: set[str] = set()
    if not root.exists():
        return keys
    for path in root.glob("**/*.json"):
        try:
            value = read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        sample_key = value.get("sample_key") if isinstance(value, dict) else None
        if sample_key:
            keys.add(str(sample_key))
    return keys


def render_snippet_prompt(candidate: dict[str, Any], bundle_dir: Path) -> str:
    schema = {
        "cve_id": candidate["cve_id"],
        "sample_id": candidate["sample_id"],
        "sample_key": candidate["sample_key"],
        "source_finding_key": candidate["source_finding_key"],
        "file_path": candidate["file_path"],
        "language": "txt",
        "vulnerable_range": {"start": 1, "end": 1},
        "fixed_range": {"start": 1, "end": 1},
        "vulnerable_code": "...",
        "fixed_code": "...",
        "rationale": "Why this is the minimal useful snippet.",
        "uncertainty": "Any ambiguity or review concern.",
        "review_notes": "Notes for human reviewer.",
    }
    finding_json = json.dumps(candidate["finding"], indent=2, sort_keys=True)
    schema_json = json.dumps(schema, indent=2, sort_keys=True)
    return f"""# Snippet Selection Task

You are a snippet-selection worker for the KEV code sample collector.

Use the prepared patch bundle at `{bundle_dir}`. Choose the smallest vulnerable/fixed code snippets that are still understandable for human secure-code review.

Return JSON only. Do not write files.

## Required Proposal Shape

```json
{schema_json}
```

## Selection Rules

- Prefer the file path already identified by the finding when it contains the vulnerable logic.
- Include enough surrounding context for a reviewer to understand why the vulnerable code is risky.
- Do not include unrelated refactors, test-only changes, or broad whole-file excerpts unless unavoidable.
- If the bundle does not yet contain fetched code, use the source URLs and patch refs to propose the expected file/range and include uncertainty.

## Finding

```json
{finding_json}
```
"""


def validate_proposal(proposal: dict[str, Any]) -> None:
    required = {
        "cve_id",
        "sample_id",
        "sample_key",
        "source_finding_key",
        "file_path",
        "vulnerable_code",
        "fixed_code",
        "rationale",
    }
    missing = sorted(field for field in required if not proposal.get(field))
    if missing:
        raise ValueError(f"proposal missing fields: {', '.join(missing)}")


def render_evidence(proposal: dict[str, Any]) -> str:
    source_urls = "\n".join(f"- {url}" for url in proposal.get("source_urls", [])) or "- TODO"
    patch_refs = "\n".join(f"- {ref}" for ref in proposal.get("patch_refs", [])) or "- TODO"
    return f"""# Evidence for {proposal['cve_id']} / {proposal['sample_id']}

## Source Links

{source_urls}

## Patch References

{patch_refs}

## Rationale

{proposal.get('rationale', '')}
"""


def render_review(proposal: dict[str, Any]) -> str:
    diff = proposal.get("diff", "")
    if not diff:
        diff = "(No focused diff supplied by proposal.)"
    return f"""# {proposal['cve_id']} / {proposal['sample_id']}

Sample key: `{proposal['sample_key']}`
Source finding: `{proposal['source_finding_key']}`
Status: needs_review
Evidence level: {proposal.get('evidence_level', '')}
Confidence: {proposal.get('confidence', '')}
License: {proposal.get('license', '')}

## Source

- Repo: {', '.join(proposal.get('repo_urls', []))}
- Source URLs: {', '.join(proposal.get('source_urls', []))}
- Patch refs: {', '.join(proposal.get('patch_refs', []))}

## Selected Snippet

File: `{proposal['file_path']}`
Vulnerable range: {format_range(proposal.get('vulnerable_range'))}
Fixed range: {format_range(proposal.get('fixed_range'))}

## Why This Snippet

{proposal.get('rationale', '')}

## Uncertainty

{proposal.get('uncertainty', '')}

## Reviewer Notes

{proposal.get('review_notes', '')}

## Diff

```diff
{diff}
```

## Reviewer Checklist

- [ ] CVE-to-patch linkage is credible
- [ ] Vulnerable snippet contains the risky logic
- [ ] Fixed snippet shows the remediation
- [ ] Snippet is minimal but understandable
- [ ] License/provenance are acceptable
"""


def format_range(value: Any) -> str:
    if isinstance(value, dict):
        return f"{value.get('start', '?')}-{value.get('end', '?')}"
    return ""


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path
