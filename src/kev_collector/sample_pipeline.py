from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .findings import normalize_finding
from .git_source import GitBundleResult, prepare_git_source_bundle
from .io import read_json, read_jsonl, write_json
from .samples import NEGATIVE_STRATEGY, normalize_extension, normalize_sample_kind

COMMIT_RE = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)
SLUG_RE = re.compile(r"[^a-z0-9_.-]+")


@dataclass(frozen=True)
class ExistingWork:
    sample_keys: set[str]
    bundle_keys: set[str]
    snippet_keys: set[str]

    @property
    def all_keys(self) -> set[str]:
        return self.sample_keys | self.bundle_keys | self.snippet_keys

    def reason_for(self, sample_key: str) -> str:
        reasons = []
        if sample_key in self.sample_keys:
            reasons.append("sample")
        if sample_key in self.bundle_keys:
            reasons.append("bundle")
        if sample_key in self.snippet_keys:
            reasons.append("snippet")
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
    fetch_code: bool = True,
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
        bundle_result = write_patch_bundle(
            bundle_dir,
            candidate,
            root=root,
            force=force,
            fetch_code=fetch_code,
        )
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        if force or not prompt_path.exists():
            prompt_path.write_text(render_snippet_prompt(candidate, bundle_dir, bundle_result), encoding="utf-8")
        prepared.append(
            {
                "cve_id": candidate["cve_id"],
                "sample_id": candidate["sample_id"],
                "sample_key": candidate["sample_key"],
                "bundle_dir": str(bundle_dir),
                "prompt_path": str(prompt_path),
                "fetch_status": bundle_result.fetch_status,
            }
        )
    return prepared


def import_snippets(root: Path, snippet_paths: list[Path], force: bool = False) -> list[Path]:
    existing = scan_existing_work(root)
    imported: list[Path] = []
    for snippet_path in snippet_paths:
        snippet = read_json(resolve(root, snippet_path))
        validate_snippet_json(snippet)
        sample_key = str(snippet["sample_key"])
        if sample_key in existing.sample_keys and not force:
            raise ValueError(f"{snippet_path}: sample_key already imported: {sample_key}")

        cve_id = str(snippet["cve_id"])
        sample_id = str(snippet["sample_id"])
        language = str(snippet.get("language") or "txt")
        extension = normalize_extension(language)
        sample_dir = root / "samples" / cve_id / sample_id
        sample_dir.mkdir(parents=True, exist_ok=True)

        metadata = {
            "cve_id": cve_id,
            "sample_id": sample_id,
            "sample_key": sample_key,
            "source_finding_key": snippet["source_finding_key"],
            "status": "needs_review",
            "sample_kind": "positive",
            "language": language,
            "source_urls": snippet.get("source_urls", []),
            "repo_urls": snippet.get("repo_urls", []),
            "patch_refs": snippet.get("patch_refs", []),
            "affected_files": [snippet["file_path"]],
            "license": {
                "name": snippet.get("license", ""),
                "url": "",
                "notes": "",
            },
            "provenance": {
                "preferred_source": snippet.get("evidence_level", ""),
                "extraction_notes": snippet.get("rationale", ""),
            },
            "expected_responses": positive_expected_responses(snippet, extension),
        }
        write_json(sample_dir / "metadata.json", metadata)
        (sample_dir / f"vulnerable.{extension}").write_text(snippet["vulnerable_code"], encoding="utf-8")
        (sample_dir / f"fixed.{extension}").write_text(snippet["fixed_code"], encoding="utf-8")
        (sample_dir / "evidence.md").write_text(render_evidence(snippet), encoding="utf-8")
        (sample_dir / "review.md").write_text(render_review(snippet), encoding="utf-8")
        imported.append(sample_dir)
        existing.sample_keys.add(sample_key)
    return imported


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
                "sample_kind": normalize_sample_kind(metadata),
                "evidence_level": str(provenance.get("preferred_source") or metadata.get("evidence_level") or ""),
                "confidence": metadata.get("confidence", ""),
                "review_path": str(review_path),
                "missing_review": not review_path.exists(),
            }
        )
    return records


def generate_negative_samples(root: Path, source_status: str = "accepted", force: bool = False) -> list[Path]:
    if source_status != "accepted":
        raise ValueError("negative generation only supports source_status='accepted'")

    source_samples = list_negative_source_samples(root, source_status)
    existing_negative_keys = scan_existing_negative_derivations(root)
    generated: list[Path] = []
    for sample_dir, metadata in source_samples:
        derived_key = derived_negative_sample_key(metadata)
        if derived_key in existing_negative_keys and not force:
            continue

        negative_dir = write_negative_sample(root, sample_dir, metadata, force=force)
        generated.append(negative_dir)
        existing_negative_keys.add(derived_key)
    return generated


def list_negative_source_samples(root: Path, source_status: str = "accepted") -> list[tuple[Path, dict[str, Any]]]:
    samples_root = root / "samples"
    if not samples_root.exists():
        return []

    records: list[tuple[Path, dict[str, Any]]] = []
    for metadata_path in sorted(samples_root.glob("**/metadata.json")):
        metadata = read_json(metadata_path)
        if not isinstance(metadata, dict):
            continue
        if str(metadata.get("status") or "") != source_status:
            continue
        if normalize_sample_kind(metadata) != "positive":
            continue
        records.append((metadata_path.parent, metadata))
    return records


def scan_existing_negative_derivations(root: Path) -> set[str]:
    keys: set[str] = set()
    samples_root = root / "samples"
    if not samples_root.exists():
        return keys

    for metadata_path in samples_root.glob("**/metadata.json"):
        metadata = read_json(metadata_path)
        if not isinstance(metadata, dict):
            continue
        if normalize_sample_kind(metadata) != "negative":
            continue
        derived_key = str(metadata.get("derived_from_sample_key") or "").strip()
        strategy = str(metadata.get("negative_strategy") or "").strip()
        if derived_key and strategy:
            keys.add(f"{derived_key}|negative|{strategy}")
    return keys


def write_negative_sample(root: Path, source_dir: Path, metadata: dict[str, Any], force: bool = False) -> Path:
    cve_id = str(metadata.get("cve_id") or "")
    source_sample_id = str(metadata.get("sample_id") or "")
    source_sample_key = str(metadata.get("sample_key") or "")
    sample_id = derive_negative_sample_id(source_sample_id)
    sample_key = derived_negative_sample_key(metadata)
    language = str(metadata.get("language") or "txt")
    extension = normalize_extension(language)
    fixed_files = sorted(source_dir.glob("fixed.*"))
    if not fixed_files:
        raise ValueError(f"{source_dir}: missing fixed.* snippet for negative generation")
    fixed_path = fixed_files[0]
    if fixed_path.suffix:
        extension = fixed_path.suffix.lstrip(".")

    negative_dir = root / "samples" / cve_id / sample_id
    metadata_path = negative_dir / "metadata.json"
    if metadata_path.exists() and not force:
        raise ValueError(f"{metadata_path}: negative sample already exists; use --force to overwrite")

    negative_dir.mkdir(parents=True, exist_ok=True)
    negative_code = fixed_path.read_text(encoding="utf-8")
    negative_metadata = {
        "cve_id": cve_id,
        "sample_id": sample_id,
        "sample_key": sample_key,
        "source_finding_key": metadata.get("source_finding_key", ""),
        "status": "needs_review",
        "sample_kind": "negative",
        "language": language,
        "source_urls": metadata.get("source_urls", []),
        "repo_urls": metadata.get("repo_urls", []),
        "patch_refs": metadata.get("patch_refs", []),
        "affected_files": metadata.get("affected_files", []),
        "license": metadata.get("license", {"name": "", "url": "", "notes": ""}),
        "provenance": metadata.get("provenance", {"preferred_source": "", "extraction_notes": ""}),
        "confidence": metadata.get("confidence", ""),
        "derived_from_sample_id": source_sample_id,
        "derived_from_sample_key": source_sample_key,
        "negative_strategy": NEGATIVE_STRATEGY,
        "expected_responses": negative_expected_responses(metadata, extension),
    }
    write_json(metadata_path, negative_metadata)
    (negative_dir / f"negative.{extension}").write_text(negative_code, encoding="utf-8")
    (negative_dir / "evidence.md").write_text(render_negative_evidence(metadata, sample_id), encoding="utf-8")
    (negative_dir / "review.md").write_text(render_negative_review(metadata, sample_id, sample_key), encoding="utf-8")
    return negative_dir


def derive_negative_sample_id(sample_id: str) -> str:
    base = sample_id[:87].rstrip("-")
    return f"{base}-negative"


def derived_negative_sample_key(metadata: dict[str, Any]) -> str:
    return f"{metadata.get('sample_key', '')}|negative|{NEGATIVE_STRATEGY}"


def write_patch_bundle(
    bundle_dir: Path,
    candidate: dict[str, Any],
    root: Path,
    force: bool = False,
    fetch_code: bool = True,
) -> GitBundleResult:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = bundle_dir / "metadata.json"
    if metadata_path.exists() and not force:
        metadata = read_json(metadata_path)
        return bundle_result_from_metadata(metadata, bundle_dir)
    (bundle_dir / "patch.diff").write_text("", encoding="utf-8")
    (bundle_dir / "candidate_hunks.jsonl").write_text("", encoding="utf-8")
    (bundle_dir / "vulnerable").mkdir(exist_ok=True)
    (bundle_dir / "fixed").mkdir(exist_ok=True)

    if fetch_code:
        bundle_result = prepare_git_source_bundle(
            candidate,
            bundle_dir,
            root / ".cache" / "repos",
            repo_slug_from_url(candidate["repo_url"]),
        )
    else:
        bundle_result = empty_bundle_result(bundle_dir, "skipped")

    write_json(metadata_path, patch_bundle_metadata(candidate, bundle_result))
    write_json(bundle_dir / "finding.json", candidate["finding"])
    return bundle_result


def patch_bundle_metadata(candidate: dict[str, Any], bundle_result: GitBundleResult) -> dict[str, Any]:
    metadata = {
        "cve_id": candidate["cve_id"],
        "sample_id": candidate["sample_id"],
        "sample_key": candidate["sample_key"],
        "source_finding_key": candidate["source_finding_key"],
        "repo_url": candidate["repo_url"],
        "patch_ref": candidate["patch_ref"],
        "file_path": candidate["file_path"],
        "status": "prepared",
    }
    metadata.update(bundle_result.metadata())
    return metadata


def empty_bundle_result(bundle_dir: Path, status: str, errors: list[str] | None = None) -> GitBundleResult:
    return GitBundleResult(
        fetch_status=status,
        git_commit="",
        git_parent="",
        vulnerable_path="",
        fixed_path="",
        patch_path=str(bundle_dir / "patch.diff"),
        candidate_hunks_path=str(bundle_dir / "candidate_hunks.jsonl"),
        fetch_errors=errors or [],
    )


def bundle_result_from_metadata(metadata: dict[str, Any], bundle_dir: Path) -> GitBundleResult:
    return GitBundleResult(
        fetch_status=str(metadata.get("fetch_status") or "skipped"),
        git_commit=str(metadata.get("git_commit") or ""),
        git_parent=str(metadata.get("git_parent") or ""),
        vulnerable_path=str(metadata.get("vulnerable_path") or ""),
        fixed_path=str(metadata.get("fixed_path") or ""),
        patch_path=str(metadata.get("patch_path") or bundle_dir / "patch.diff"),
        candidate_hunks_path=str(metadata.get("candidate_hunks_path") or bundle_dir / "candidate_hunks.jsonl"),
        fetch_errors=[str(error) for error in metadata.get("fetch_errors", [])],
    )


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
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return value.rstrip("/").lower()
    return value.rstrip("/")


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
        snippet_keys=scan_snippet_keys(root / "agent-output" / "snippets"),
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


def scan_snippet_keys(root: Path) -> set[str]:
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


def render_snippet_prompt(
    candidate: dict[str, Any],
    bundle_dir: Path,
    bundle_result: GitBundleResult | None = None,
) -> str:
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
        "rationale": "Why this is the smallest snippet that still contains enough context to identify the bug.",
        "vulnerability_type": "Concrete bug class visible in the snippet, such as stored XSS, path traversal, auth bypass, or buffer overflow.",
        "vulnerable_behavior": "What a correct judge should identify as vulnerable in the vulnerable snippet.",
        "fixed_behavior": "What a correct judge should identify as remediated or safe in the fixed snippet.",
        "code_evidence": "The specific source, guard, sink, parser, permission check, bounds check, lifetime handling, or equivalent code evidence.",
        "uncertainty": "Any ambiguity, missing context, or review concern.",
        "review_notes": "Notes for human reviewer.",
    }
    finding_json = json.dumps(candidate["finding"], indent=2, sort_keys=True)
    schema_json = json.dumps(schema, indent=2, sort_keys=True)
    bundle_result = bundle_result or empty_bundle_result(bundle_dir, "skipped")
    bundle_json = json.dumps(bundle_result.metadata(), indent=2, sort_keys=True)
    return f"""# Snippet Selection Task

You are a snippet-selection worker for the KEV code sample collector.

Use the prepared patch bundle at `{bundle_dir}`. Choose vulnerable/fixed code snippets that are as small as possible while still containing enough local code to identify the vulnerability and the fix.

Return JSON only. Do not write files.

## Prepared Source Context

```json
{bundle_json}
```

Use `vulnerable_path`, `fixed_path`, `patch_path`, and `candidate_hunks_path` when `fetch_status` is `fetched`. If `fetch_status` is `partial` or `skipped`, use `fetch_errors`, source URLs, and patch refs to decide whether you can still return useful snippet JSON with clear uncertainty.

## Required Snippet JSON Shape

```json
{schema_json}
```

## Selection Rules

- Prefer the file path already identified by the finding when it contains the vulnerable logic.
- Include enough surrounding context for a reviewer to identify the bug from the snippet itself: the risky source or state, the guard/validation/permission/lifetime check, the sink or security-sensitive operation, and the fixed behavior.
- If the changed hunk alone does not make the bug identifiable, expand to the smallest enclosing function, helper pair, call path, or adjacent type/constant definitions needed to make the vulnerability clear.
- Prefer a larger coherent snippet over a tiny diff that requires hidden framework, kernel, or product context to determine whether the code is vulnerable.
- If the vulnerability still cannot be determined from code in the prepared bundle, say so in `uncertainty` and `review_notes` instead of overclaiming.
- Do not include unrelated refactors, test-only changes, or broad whole-file excerpts unless unavoidable.
- Use the prepared vulnerable/fixed files as the source of truth when available.
- Fill `vulnerability_type`, `vulnerable_behavior`, `fixed_behavior`, and `code_evidence` with concise expected-answer data for downstream benchmark judging.

## Finding

```json
{finding_json}
```
"""


def validate_snippet_json(snippet: dict[str, Any]) -> None:
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
    missing = sorted(field for field in required if not snippet.get(field))
    if missing:
        raise ValueError(f"snippet JSON missing fields: {', '.join(missing)}")


def positive_expected_responses(snippet: dict[str, Any], extension: str) -> dict[str, Any]:
    vulnerability_type = str(snippet.get("vulnerability_type") or "").strip()
    code_evidence = str(snippet.get("code_evidence") or snippet.get("rationale") or "").strip()
    vulnerable_behavior = str(snippet.get("vulnerable_behavior") or code_evidence).strip()
    fixed_behavior = str(snippet.get("fixed_behavior") or snippet.get("rationale") or "").strip()
    return {
        "vulnerable": {
            "file": f"vulnerable.{extension}",
            "is_vulnerable": True,
            "label": "vulnerable",
            "vulnerability_type": vulnerability_type,
            "expected_behavior": vulnerable_behavior,
            "code_evidence": code_evidence,
        },
        "fixed": {
            "file": f"fixed.{extension}",
            "is_vulnerable": False,
            "label": "fixed",
            "vulnerability_type": vulnerability_type,
            "expected_behavior": fixed_behavior,
            "code_evidence": fixed_behavior,
        },
    }


def negative_expected_responses(metadata: dict[str, Any], extension: str) -> dict[str, Any]:
    source_expected = metadata.get("expected_responses") if isinstance(metadata.get("expected_responses"), dict) else {}
    source_vulnerable = source_expected.get("vulnerable") if isinstance(source_expected.get("vulnerable"), dict) else {}
    source_fixed = source_expected.get("fixed") if isinstance(source_expected.get("fixed"), dict) else {}
    vulnerability_type = str(source_vulnerable.get("vulnerability_type") or source_fixed.get("vulnerability_type") or "").strip()
    expected_behavior = str(source_fixed.get("expected_behavior") or source_fixed.get("code_evidence") or "").strip()
    return {
        "negative": {
            "file": f"negative.{extension}",
            "is_vulnerable": False,
            "label": "non_vulnerable",
            "vulnerability_type": vulnerability_type,
            "expected_behavior": expected_behavior,
            "code_evidence": expected_behavior,
            "derived_from": str(metadata.get("sample_id") or ""),
            "negative_strategy": NEGATIVE_STRATEGY,
        },
    }


def render_evidence(snippet: dict[str, Any]) -> str:
    source_urls = "\n".join(f"- {url}" for url in snippet.get("source_urls", [])) or "- TODO"
    patch_refs = "\n".join(f"- {ref}" for ref in snippet.get("patch_refs", [])) or "- TODO"
    return f"""# Evidence for {snippet['cve_id']} / {snippet['sample_id']}

## Source Links

{source_urls}

## Patch References

{patch_refs}

## Rationale

{snippet.get('rationale', '')}
"""


def render_review(snippet: dict[str, Any]) -> str:
    diff = snippet.get("diff", "")
    if not diff:
        diff = "(No focused diff supplied by snippet JSON.)"
    return f"""# {snippet['cve_id']} / {snippet['sample_id']}

Sample key: `{snippet['sample_key']}`
Source finding: `{snippet['source_finding_key']}`
Status: needs_review
Evidence level: {snippet.get('evidence_level', '')}
Confidence: {snippet.get('confidence', '')}
License: {snippet.get('license', '')}

## Source

- Repo: {', '.join(snippet.get('repo_urls', []))}
- Source URLs: {', '.join(snippet.get('source_urls', []))}
- Patch refs: {', '.join(snippet.get('patch_refs', []))}

## Selected Snippet

File: `{snippet['file_path']}`
Vulnerable range: {format_range(snippet.get('vulnerable_range'))}
Fixed range: {format_range(snippet.get('fixed_range'))}

## Why This Snippet

{snippet.get('rationale', '')}

## Uncertainty

{snippet.get('uncertainty', '')}

## Reviewer Notes

{snippet.get('review_notes', '')}

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


def render_negative_evidence(metadata: dict[str, Any], sample_id: str) -> str:
    source_urls = "\n".join(f"- {url}" for url in metadata.get("source_urls", [])) or "- TODO"
    patch_refs = "\n".join(f"- {ref}" for ref in metadata.get("patch_refs", [])) or "- TODO"
    return f"""# Evidence for {metadata.get('cve_id', '')} / {sample_id}

## Source Links

{source_urls}

## Patch References

{patch_refs}

## Rationale

Derived benchmark negative from the accepted fixed snippet of `{metadata.get('sample_id', '')}` using `{NEGATIVE_STRATEGY}`. This artifact is intended to preserve code style and local context while remaining non-vulnerable.
"""


def render_negative_review(metadata: dict[str, Any], sample_id: str, sample_key: str) -> str:
    return f"""# {metadata.get('cve_id', '')} / {sample_id}

Sample key: `{sample_key}`
Derived from sample: `{metadata.get('sample_id', '')}`
Derived from key: `{metadata.get('sample_key', '')}`
Status: needs_review
Sample kind: negative
Strategy: {NEGATIVE_STRATEGY}
Evidence level: {metadata.get('provenance', {}).get('preferred_source', '') if isinstance(metadata.get('provenance'), dict) else ''}
Confidence: {metadata.get('confidence', '')}
License: {metadata.get('license', {}).get('name', '') if isinstance(metadata.get('license'), dict) else ''}

## Source

- Repo: {', '.join(metadata.get('repo_urls', []))}
- Source URLs: {', '.join(metadata.get('source_urls', []))}
- Patch refs: {', '.join(metadata.get('patch_refs', []))}

## Negative Snippet

File: `negative.{normalize_extension(str(metadata.get('language') or 'txt'))}`

## Why This Snippet

This sample is derived from the accepted fixed snippet so it stays structurally similar to a real KEV example while representing a non-vulnerable response.

## Reviewer Notes

Confirm the snippet is still understandable in isolation, remains non-vulnerable, and is distinct enough to serve as a negative benchmark example.

## Reviewer Checklist

- [ ] Source positive sample is accepted and credible
- [ ] Negative snippet is non-vulnerable
- [ ] Negative remains structurally similar to the accepted sample
- [ ] Derivation metadata is complete
- [ ] License/provenance are acceptable
"""


def format_range(value: Any) -> str:
    if isinstance(value, dict):
        return f"{value.get('start', '?')}-{value.get('end', '?')}"
    return ""


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path
