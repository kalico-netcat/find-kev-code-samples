# Agent Workflow

This repo collects research evidence for real-world vulnerable code samples tied to CISA KEV CVEs. The collector is the source of truth for generated files; agents provide bounded research findings.

## Full Collection Flow

When the user asks to "run a KEV collection pass", "collect samples", "do a full agentic pass", or "prepare samples for review", act as the orchestrator and follow `docs/full-run-orchestrator.md`.

The user should only need to provide intent and optional run parameters:

- research batch count
- batch size
- sample candidate limit
- evidence level
- minimum confidence

If the user omits parameters, use the defaults in `docs/full-run-orchestrator.md`. Do not require the user to mention `AGENTS.md` or the runbook by name.

## Roles

### Orchestrator

The orchestrator owns repo state. It runs `fetch`, `rank`, `batch`, assigns one batch file per worker, ingests returned findings, and runs validation. The orchestrator is the only role that should modify canonical `data/findings.jsonl`.

### Worker Agent

A worker receives exactly one `batches/batch-NNNN.jsonl` file or generated prompt. It researches every CVE in that batch and returns JSONL findings only. A worker should not edit `data/findings.jsonl`, create accepted samples, or modify unrelated project files.

### Reviewer Or Auditor

A reviewer may inspect findings or samples after worker output is ingested. This role is optional and should be used for verification, not primary collection.

## Parallel Research Model

Use batch-level parallelism. Assign each worker exactly one batch file:

- input: `batches/batch-0001.jsonl`
- output: `findings/batch-0001.jsonl`

Do not use one agent per CVE by default. Do not have multiple workers research the same batch unless the task is explicit review or verification.

Use `--size 10` for difficult/manual research batches, `--size 20` for normal KEV triage, and larger batches only for quick low-depth sweeps.

## Evidence Priority

Prefer evidence in this order:

1. Official project repository commits, tags, release notes, or advisories.
2. Official vendor advisories that identify affected versions or patches.
3. GitHub Security Advisories, NVD references, package advisories, and ecosystem databases.
4. Public web sources such as blogs, exploit databases, mirrors, or PoCs when official sources are insufficient.

Clearly distinguish confirmed patch refs from speculative links. Do not claim a CVE-to-commit relationship unless the evidence supports it.

## Worker Output

Workers return newline-delimited JSON only. Each record should use this shape:

```json
{"cve_id":"CVE-YYYY-NNNN","source_urls":["https://..."],"repo_urls":["https://..."],"patch_refs":["commit/tag/release/advisory ref"],"affected_files":["path/or/component"],"license":"MIT/Apache-2.0/GPL/unknown/etc","evidence_level":"official_patch","confidence":0.0,"notes":"Short evidence summary and uncertainty."}
```

Required fields are `cve_id`, `source_urls`, `evidence_level`, `confidence`, and `notes`.

Allowed `evidence_level` values:

- `official_patch`: official project repository commit, patch, pull request, or comparable source ref explicitly tied to the CVE.
- `official_advisory`: official vendor/project advisory identifies affected versions or remediation, but no exact source patch is confirmed.
- `upstream_release`: upstream release notes, changelog, tag, or version diff strongly indicate the fix.
- `third_party_analysis`: credible public analysis, advisory database, blog, exploit writeup, or mirror provides useful source leads.
- `weak_lead`: possible repo, file, patch, or source trail exists, but CVE-to-code linkage is incomplete or speculative.
- `no_public_code`: research found no usable public source trail, or the product appears closed source.

Use both fields:

- `evidence_level` describes the kind of source evidence found.
- `confidence` describes how sure the worker is that the evidence is correctly linked to this CVE and useful for later source/sample extraction.

These fields are independent. For example, an `official_patch` can still have low confidence if the patch is official but the CVE-to-commit linkage is inferred from a release window, internal bug ID, or ambiguous advisory.

After workers finish, the orchestrator ingests findings:

```sh
bin/kev-collector ingest findings/batch-0001.jsonl
bin/kev-collector validate
```
