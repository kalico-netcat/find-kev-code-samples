# KEV Code Sample Collector

Small Python CLI for turning CISA KEV entries into a triage queue for real-world vulnerable code samples.

## Quick Start

```sh
bin/kev-collector fetch
bin/kev-collector rank
bin/kev-collector batch --size 20
bin/kev-collector validate
```

All generated artifacts are local files under `data/`, `batches/`, and `samples/`.

## Multi-Agent Workflow

Use one orchestrator and many batch workers. The orchestrator owns repo state; each worker gets exactly one `batches/batch-NNNN.jsonl` file and returns findings JSONL only.

## How To Ask The Agent

Use a short natural request. The agent should discover the workflow from `AGENTS.md` and follow [docs/full-run-orchestrator.md](docs/full-run-orchestrator.md).

```text
Run a KEV collection pass with 3 research batches, batch size 10, and 5 sample candidates. Stop before accepting samples.
```

If you omit parameters, the default run is 3 research batches, batch size 10, 5 sample candidates, `official_patch` evidence, and minimum confidence 0.85.

## Manual Research Flow

```sh
bin/kev-collector fetch
bin/kev-collector rank
bin/kev-collector batch --size 20
bin/kev-collector prompt-batch batches/batch-0001.jsonl --output prompts/batch-0001.md
```

Assign each generated prompt to one worker agent. Save returned findings under `findings/` with matching names:

```text
batches/batch-0001.jsonl -> prompts/batch-0001.md -> findings/batch-0001.jsonl
```

Then ingest and validate:

```sh
bin/kev-collector ingest findings/batch-0001.jsonl
bin/kev-collector validate
```

Use `--size 10` for difficult/manual research batches and `--size 20` for normal KEV triage.

Worker findings must include an `evidence_level` value. Allowed levels are `official_patch`, `official_advisory`, `upstream_release`, `third_party_analysis`, `weak_lead`, and `no_public_code`.

Use `evidence_level` for the kind of evidence and `confidence` for CVE-to-code linkage certainty. These are independent: an official patch can still have low confidence if the worker cannot clearly prove it is the patch for that CVE.

## Sample Pulling

After findings are ingested, list and prepare high-confidence sample candidates:

```sh
bin/kev-collector samples candidates --limit 5 --level official_patch --min-confidence 0.85
bin/kev-collector samples prepare --limit 5 --level official_patch --min-confidence 0.85
```

These commands compute a stable `sample_key` and skip candidates already present in `samples/`, `work/`, or `agent-output/snippets/`.

`samples prepare` fetches git commit source context when possible. For commit-based findings, it writes the vulnerable file from the patch commit's first parent, the fixed file from the patch commit, a focused diff, and hunk metadata under `work/`. If fetching fails, it keeps a partial bundle with fetch errors so the rest of the batch can continue. Use `--no-fetch-code` for offline prompt-only bundle generation.

The snippet-worker prompts are written under `prompts/snippets/`. Give each snippet prompt to one worker agent. The worker should return direct snippet JSON with `vulnerable_code` and `fixed_code`; save that output under:

```text
agent-output/snippets/<CVE>/<sample_id>.json
```

Then import snippet JSON into review-ready sample folders:

```sh
bin/kev-collector samples import agent-output/snippets/CVE-YYYY-NNNN/sample.json
```

## Human Review

Human review happens after `samples import`, when `samples/<CVE>/<sample_id>/review.md`, `vulnerable.*`, and `fixed.*` exist. List review cards with:

```sh
bin/kev-collector samples review-list
```

Useful variants:

```sh
bin/kev-collector samples review-list --status all
bin/kev-collector samples review-list --status accepted
bin/kev-collector samples review-list --status rejected
bin/kev-collector samples review-list --status needs_more_evidence
bin/kev-collector samples review-list --jsonl
```

The command defaults to `status: needs_review` and prints each sample's `review.md` path. It may print nothing until `samples import` has created sample folders.
