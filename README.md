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

These commands compute a stable `sample_key` and skip candidates already present in `samples/`, `work/`, or `proposals/`. Snippet workers should return proposal JSON only; the collector materializes review-ready samples from proposals:

```sh
bin/kev-collector samples materialize proposals/CVE-YYYY-NNNN/sample.json
```
