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
