# Full Run Orchestrator Runbook

Use this runbook when the user asks for an end-to-end KEV collection pass, sample collection pass, full agentic pass, or samples prepared for review.

The human provides intent and optional parameters. The orchestrator reads this runbook, runs the tools, spawns workers as needed, and stops before accepting samples.

## Defaults

- Research batches: `3`
- Batch size: `10`
- Sample candidates: `5`
- Evidence level: `official_patch`
- Minimum confidence: `0.85`
- Stop condition: materialized samples with `status: needs_review`

## Current Implemented Flow

The current CLI supports the research half of the flow:

```sh
bin/kev-collector fetch
bin/kev-collector rank
bin/kev-collector batch --size 10
bin/kev-collector prompt-batch batches/batch-0001.jsonl --output prompts/batch-0001.md
bin/kev-collector prompt-batch batches/batch-0002.jsonl --output prompts/batch-0002.md
bin/kev-collector prompt-batch batches/batch-0003.jsonl --output prompts/batch-0003.md
```

Spawn one research worker per generated batch prompt. Save each worker result under `findings/` with the matching batch name:

```text
prompts/batch-0001.md -> findings/batch-0001.jsonl
prompts/batch-0002.md -> findings/batch-0002.jsonl
prompts/batch-0003.md -> findings/batch-0003.jsonl
```

Then ingest and validate:

```sh
bin/kev-collector ingest findings/batch-0001.jsonl
bin/kev-collector ingest findings/batch-0002.jsonl
bin/kev-collector ingest findings/batch-0003.jsonl
bin/kev-collector validate
```

Summarize findings by `evidence_level` and call out batches or CVEs that need another pass.

## Planned Sample Pulling Flow

When sample-pulling commands are implemented, continue from ingested findings:

```sh
bin/kev-collector samples prepare --limit 5 --level official_patch --min-confidence 0.85
```

The command should prepare patch bundles under `work/` and snippet prompts under `prompts/`. Spawn one snippet worker per prompt. Workers return snippet proposals only, not canonical sample files.

Save proposals under:

```text
proposals/<CVE>/<sample_id>.json
```

Then materialize review-ready samples:

```sh
bin/kev-collector samples materialize proposals/**/*.json
bin/kev-collector validate
```

Final samples should remain `status: needs_review`.

## Worker Boundaries

Research workers:

- receive exactly one `prompts/batch-NNNN.md`
- research every CVE in that batch
- return findings JSONL only
- do not edit `data/findings.jsonl`
- do not create samples

Snippet workers:

- receive exactly one snippet prompt or patch bundle
- choose minimal vulnerable/fixed snippet ranges
- return a JSON proposal only
- do not write canonical `samples/` files
- include rationale and uncertainty for human review

## Output Locations

```text
data/kev.jsonl              normalized KEV feed
data/candidates.jsonl       ranked CVE candidates
batches/batch-NNNN.jsonl    research batches
prompts/batch-NNNN.md       research worker prompts
findings/batch-NNNN.jsonl   worker findings
data/findings.jsonl         canonical merged findings
work/<CVE>/<sample_id>/     patch bundles, temporary
proposals/<CVE>/*.json      snippet worker proposals
samples/<CVE>/<sample_id>/  review-ready sample artifacts
```

## Stop Condition

Never mark samples `accepted` during the agentic flow. Stop after samples are materialized with `status: needs_review`, then report the `samples/**/review.md` files for human review.
