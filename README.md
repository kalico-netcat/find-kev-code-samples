# KEV Code Sample Collector

Small Python CLI for turning CISA KEV entries into a triage queue for real-world vulnerable code samples.

## Quick Start

```sh
PYTHONPATH=src python3 -m kev_collector.cli fetch
PYTHONPATH=src python3 -m kev_collector.cli rank
PYTHONPATH=src python3 -m kev_collector.cli batch
PYTHONPATH=src python3 -m kev_collector.cli validate
```

All generated artifacts are local files under `data/`, `batches/`, and `samples/`.
