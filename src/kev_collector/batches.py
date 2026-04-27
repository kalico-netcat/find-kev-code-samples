from __future__ import annotations

from pathlib import Path

from .io import write_jsonl


def write_batches(records: list[dict], output_dir: Path, batch_size: int = 20, prefix: str = "batch") -> list[Path]:
    if batch_size < 1:
        raise ValueError("batch size must be at least 1")
    output_dir.mkdir(parents=True, exist_ok=True)

    paths: list[Path] = []
    for index in range(0, len(records), batch_size):
        batch_number = len(paths) + 1
        path = output_dir / f"{prefix}-{batch_number:04d}.jsonl"
        write_jsonl(path, records[index : index + batch_size])
        paths.append(path)
    return paths
