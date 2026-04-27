from pathlib import Path
import tempfile
import unittest

from kev_collector.batches import write_batches
from kev_collector.io import read_jsonl


class BatchTests(unittest.TestCase):
    def test_write_batches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            records = [{"cve_id": f"CVE-2024-{index:04d}", "score": 10} for index in range(5)]

            paths = write_batches(records, tmp_path / "batches", batch_size=2)

            self.assertEqual(
                [path.name for path in paths],
                ["batch-0001.jsonl", "batch-0002.jsonl", "batch-0003.jsonl"],
            )
            self.assertEqual(len(read_jsonl(paths[0])), 2)
            self.assertEqual(len(read_jsonl(paths[2])), 1)


if __name__ == "__main__":
    unittest.main()
