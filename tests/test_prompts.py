from pathlib import Path
import contextlib
import io
import tempfile
import unittest

from kev_collector.io import read_jsonl
from kev_collector.prompts import render_batch_prompt
from kev_collector.cli import main


class PromptTests(unittest.TestCase):
    def test_render_batch_prompt_includes_schema_and_boundaries(self) -> None:
        batch_path = Path("tests/fixtures/batch.jsonl")
        prompt = render_batch_prompt(batch_path, read_jsonl(batch_path))

        self.assertIn("You are a worker research agent", prompt)
        self.assertIn("The orchestrator owns repo state", prompt)
        self.assertIn('"cve_id":"CVE-YYYY-NNNN"', prompt)
        self.assertIn('"evidence_level":"official_patch"', prompt)
        self.assertIn("official_advisory", prompt)
        self.assertIn("no_public_code", prompt)
        self.assertIn("These fields are independent", prompt)
        self.assertIn("official_patch` with low confidence", prompt)
        self.assertIn("CVE-2020-11023", prompt)
        self.assertIn("findings/batch.jsonl", prompt)

    def test_prompt_batch_writes_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "batch.md"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["prompt-batch", "tests/fixtures/batch.jsonl", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            self.assertTrue(output.exists())
            self.assertIn("Required Output", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
