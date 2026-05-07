from pathlib import Path
import contextlib
import io
import tempfile
import unittest

from kev_collector.cli import main
from kev_collector.io import read_json
from kev_collector.io import read_jsonl
from kev_collector.io import write_jsonl
from kev_collector.kev import normalize_kev_feed
from kev_collector.rank import rank_records


class RankTests(unittest.TestCase):
    def test_rank_records_prioritizes_open_source_candidates(self) -> None:
        records = normalize_kev_feed(read_json(Path("tests/fixtures/kev.json")))

        ranked = rank_records(records)

        self.assertIn(ranked[0]["cve_id"], {"CVE-2020-11023", "CVE-2025-48384"})
        self.assertGreater(ranked[0]["score"], 0)
        self.assertEqual(ranked[0]["research_status"], "needs_research")
        self.assertTrue(ranked[0]["score_reasons"])

    def test_rank_records_excludes_known_famous_by_default(self) -> None:
        records = normalize_kev_feed(read_json(Path("tests/fixtures/kev.json")))

        ranked = rank_records(records)

        self.assertNotIn("CVE-2021-44228", {record["cve_id"] for record in ranked})

    def test_rank_records_can_include_and_annotate_known_famous(self) -> None:
        records = normalize_kev_feed(read_json(Path("tests/fixtures/kev.json")))

        ranked = rank_records(records, include_famous=True)
        famous = next(record for record in ranked if record["cve_id"] == "CVE-2021-44228")

        self.assertTrue(famous["famous_sample"])
        self.assertEqual(famous["famous_reason"], "Log4Shell")
        self.assertEqual(famous["research_status"], "needs_research")

    def test_rank_cli_excludes_known_famous_by_default(self) -> None:
        records = normalize_kev_feed(read_json(Path("tests/fixtures/kev.json")))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_jsonl(root / "data/kev.jsonl", records)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["--root", str(root), "rank"])

            self.assertEqual(exit_code, 0)
            candidates = read_jsonl(root / "data/candidates.jsonl")
            self.assertNotIn("CVE-2021-44228", {record["cve_id"] for record in candidates})

    def test_rank_cli_can_include_known_famous(self) -> None:
        records = normalize_kev_feed(read_json(Path("tests/fixtures/kev.json")))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_jsonl(root / "data/kev.jsonl", records)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["--root", str(root), "rank", "--include-famous"])

            self.assertEqual(exit_code, 0)
            candidates = read_jsonl(root / "data/candidates.jsonl")
            famous = next(record for record in candidates if record["cve_id"] == "CVE-2021-44228")
            self.assertTrue(famous["famous_sample"])
            self.assertEqual(famous["famous_reason"], "Log4Shell")


if __name__ == "__main__":
    unittest.main()
