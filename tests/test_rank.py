from pathlib import Path
import unittest

from kev_collector.io import read_json
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


if __name__ == "__main__":
    unittest.main()
