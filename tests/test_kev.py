from pathlib import Path
import unittest

from kev_collector.io import read_json
from kev_collector.kev import normalize_kev_feed


class KevTests(unittest.TestCase):
    def test_normalize_kev_feed(self) -> None:
        feed = read_json(Path("tests/fixtures/kev.json"))

        records = normalize_kev_feed(feed)

        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["cve_id"], "CVE-2020-11023")
        self.assertEqual(records[0]["cwes"], ["CWE-79"])
        self.assertEqual(records[0]["source"]["catalog"], "CISA KEV")


if __name__ == "__main__":
    unittest.main()
