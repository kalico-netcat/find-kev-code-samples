import unittest

from kev_collector.findings import merge_findings


class FindingTests(unittest.TestCase):
    def test_merge_findings_deduplicates_by_cve_sources_and_patch_refs(self) -> None:
        incoming = [
            {
                "cve_id": "CVE-2020-11023",
                "source_urls": ["https://example.test/advisory"],
                "repo_urls": ["https://github.com/jquery/jquery"],
                "patch_refs": ["abc123"],
                "confidence": 0.8,
                "notes": "first",
            },
            {
                "cve_id": "CVE-2020-11023",
                "source_urls": ["https://example.test/advisory"],
                "repo_urls": ["https://github.com/jquery/jquery"],
                "patch_refs": ["abc123"],
                "confidence": 0.9,
                "notes": "replacement",
            },
        ]

        merged = merge_findings([], incoming)

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["confidence"], 0.9)
        self.assertEqual(merged[0]["notes"], "replacement")


if __name__ == "__main__":
    unittest.main()
