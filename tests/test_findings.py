import unittest

from kev_collector.findings import merge_findings, normalize_finding


class FindingTests(unittest.TestCase):
    def test_merge_findings_deduplicates_by_cve_sources_and_patch_refs(self) -> None:
        incoming = [
            {
                "cve_id": "CVE-2020-11023",
                "source_urls": ["https://example.test/advisory"],
                "repo_urls": ["https://github.com/jquery/jquery"],
                "patch_refs": ["abc123"],
                "evidence_level": "official_advisory",
                "confidence": 0.8,
                "notes": "first",
            },
            {
                "cve_id": "CVE-2020-11023",
                "source_urls": ["https://example.test/advisory"],
                "repo_urls": ["https://github.com/jquery/jquery"],
                "patch_refs": ["abc123"],
                "evidence_level": "official_patch",
                "confidence": 0.9,
                "notes": "replacement",
            },
        ]

        merged = merge_findings([], incoming)

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["evidence_level"], "official_patch")
        self.assertEqual(merged[0]["confidence"], 0.9)
        self.assertEqual(merged[0]["notes"], "replacement")

    def test_normalize_finding_requires_valid_evidence_level(self) -> None:
        with self.assertRaisesRegex(ValueError, "evidence_level"):
            normalize_finding(
                {
                    "cve_id": "CVE-2020-11023",
                    "source_urls": ["https://example.test/advisory"],
                    "confidence": 0.5,
                    "notes": "missing evidence level",
                }
            )

        with self.assertRaisesRegex(ValueError, "invalid evidence_level"):
            normalize_finding(
                {
                    "cve_id": "CVE-2020-11023",
                    "source_urls": ["https://example.test/advisory"],
                    "evidence_level": "pretty_sure",
                    "confidence": 0.5,
                    "notes": "invalid evidence level",
                }
            )


if __name__ == "__main__":
    unittest.main()
