from pathlib import Path
import tempfile
import unittest

from kev_collector.io import write_json, write_jsonl
from kev_collector.sample_pipeline import (
    build_sample_candidate,
    list_sample_candidates,
    materialize_proposals,
    prepare_sample_candidates,
)


def fixture_finding(cve_id: str = "CVE-2020-11023") -> dict:
    return {
        "cve_id": cve_id,
        "source_urls": [
            "https://github.com/jquery/jquery/security/advisories/GHSA-jpcq-cgw6-v4j6",
            "https://github.com/jquery/jquery/commit/1d61fd9407e6fbe82fe55cb0b938307aa0791f77",
        ],
        "repo_urls": ["https://github.com/jquery/jquery"],
        "patch_refs": ["commit 1d61fd9407e6fbe82fe55cb0b938307aa0791f77"],
        "affected_files": ["src/manipulation.js"],
        "license": "MIT",
        "evidence_level": "official_patch",
        "confidence": 0.94,
        "notes": "Fixture finding.",
    }


class SamplePipelineTests(unittest.TestCase):
    def test_candidates_skip_existing_materialized_sample(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = fixture_finding()
            candidate = build_sample_candidate(finding)
            write_jsonl(root / "data/findings.jsonl", [finding])
            write_json(
                root / "samples/CVE-2020-11023/existing/metadata.json",
                {
                    "cve_id": "CVE-2020-11023",
                    "sample_id": "existing",
                    "sample_key": candidate["sample_key"],
                    "status": "needs_review",
                },
            )

            candidates = list_sample_candidates(root)

            self.assertEqual(candidates, [])
            skipped = list_sample_candidates(root, include_skipped=True)
            self.assertEqual(skipped[0]["skip_reason"], "already_exists:sample")

    def test_prepare_skips_existing_bundle_before_rebuilding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = fixture_finding()
            candidate = build_sample_candidate(finding)
            write_jsonl(root / "data/findings.jsonl", [finding])
            write_json(
                root / "work/CVE-2020-11023/existing/metadata.json",
                {
                    "cve_id": "CVE-2020-11023",
                    "sample_id": "existing",
                    "sample_key": candidate["sample_key"],
                    "status": "prepared",
                },
            )

            prepared = prepare_sample_candidates(root)

            self.assertEqual(prepared, [])

    def test_prepare_creates_bundle_and_prompt_for_new_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_jsonl(root / "data/findings.jsonl", [fixture_finding()])

            prepared = prepare_sample_candidates(root)

            self.assertEqual(len(prepared), 1)
            bundle_dir = Path(prepared[0]["bundle_dir"])
            prompt_path = Path(prepared[0]["prompt_path"])
            self.assertTrue((bundle_dir / "metadata.json").exists())
            self.assertTrue((bundle_dir / "finding.json").exists())
            self.assertTrue(prompt_path.exists())

    def test_materialize_refuses_duplicate_sample_key_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = fixture_finding()
            candidate = build_sample_candidate(finding)
            proposal = proposal_for(candidate)
            write_json(root / "proposals/CVE-2020-11023/sample.json", proposal)
            write_json(
                root / "samples/CVE-2020-11023/existing/metadata.json",
                {
                    "cve_id": "CVE-2020-11023",
                    "sample_id": "existing",
                    "sample_key": candidate["sample_key"],
                    "status": "needs_review",
                },
            )

            with self.assertRaisesRegex(ValueError, "already materialized"):
                materialize_proposals(root, [Path("proposals/CVE-2020-11023/sample.json")])

    def test_materialize_writes_review_ready_sample(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = build_sample_candidate(fixture_finding())
            proposal_path = root / "proposals/CVE-2020-11023/sample.json"
            write_json(proposal_path, proposal_for(candidate))

            paths = materialize_proposals(root, [proposal_path])

            sample_dir = paths[0]
            self.assertTrue((sample_dir / "metadata.json").exists())
            self.assertTrue((sample_dir / "review.md").exists())
            self.assertTrue((sample_dir / "vulnerable.js").exists())
            self.assertTrue((sample_dir / "fixed.js").exists())
            review = (sample_dir / "review.md").read_text(encoding="utf-8")
            self.assertIn("Sample key:", review)
            self.assertIn("Reviewer Checklist", review)


def proposal_for(candidate: dict) -> dict:
    finding = candidate["finding"]
    return {
        "cve_id": candidate["cve_id"],
        "sample_id": candidate["sample_id"],
        "sample_key": candidate["sample_key"],
        "source_finding_key": candidate["source_finding_key"],
        "file_path": candidate["file_path"],
        "language": "javascript",
        "vulnerable_range": {"start": 1, "end": 3},
        "fixed_range": {"start": 1, "end": 3},
        "vulnerable_code": "htmlPrefilter: function( html ) {\n  return html.replace( rxhtmlTag, '<$1></$2>' );\n}",
        "fixed_code": "htmlPrefilter: function( html ) {\n  return html;\n}",
        "rationale": "Smallest changed function that shows the sanitizer behavior.",
        "uncertainty": "",
        "review_notes": "Review against upstream commit.",
        "source_urls": finding["source_urls"],
        "repo_urls": finding["repo_urls"],
        "patch_refs": finding["patch_refs"],
        "license": finding["license"],
        "evidence_level": finding["evidence_level"],
        "confidence": finding["confidence"],
    }


if __name__ == "__main__":
    unittest.main()
