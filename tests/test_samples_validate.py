from pathlib import Path
import tempfile
import unittest

from kev_collector.io import read_json, write_json
from kev_collector.samples import NEGATIVE_STRATEGY, create_sample, validate_sample_dir


class SampleValidationTests(unittest.TestCase):
    def test_new_sample_scaffold_is_valid_before_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            sample_dir = create_sample(tmp_path / "samples", "CVE-2020-11023", "jquery-xss", "javascript")

            self.assertTrue((sample_dir / "metadata.json").exists())
            self.assertTrue((sample_dir / "evidence.md").exists())
            self.assertTrue((sample_dir / "vulnerable.js").exists())
            self.assertTrue((sample_dir / "fixed.js").exists())
            metadata = read_json(sample_dir / "metadata.json")
            self.assertEqual(metadata["expected_responses"]["vulnerable"]["file"], "vulnerable.js")
            self.assertEqual(metadata["expected_responses"]["fixed"]["file"], "fixed.js")
            self.assertEqual(validate_sample_dir(sample_dir), [])


    def test_accepted_sample_requires_provenance_license_and_nonempty_snippets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            sample_dir = create_sample(tmp_path / "samples", "CVE-2020-11023", "jquery-xss", "javascript")
            metadata_path = sample_dir / "metadata.json"
            metadata = read_json(metadata_path)
            metadata["status"] = "accepted"
            write_json(metadata_path, metadata)

            errors = validate_sample_dir(sample_dir)

            self.assertTrue(any("source_urls" in error for error in errors))
            self.assertTrue(any("license metadata" in error for error in errors))
            self.assertTrue(any("snippet is empty" in error for error in errors))
            self.assertTrue(any("expected_responses.vulnerable empty fields" in error for error in errors))

    def test_accepted_sample_requires_expected_responses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            sample_dir = create_sample(tmp_path / "samples", "CVE-2020-11023", "jquery-xss", "javascript")
            metadata_path = sample_dir / "metadata.json"
            metadata = read_json(metadata_path)
            metadata["status"] = "accepted"
            metadata.pop("expected_responses")
            write_json(metadata_path, metadata)

            errors = validate_sample_dir(sample_dir)

            self.assertTrue(any("expected_responses" in error for error in errors))

    def test_explicit_positive_sample_kind_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            sample_dir = create_sample(tmp_path / "samples", "CVE-2020-11023", "jquery-xss", "javascript")
            metadata_path = sample_dir / "metadata.json"
            metadata = read_json(metadata_path)
            metadata["sample_kind"] = "positive"
            write_json(metadata_path, metadata)

            self.assertEqual(validate_sample_dir(sample_dir), [])

    def test_negative_sample_is_valid_before_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            sample_dir = tmp_path / "samples" / "CVE-2020-11023" / "jquery-xss-negative"
            sample_dir.mkdir(parents=True)
            write_json(
                sample_dir / "metadata.json",
                {
                    "cve_id": "CVE-2020-11023",
                    "sample_id": "jquery-xss-negative",
                    "sample_key": "CVE-2020-11023|repo|commit|file|negative|fixed-lookalike-v1",
                    "source_finding_key": "CVE-2020-11023|source|patch",
                    "status": "needs_review",
                    "sample_kind": "negative",
                    "language": "javascript",
                    "source_urls": ["https://github.com/example/project/commit/deadbeef"],
                    "license": {"name": "MIT", "url": "", "notes": ""},
                    "derived_from_sample_id": "jquery-xss",
                    "derived_from_sample_key": "CVE-2020-11023|repo|commit|file",
                    "negative_strategy": NEGATIVE_STRATEGY,
                },
            )
            (sample_dir / "negative.js").write_text("function safeValue(input) {\n  return input;\n}\n", encoding="utf-8")
            (sample_dir / "evidence.md").write_text("# Evidence\n", encoding="utf-8")

            self.assertEqual(validate_sample_dir(sample_dir), [])

    def test_negative_sample_requires_derivation_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            sample_dir = tmp_path / "samples" / "CVE-2020-11023" / "jquery-xss-negative"
            sample_dir.mkdir(parents=True)
            write_json(
                sample_dir / "metadata.json",
                {
                    "cve_id": "CVE-2020-11023",
                    "sample_id": "jquery-xss-negative",
                    "status": "needs_review",
                    "sample_kind": "negative",
                },
            )
            (sample_dir / "negative.txt").write_text("safe\n", encoding="utf-8")

            errors = validate_sample_dir(sample_dir)

            self.assertTrue(any("negative sample missing fields" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
