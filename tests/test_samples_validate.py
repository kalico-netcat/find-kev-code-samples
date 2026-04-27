from pathlib import Path
import tempfile
import unittest

from kev_collector.io import read_json, write_json
from kev_collector.samples import create_sample, validate_sample_dir


class SampleValidationTests(unittest.TestCase):
    def test_new_sample_scaffold_is_valid_before_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            sample_dir = create_sample(tmp_path / "samples", "CVE-2020-11023", "jquery-xss", "javascript")

            self.assertTrue((sample_dir / "metadata.json").exists())
            self.assertTrue((sample_dir / "evidence.md").exists())
            self.assertTrue((sample_dir / "vulnerable.js").exists())
            self.assertTrue((sample_dir / "fixed.js").exists())
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


if __name__ == "__main__":
    unittest.main()
