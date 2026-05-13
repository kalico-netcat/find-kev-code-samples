from pathlib import Path
import contextlib
import io
import json
import tempfile
import unittest

from kev_collector.anonymize import DEFAULT_SHUFFLE_SEED, anonymize_code_pair, anonymize_samples, validate_anonymized_output
from kev_collector.cli import main
from kev_collector.io import write_json


class AnonymizeTests(unittest.TestCase):
    def test_anonymize_code_pair_renames_symbols_consistently_and_strips_comments(self) -> None:
        vulnerable = """// CVE note from upstream
function checkUser(userInput) {
  const cleaned = sanitize(userInput);
  return cleaned.replace(rxhtmlTag, '<$1></$2>');
}
"""
        fixed = """// fixed upstream behavior
function checkUser(userInput) {
  const cleaned = sanitize(userInput);
  return cleaned;
}
"""

        result = anonymize_code_pair(vulnerable, fixed, "js")

        self.assertNotIn("checkUser", result["vulnerable_code"])
        self.assertNotIn("userInput", result["fixed_code"])
        self.assertNotIn("CVE note", result["vulnerable_code"])
        self.assertEqual(result["symbol_map"]["checkUser"], "sym_0001")
        self.assertEqual(result["symbol_map"]["userInput"], "sym_0002")
        self.assertIn("function sym_0001(sym_0002)", result["vulnerable_code"])
        self.assertIn("function sym_0001(sym_0002)", result["fixed_code"])

    def test_anonymize_preserves_javascript_regex_literals(self) -> None:
        vulnerable = "function parse(value) {\n  return /https?:\\/\\/example\\/path/.test(value);\n}\n"
        fixed = "function parse(value) {\n  return /https?:\\/\\/example\\/safe/.test(value);\n}\n"

        result = anonymize_code_pair(vulnerable, fixed, "js")

        self.assertIn("/https?:\\/\\/example\\/path/", result["vulnerable_code"])
        self.assertIn("/https?:\\/\\/example\\/safe/", result["fixed_code"])

    def test_anonymize_samples_writes_public_safe_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sample(root, status="accepted")

            results = anonymize_samples(root)

            self.assertEqual(len(results), 1)
            sample_dirs = list_sample_dirs(root / "anonymized-samples")
            self.assertEqual(len(sample_dirs), 1)
            for sample_dir in sample_dirs:
                metadata = read_public_metadata(sample_dir)
                self.assertEqual(metadata["status"], "accepted")
                self.assertEqual(metadata["sample_kind"], "positive")
                self.assertTrue(metadata["is_vulnerable"])
                self.assertNotIn("cve_id", metadata)
                self.assertNotIn("source_urls", metadata)
                self.assertNotIn("source_status", metadata)
                snippet_files = snippet_files_for_sample(sample_dir)
                self.assertEqual(len(snippet_files), 2)
                self.assertTrue((sample_dir / "vulnerable.js").exists())
                self.assertTrue((sample_dir / "fixed.js").exists())

            combined = "\n".join(
                path.read_text(encoding="utf-8")
                for sample_dir in sample_dirs
                for path in sample_dir.iterdir()
                if path.is_file()
            )
            self.assertNotIn("CVE-2020-11023", combined)
            self.assertNotIn("jquery", combined.lower())
            self.assertNotIn("1d61fd9407e6fbe82fe55cb0b938307aa0791f77", combined)
            self.assertEqual(validate_anonymized_output(root / "anonymized-samples"), [])

    def test_dry_run_does_not_write_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sample(root, status="accepted")

            results = anonymize_samples(root, dry_run=True)

            self.assertEqual(len(results), 1)
            self.assertFalse((root / "anonymized-samples").exists())

    def test_rerun_skips_existing_output_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sample(root, status="accepted")
            first = anonymize_samples(root)
            second = anonymize_samples(root)

            self.assertEqual(len(first), 1)
            self.assertEqual(len(second), 1)
            self.assertTrue(all(item["action"] == "skipped_existing" for item in second))

            results = anonymize_samples(root, force=True)
            self.assertEqual(len(results), 1)

    def test_rerun_adds_new_negative_sample_without_colliding_with_positive_samples(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sample(root, status="accepted")
            anonymize_samples(root)
            write_negative_sample(root, status="accepted")

            results = anonymize_samples(root)

            self.assertEqual(len(results), 2)
            negative = [item for item in results if item["sample_kind"] == "negative"][0]
            self.assertEqual(negative["action"], "anonymized")
            negative_dir = Path(negative["destination"])
            self.assertTrue((negative_dir / "vulnerable.js").exists())
            self.assertTrue((negative_dir / "fixed.js").exists())

    def test_cli_samples_anonymize(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sample(root, status="needs_review")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["--root", str(root), "samples", "anonymize", "--status", "needs_review"])

            self.assertEqual(exit_code, 0)
            output = stdout.getvalue()
            self.assertIn("anonymized", output)
            self.assertIn("positive", output)
            self.assertEqual(len(list_sample_dirs(root / "anonymized-samples")), 1)

    def test_anonymize_samples_writes_negative_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_negative_sample(root, status="accepted")

            results = anonymize_samples(root)

            self.assertEqual(len(results), 1)
            output = list_sample_dirs(root / "anonymized-samples")[0]
            metadata = read_public_metadata(output)
            self.assertEqual(metadata["sample_kind"], "negative")
            self.assertFalse(metadata["is_vulnerable"])
            self.assertTrue((output / "vulnerable.js").exists())
            self.assertTrue((output / "fixed.js").exists())
            self.assertEqual(
                (output / "vulnerable.js").read_text(encoding="utf-8"),
                (output / "fixed.js").read_text(encoding="utf-8"),
            )
            self.assertEqual(validate_anonymized_output(root / "anonymized-samples"), [])

    def test_mixed_pool_contains_positive_and_negative_sample_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sample(root, status="accepted")
            write_negative_sample(root, status="accepted")

            results = anonymize_samples(root)

            self.assertEqual(len(results), 2)
            sample_kinds = sorted(item["sample_kind"] for item in results)
            self.assertEqual(sample_kinds, ["negative", "positive"])
            for sample_dir in list_sample_dirs(root / "anonymized-samples"):
                self.assertEqual(len(snippet_files_for_sample(sample_dir)), 2)

    def test_shuffle_seed_is_stable_and_changes_order_without_changing_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sample(root, status="accepted")
            write_negative_sample(root, status="accepted")

            first = anonymize_samples(root, dry_run=True, seed=DEFAULT_SHUFFLE_SEED)
            second = anonymize_samples(root, dry_run=True, seed=DEFAULT_SHUFFLE_SEED)
            third = anonymize_samples(root, dry_run=True, seed="different-seed")

            first_order = [item["sample_id"] for item in first]
            second_order = [item["sample_id"] for item in second]
            third_order = [item["sample_id"] for item in third]
            self.assertEqual(first_order, second_order)
            self.assertNotEqual(first_order, third_order)
            self.assertEqual(sorted(first_order), sorted(third_order))


def write_sample(root: Path, status: str) -> None:
    sample_dir = root / "samples/CVE-2020-11023/jquery-jquery-1d61fd9407e6-manipulation"
    sample_dir.mkdir(parents=True)
    write_json(
        sample_dir / "metadata.json",
        {
            "cve_id": "CVE-2020-11023",
            "sample_id": "jquery-jquery-1d61fd9407e6-manipulation",
            "sample_key": (
                "CVE-2020-11023|https://github.com/jquery/jquery|"
                "1d61fd9407e6fbe82fe55cb0b938307aa0791f77|src/manipulation.js"
            ),
            "source_finding_key": "CVE-2020-11023|https://github.com/jquery/jquery/security/advisories/GHSA|commit",
            "status": status,
            "sample_kind": "positive",
            "language": "javascript",
            "source_urls": ["https://github.com/jquery/jquery/commit/1d61fd9407e6fbe82fe55cb0b938307aa0791f77"],
            "repo_urls": ["https://github.com/jquery/jquery"],
            "patch_refs": ["1d61fd9407e6fbe82fe55cb0b938307aa0791f77"],
        },
    )
    (sample_dir / "vulnerable.js").write_text(
        """// jquery CVE-2020-11023 upstream note
function htmlPrefilter(userInput) {
  const cleaned = sanitize(userInput);
  return cleaned.replace(rxhtmlTag, '<$1></$2>');
}
""",
        encoding="utf-8",
    )
    (sample_dir / "fixed.js").write_text(
        """// jquery commit 1d61fd9407e6fbe82fe55cb0b938307aa0791f77
function htmlPrefilter(userInput) {
  const cleaned = sanitize(userInput);
  return cleaned;
}
""",
        encoding="utf-8",
    )


def write_negative_sample(root: Path, status: str) -> None:
    sample_dir = root / "samples/CVE-2020-11023/jquery-jquery-1d61fd9407e6-manipulation-negative"
    sample_dir.mkdir(parents=True)
    write_json(
        sample_dir / "metadata.json",
        {
            "cve_id": "CVE-2020-11023",
            "sample_id": "jquery-jquery-1d61fd9407e6-manipulation-negative",
            "sample_key": (
                "CVE-2020-11023|https://github.com/jquery/jquery|"
                "1d61fd9407e6fbe82fe55cb0b938307aa0791f77|src/manipulation.js|negative|fixed-lookalike-v1"
            ),
            "source_finding_key": "CVE-2020-11023|https://github.com/jquery/jquery/security/advisories/GHSA|commit",
            "status": status,
            "sample_kind": "negative",
            "language": "javascript",
            "source_urls": ["https://github.com/jquery/jquery/commit/1d61fd9407e6fbe82fe55cb0b938307aa0791f77"],
            "repo_urls": ["https://github.com/jquery/jquery"],
            "patch_refs": ["1d61fd9407e6fbe82fe55cb0b938307aa0791f77"],
            "license": {"name": "MIT", "url": "", "notes": ""},
            "derived_from_sample_id": "jquery-jquery-1d61fd9407e6-manipulation",
            "derived_from_sample_key": (
                "CVE-2020-11023|https://github.com/jquery/jquery|"
                "1d61fd9407e6fbe82fe55cb0b938307aa0791f77|src/manipulation.js"
            ),
            "negative_strategy": "fixed-lookalike-v1",
        },
    )
    (sample_dir / "negative.js").write_text(
        """// jquery commit 1d61fd9407e6fbe82fe55cb0b938307aa0791f77
function htmlPrefilter(userInput) {
  const cleaned = sanitize(userInput);
  return cleaned;
}
""",
        encoding="utf-8",
    )


def list_sample_dirs(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.iterdir() if path.is_dir())


def read_public_metadata(item_dir: Path) -> dict:
    return json.loads((item_dir / "metadata.json").read_text(encoding="utf-8"))


def snippet_files_for_sample(item_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in item_dir.iterdir()
        if path.is_file() and path.name not in {"metadata.json", "mapping.json", "review.md"}
    )


if __name__ == "__main__":
    unittest.main()
