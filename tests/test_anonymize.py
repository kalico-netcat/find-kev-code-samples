from pathlib import Path
import contextlib
import io
import json
import tempfile
import unittest

from kev_collector.anonymize import anonymize_code_pair, anonymize_samples, validate_anonymized_output
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
            output = root / "anonymized-samples/sample-0001"
            self.assertTrue((output / "metadata.json").exists())
            metadata = json.loads((output / "metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["sample_id"], "sample-0001")
            self.assertEqual(metadata["status"], "accepted")
            self.assertNotIn("cve_id", metadata)
            self.assertNotIn("source_urls", metadata)
            self.assertNotIn("source_status", metadata)

            combined = "\n".join(path.read_text(encoding="utf-8") for path in output.iterdir() if path.is_file())
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

    def test_refuses_existing_output_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sample(root, status="accepted")
            anonymize_samples(root)

            with self.assertRaisesRegex(ValueError, "already exists"):
                anonymize_samples(root)

            results = anonymize_samples(root, force=True)
            self.assertEqual(len(results), 1)

    def test_cli_samples_anonymize(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sample(root, status="needs_review")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["--root", str(root), "samples", "anonymize", "--status", "needs_review"])

            self.assertEqual(exit_code, 0)
            self.assertIn("anonymized sample-0001", stdout.getvalue())
            self.assertTrue((root / "anonymized-samples/sample-0001/vulnerable.js").exists())


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


if __name__ == "__main__":
    unittest.main()
