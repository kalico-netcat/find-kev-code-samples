from pathlib import Path
import contextlib
import io
import json
import subprocess
import tempfile
import unittest

from kev_collector.io import write_json, write_jsonl
from kev_collector.cli import main
from kev_collector.sample_pipeline import (
    build_sample_candidate,
    import_snippets,
    list_sample_reviews,
    list_sample_candidates,
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
    def test_candidates_skip_existing_sample(self) -> None:
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

    def test_candidates_skip_existing_snippet_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = fixture_finding()
            candidate = build_sample_candidate(finding)
            write_jsonl(root / "data/findings.jsonl", [finding])
            write_json(root / "agent-output/snippets/CVE-2020-11023/sample.json", snippet_for(candidate))

            candidates = list_sample_candidates(root)

            self.assertEqual(candidates, [])
            skipped = list_sample_candidates(root, include_skipped=True)
            self.assertEqual(skipped[0]["skip_reason"], "already_exists:snippet")

    def test_prepare_creates_bundle_and_prompt_for_new_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_jsonl(root / "data/findings.jsonl", [fixture_finding()])

            prepared = prepare_sample_candidates(root, fetch_code=False)

            self.assertEqual(len(prepared), 1)
            bundle_dir = Path(prepared[0]["bundle_dir"])
            prompt_path = Path(prepared[0]["prompt_path"])
            self.assertTrue((bundle_dir / "metadata.json").exists())
            self.assertTrue((bundle_dir / "finding.json").exists())
            self.assertTrue(prompt_path.exists())
            metadata = json.loads((bundle_dir / "metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["fetch_status"], "skipped")

    def test_prepare_fetches_git_bundle_for_commit_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, commit = create_git_repo(root)
            finding = fixture_finding()
            finding["repo_urls"] = [str(repo)]
            finding["patch_refs"] = [commit]
            finding["source_urls"] = [f"{repo}/commit/{commit}"]
            finding["affected_files"] = ["src/app.js"]
            write_jsonl(root / "data/findings.jsonl", [finding])

            prepared = prepare_sample_candidates(root)

            self.assertEqual(len(prepared), 1)
            self.assertEqual(prepared[0]["fetch_status"], "fetched")
            bundle_dir = Path(prepared[0]["bundle_dir"])
            metadata = json.loads((bundle_dir / "metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["fetch_status"], "fetched")
            self.assertTrue(metadata["git_commit"])
            self.assertTrue(metadata["git_parent"])
            self.assertEqual((bundle_dir / "vulnerable/src/app.js").read_text(encoding="utf-8"), "const mode = 'unsafe';\n")
            self.assertEqual((bundle_dir / "fixed/src/app.js").read_text(encoding="utf-8"), "const mode = 'safe';\n")
            diff = (bundle_dir / "patch.diff").read_text(encoding="utf-8")
            self.assertIn("-const mode = 'unsafe';", diff)
            self.assertIn("+const mode = 'safe';", diff)
            hunks = [json.loads(line) for line in (bundle_dir / "candidate_hunks.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(hunks[0]["file_path"], "src/app.js")
            self.assertGreaterEqual(hunks[0]["removed_lines"], 1)
            self.assertGreaterEqual(hunks[0]["added_lines"], 1)
            prompt = Path(prepared[0]["prompt_path"]).read_text(encoding="utf-8")
            self.assertIn("Prepared Source Context", prompt)
            self.assertIn("vulnerable_path", prompt)

    def test_prepare_records_fetch_errors_and_keeps_partial_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, _commit = create_git_repo(root)
            finding = fixture_finding()
            finding["repo_urls"] = [str(repo)]
            finding["patch_refs"] = ["deadbee"]
            finding["source_urls"] = [f"{repo}/commit/deadbee"]
            finding["affected_files"] = ["src/app.js"]
            write_jsonl(root / "data/findings.jsonl", [finding])

            prepared = prepare_sample_candidates(root)

            self.assertEqual(len(prepared), 1)
            self.assertEqual(prepared[0]["fetch_status"], "partial")
            bundle_dir = Path(prepared[0]["bundle_dir"])
            metadata = json.loads((bundle_dir / "metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["fetch_status"], "partial")
            self.assertTrue(metadata["fetch_errors"])
            self.assertTrue((bundle_dir / "patch.diff").exists())
            self.assertTrue(Path(prepared[0]["prompt_path"]).exists())

    def test_prepare_no_fetch_code_creates_prompt_only_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, commit = create_git_repo(root)
            finding = fixture_finding()
            finding["repo_urls"] = [str(repo)]
            finding["patch_refs"] = [commit]
            finding["source_urls"] = [f"{repo}/commit/{commit}"]
            finding["affected_files"] = ["src/app.js"]
            write_jsonl(root / "data/findings.jsonl", [finding])

            prepared = prepare_sample_candidates(root, fetch_code=False)

            bundle_dir = Path(prepared[0]["bundle_dir"])
            metadata = json.loads((bundle_dir / "metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["fetch_status"], "skipped")
            self.assertFalse((bundle_dir / "vulnerable/src/app.js").exists())

    def test_import_refuses_duplicate_sample_key_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = fixture_finding()
            candidate = build_sample_candidate(finding)
            snippet = snippet_for(candidate)
            write_json(root / "agent-output/snippets/CVE-2020-11023/sample.json", snippet)
            write_json(
                root / "samples/CVE-2020-11023/existing/metadata.json",
                {
                    "cve_id": "CVE-2020-11023",
                    "sample_id": "existing",
                    "sample_key": candidate["sample_key"],
                    "status": "needs_review",
                },
            )

            with self.assertRaisesRegex(ValueError, "already imported"):
                import_snippets(root, [Path("agent-output/snippets/CVE-2020-11023/sample.json")])

    def test_import_requires_snippet_code_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = build_sample_candidate(fixture_finding())
            snippet = snippet_for(candidate)
            snippet.pop("vulnerable_code")
            snippet_path = root / "agent-output/snippets/CVE-2020-11023/sample.json"
            write_json(snippet_path, snippet)

            with self.assertRaisesRegex(ValueError, "snippet JSON missing fields: vulnerable_code"):
                import_snippets(root, [snippet_path])

    def test_import_writes_review_ready_sample(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = build_sample_candidate(fixture_finding())
            snippet_path = root / "agent-output/snippets/CVE-2020-11023/sample.json"
            write_json(snippet_path, snippet_for(candidate))

            paths = import_snippets(root, [snippet_path])

            sample_dir = paths[0]
            self.assertTrue((sample_dir / "metadata.json").exists())
            self.assertTrue((sample_dir / "review.md").exists())
            self.assertTrue((sample_dir / "vulnerable.js").exists())
            self.assertTrue((sample_dir / "fixed.js").exists())
            review = (sample_dir / "review.md").read_text(encoding="utf-8")
            self.assertIn("Sample key:", review)
            self.assertIn("Reviewer Checklist", review)

    def test_review_list_defaults_to_needs_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sample_metadata(root, "CVE-2020-11023", "needs", "needs_review")
            write_sample_metadata(root, "CVE-2020-11024", "accepted", "accepted")

            records = list_sample_reviews(root)

            self.assertEqual([record["sample_id"] for record in records], ["needs"])
            self.assertFalse(records[0]["missing_review"])

    def test_review_list_status_all_and_missing_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sample_metadata(root, "CVE-2020-11023", "needs", "needs_review")
            write_sample_metadata(root, "CVE-2020-11024", "accepted", "accepted", with_review=False)

            records = list_sample_reviews(root, status="all")

            self.assertEqual([record["sample_id"] for record in records], ["needs", "accepted"])
            accepted = [record for record in records if record["sample_id"] == "accepted"][0]
            self.assertTrue(accepted["missing_review"])

    def test_review_list_cli_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sample_metadata(root, "CVE-2020-11023", "needs", "needs_review")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["--root", str(root), "samples", "review-list", "--jsonl"])

            self.assertEqual(exit_code, 0)
            rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
            self.assertEqual(rows[0]["cve_id"], "CVE-2020-11023")
            self.assertEqual(rows[0]["status"], "needs_review")


def snippet_for(candidate: dict) -> dict:
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


def create_git_repo(root: Path) -> tuple[Path, str]:
    repo = root / "source-repo"
    repo.mkdir()
    git_command(repo, "init")
    git_command(repo, "config", "user.email", "test@example.invalid")
    git_command(repo, "config", "user.name", "Test User")
    source_file = repo / "src/app.js"
    source_file.parent.mkdir()
    source_file.write_text("const mode = 'unsafe';\n", encoding="utf-8")
    git_command(repo, "add", "src/app.js")
    git_command(repo, "commit", "-m", "initial vulnerable version")
    source_file.write_text("const mode = 'safe';\n", encoding="utf-8")
    git_command(repo, "add", "src/app.js")
    git_command(repo, "commit", "-m", "fix vulnerability")
    commit = git_command(repo, "rev-parse", "HEAD").stdout.decode("utf-8").strip()
    return repo, commit


def git_command(cwd: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def write_sample_metadata(
    root: Path,
    cve_id: str,
    sample_id: str,
    status: str,
    with_review: bool = True,
) -> None:
    sample_dir = root / "samples" / cve_id / sample_id
    write_json(
        sample_dir / "metadata.json",
        {
            "cve_id": cve_id,
            "sample_id": sample_id,
            "sample_key": f"{cve_id}|repo|commit|file",
            "source_finding_key": f"{cve_id}|source|patch",
            "status": status,
            "confidence": 0.94,
            "provenance": {"preferred_source": "official_patch"},
        },
    )
    if with_review:
        (sample_dir / "review.md").write_text("# Review\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
