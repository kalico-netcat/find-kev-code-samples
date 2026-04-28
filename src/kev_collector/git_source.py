from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GitBundleResult:
    fetch_status: str
    git_commit: str
    git_parent: str
    vulnerable_path: str
    fixed_path: str
    patch_path: str
    candidate_hunks_path: str
    fetch_errors: list[str]

    def metadata(self) -> dict[str, Any]:
        return {
            "fetch_status": self.fetch_status,
            "git_commit": self.git_commit,
            "git_parent": self.git_parent,
            "vulnerable_path": self.vulnerable_path,
            "fixed_path": self.fixed_path,
            "patch_path": self.patch_path,
            "candidate_hunks_path": self.candidate_hunks_path,
            "fetch_errors": self.fetch_errors,
        }


class GitSourceError(RuntimeError):
    pass


def prepare_git_source_bundle(
    candidate: dict[str, Any],
    bundle_dir: Path,
    cache_root: Path,
    cache_name: str,
) -> GitBundleResult:
    errors: list[str] = []
    git_commit = ""
    git_parent = ""
    vulnerable_path = ""
    fixed_path = ""
    patch_path = str(bundle_dir / "patch.diff")
    hunk_path = str(bundle_dir / "candidate_hunks.jsonl")

    try:
        repo_url = require_value(candidate.get("repo_url"), "repo_url")
        patch_ref = require_value(candidate.get("patch_ref"), "patch_ref")
        file_path = safe_relative_path(require_value(candidate.get("file_path"), "file_path"))
        cache_repo = ensure_repo_cache(repo_url, cache_root, cache_name)
        git_commit = git(cache_repo, "rev-parse", f"{patch_ref}^{{commit}}").strip()
        git_parent = git(cache_repo, "rev-parse", f"{git_commit}^").strip()

        vulnerable_bytes = git_bytes(cache_repo, "show", f"{git_parent}:{file_path.as_posix()}")
        fixed_bytes = git_bytes(cache_repo, "show", f"{git_commit}:{file_path.as_posix()}")
        diff_text = git(
            cache_repo,
            "diff",
            "--no-ext-diff",
            "--src-prefix=vulnerable/",
            "--dst-prefix=fixed/",
            git_parent,
            git_commit,
            "--",
            file_path.as_posix(),
        )

        vulnerable_file = bundle_dir / "vulnerable" / file_path
        fixed_file = bundle_dir / "fixed" / file_path
        vulnerable_file.parent.mkdir(parents=True, exist_ok=True)
        fixed_file.parent.mkdir(parents=True, exist_ok=True)
        vulnerable_file.write_bytes(vulnerable_bytes)
        fixed_file.write_bytes(fixed_bytes)
        (bundle_dir / "patch.diff").write_text(diff_text, encoding="utf-8")
        write_hunks(bundle_dir / "candidate_hunks.jsonl", diff_text, file_path.as_posix())
        vulnerable_path = str(vulnerable_file)
        fixed_path = str(fixed_file)
    except (GitSourceError, OSError, UnicodeDecodeError) as exc:
        errors.append(str(exc))

    return GitBundleResult(
        fetch_status="fetched" if not errors else "partial",
        git_commit=git_commit,
        git_parent=git_parent,
        vulnerable_path=vulnerable_path,
        fixed_path=fixed_path,
        patch_path=patch_path,
        candidate_hunks_path=hunk_path,
        fetch_errors=errors,
    )


def ensure_repo_cache(repo_url: str, cache_root: Path, sample_id: str) -> Path:
    cache_root.mkdir(parents=True, exist_ok=True)
    cache_repo = cache_root / f"{safe_cache_name(sample_id)}.git"
    if cache_repo.exists():
        run_git(["--git-dir", str(cache_repo), "fetch", "--all", "--tags", "--prune"])
    else:
        run_git(["clone", "--mirror", repo_url, str(cache_repo)])
    return cache_repo


def git(cache_repo: Path, *args: str) -> str:
    output = git_bytes(cache_repo, *args)
    return output.decode("utf-8", errors="replace")


def git_bytes(cache_repo: Path, *args: str) -> bytes:
    return run_git(["--git-dir", str(cache_repo), *args]).stdout


def run_git(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            ["git", *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise GitSourceError("git executable not found") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", errors="replace").strip()
        command = "git " + " ".join(args)
        raise GitSourceError(f"{command} failed: {stderr}") from exc
    return result


def write_hunks(path: Path, diff_text: str, file_path: str) -> None:
    hunks = parse_hunks(diff_text, file_path)
    with path.open("w", encoding="utf-8") as handle:
        for hunk in hunks:
            handle.write(json.dumps(hunk, sort_keys=True, separators=(",", ":")) + "\n")


def parse_hunks(diff_text: str, file_path: str) -> list[dict[str, Any]]:
    hunks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in diff_text.splitlines():
        if line.startswith("@@ "):
            current = {
                "file_path": file_path,
                "header": line,
                "removed_lines": 0,
                "added_lines": 0,
            }
            hunks.append(current)
        elif current and line.startswith("-") and not line.startswith("---"):
            current["removed_lines"] += 1
        elif current and line.startswith("+") and not line.startswith("+++"):
            current["added_lines"] += 1
    return hunks


def require_value(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not text or text.startswith("unknown-"):
        raise GitSourceError(f"missing usable {name}")
    return text


def safe_relative_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise GitSourceError(f"unsafe file_path: {value}")
    return path


def safe_cache_name(value: str) -> str:
    return "".join(character if character.isalnum() or character in "._-" else "-" for character in value)[:96]
