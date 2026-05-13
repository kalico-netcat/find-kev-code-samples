from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .io import read_json, write_json
from .samples import normalize_extension, normalize_sample_kind

TRANSFORM_VERSION = "generic-lexical-v1"
IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
COMMIT_RE = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)

KEYWORDS_BY_EXTENSION = {
    "c": {
        "auto",
        "break",
        "case",
        "char",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "float",
        "for",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "register",
        "restrict",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
    },
    "cpp": {
        "alignas",
        "alignof",
        "and",
        "asm",
        "auto",
        "bool",
        "break",
        "case",
        "catch",
        "char",
        "class",
        "const",
        "constexpr",
        "continue",
        "decltype",
        "default",
        "delete",
        "do",
        "double",
        "else",
        "enum",
        "explicit",
        "extern",
        "false",
        "float",
        "for",
        "friend",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "namespace",
        "new",
        "noexcept",
        "nullptr",
        "operator",
        "private",
        "protected",
        "public",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "template",
        "this",
        "throw",
        "true",
        "try",
        "typedef",
        "typename",
        "union",
        "unsigned",
        "using",
        "virtual",
        "void",
        "volatile",
        "while",
    },
    "java": {
        "abstract",
        "assert",
        "boolean",
        "break",
        "byte",
        "case",
        "catch",
        "char",
        "class",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extends",
        "final",
        "finally",
        "float",
        "for",
        "if",
        "implements",
        "import",
        "instanceof",
        "int",
        "interface",
        "long",
        "native",
        "new",
        "null",
        "package",
        "private",
        "protected",
        "public",
        "return",
        "short",
        "static",
        "strictfp",
        "super",
        "switch",
        "synchronized",
        "this",
        "throw",
        "throws",
        "transient",
        "true",
        "try",
        "void",
        "volatile",
        "while",
    },
    "js": {
        "await",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "export",
        "extends",
        "false",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "let",
        "new",
        "null",
        "of",
        "return",
        "static",
        "super",
        "switch",
        "this",
        "throw",
        "true",
        "try",
        "typeof",
        "undefined",
        "var",
        "void",
        "while",
        "with",
        "yield",
    },
    "php": {
        "abstract",
        "and",
        "array",
        "as",
        "break",
        "callable",
        "case",
        "catch",
        "class",
        "clone",
        "const",
        "continue",
        "declare",
        "default",
        "die",
        "do",
        "echo",
        "else",
        "elseif",
        "empty",
        "enddeclare",
        "endfor",
        "endforeach",
        "endif",
        "endswitch",
        "endwhile",
        "eval",
        "exit",
        "extends",
        "false",
        "final",
        "finally",
        "fn",
        "for",
        "foreach",
        "function",
        "global",
        "if",
        "implements",
        "include",
        "include_once",
        "instanceof",
        "insteadof",
        "interface",
        "isset",
        "list",
        "namespace",
        "new",
        "null",
        "or",
        "print",
        "private",
        "protected",
        "public",
        "require",
        "require_once",
        "return",
        "static",
        "switch",
        "throw",
        "trait",
        "true",
        "try",
        "unset",
        "use",
        "var",
        "while",
        "xor",
        "yield",
    },
    "py": {
        "and",
        "as",
        "assert",
        "async",
        "await",
        "break",
        "class",
        "continue",
        "def",
        "del",
        "elif",
        "else",
        "except",
        "false",
        "finally",
        "for",
        "from",
        "global",
        "if",
        "import",
        "in",
        "is",
        "lambda",
        "none",
        "nonlocal",
        "not",
        "or",
        "pass",
        "raise",
        "return",
        "true",
        "try",
        "while",
        "with",
        "yield",
    },
    "rb": {
        "alias",
        "and",
        "begin",
        "break",
        "case",
        "class",
        "def",
        "defined",
        "do",
        "else",
        "elsif",
        "end",
        "ensure",
        "false",
        "for",
        "if",
        "in",
        "module",
        "next",
        "nil",
        "not",
        "or",
        "redo",
        "rescue",
        "retry",
        "return",
        "self",
        "super",
        "then",
        "true",
        "undef",
        "unless",
        "until",
        "when",
        "while",
        "yield",
    },
}


@dataclass(frozen=True)
class CodePair:
    extension: str
    vulnerable_path: Path
    fixed_path: Path
    vulnerable_code: str
    fixed_code: str


@dataclass(frozen=True)
class NegativeCode:
    extension: str
    negative_path: Path
    negative_code: str


@dataclass(frozen=True)
class AnonymizedSample:
    source_fingerprint: str
    public_id: str
    source_sample_kind: str
    is_vulnerable: bool
    language: str
    extension: str
    vulnerable_code: str
    fixed_code: str
    sample_dir: Path
    status: str


def anonymize_samples(
    root: Path,
    status: str = "accepted",
    output_dir: Path = Path("anonymized-samples"),
    force: bool = False,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    sample_dirs = sample_dirs_for_status(root, status)
    output_root = resolve(root, output_dir)
    existing_ids = existing_public_ids(output_root)
    samples = build_anonymized_samples(sample_dirs, existing_ids=existing_ids)
    results: list[dict[str, Any]] = []
    for sample in samples:
        result = anonymize_sample_dir(
            sample,
            output_root,
            force=force,
            dry_run=dry_run,
        )
        results.append(result)
    return results


def sample_dirs_for_status(root: Path, status: str) -> list[Path]:
    allowed = {"needs_review", "accepted", "rejected", "needs_more_evidence", "all"}
    if status not in allowed:
        raise ValueError(f"invalid review status {status!r}; expected one of: {', '.join(sorted(allowed))}")

    samples_root = root / "samples"
    if not samples_root.exists():
        return []

    sample_dirs: list[Path] = []
    for metadata_path in sorted(samples_root.glob("**/metadata.json")):
        metadata = read_json(metadata_path)
        sample_status = str(metadata.get("status") or "") if isinstance(metadata, dict) else ""
        if status == "all" or sample_status == status:
            sample_dirs.append(metadata_path.parent)
    return sample_dirs


def anonymize_sample_dir(
    sample: AnonymizedSample,
    output_root: Path,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    destination = output_root / sample.public_id
    transform = anonymize_code_pair(sample.vulnerable_code, sample.fixed_code, sample.extension)
    result = base_anonymize_result(sample, destination, dry_run)
    result["symbols_renamed"] = len(transform["symbol_map"])
    result["comments_removed"] = transform["comments_removed"]

    if dry_run:
        return result

    if destination.exists() and not force:
        existing_metadata = read_json(destination / "metadata.json") if (destination / "metadata.json").exists() else {}
        if (
            isinstance(existing_metadata, dict)
            and str(existing_metadata.get("source_fingerprint") or "") == result["source_fingerprint"]
        ):
            result["action"] = "skipped_existing"
            return result
        raise ValueError(f"{destination}: anonymized sample already exists; use --force to overwrite")

    destination.mkdir(parents=True, exist_ok=True)
    public_metadata = {
        "sample_id": sample.public_id,
        "status": result["status"],
        "sample_kind": sample.source_sample_kind,
        "is_vulnerable": sample.is_vulnerable,
        "language": sample.language,
        "source_fingerprint": sample.source_fingerprint,
        "transform_version": TRANSFORM_VERSION,
        "files": {
            "vulnerable": f"vulnerable.{sample.extension}",
            "fixed": f"fixed.{sample.extension}",
        },
    }
    write_json(destination / "metadata.json", public_metadata)
    (destination / f"vulnerable.{sample.extension}").write_text(transform["vulnerable_code"], encoding="utf-8")
    (destination / f"fixed.{sample.extension}").write_text(transform["fixed_code"], encoding="utf-8")
    write_json(
        destination / "mapping.json",
        {
            "transform_version": TRANSFORM_VERSION,
            "source_fingerprint": sample.source_fingerprint,
            "symbol_count": len(transform["symbol_map"]),
            "symbol_hashes": hashed_symbol_map(transform["symbol_map"]),
            "comments_removed": transform["comments_removed"],
        },
    )
    (destination / "review.md").write_text(render_public_review(public_metadata, result), encoding="utf-8")
    result["action"] = "anonymized"
    return result


def base_anonymize_result(
    sample: AnonymizedSample,
    destination: Path,
    dry_run: bool,
) -> dict[str, Any]:
    return {
        "sample_id": sample.public_id,
        "source_fingerprint": sample.source_fingerprint,
        "status": sample.status,
        "sample_kind": sample.source_sample_kind,
        "is_vulnerable": sample.is_vulnerable,
        "language": sample.language,
        "destination": str(destination),
        "action": "planned" if dry_run else "",
        "dry_run": dry_run,
    }


def existing_public_ids(output_root: Path) -> dict[str, str]:
    ids: dict[str, str] = {}
    if not output_root.exists():
        return ids
    for metadata_path in sorted(output_root.glob("*/metadata.json")):
        metadata = read_json(metadata_path)
        if not isinstance(metadata, dict):
            continue
        fingerprint = str(metadata.get("source_fingerprint") or "").strip()
        sample_id = str(metadata.get("sample_id") or metadata_path.parent.name).strip()
        if fingerprint and sample_id:
            ids[fingerprint] = sample_id
    return ids


def build_anonymized_samples(sample_dirs: list[Path], existing_ids: dict[str, str]) -> list[AnonymizedSample]:
    samples: list[AnonymizedSample] = []
    for sample_dir in sample_dirs:
        metadata = read_json(sample_dir / "metadata.json")
        if not isinstance(metadata, dict):
            raise ValueError(f"{sample_dir / 'metadata.json'}: metadata must be an object")
        samples.append(build_sample_for_export(sample_dir, metadata, existing_ids))
    return samples


def build_sample_for_export(sample_dir: Path, metadata: dict[str, Any], existing_ids: dict[str, str]) -> AnonymizedSample:
    sample_kind = normalize_sample_kind(metadata)
    sample_language = str(metadata.get("language") or "txt")
    base_fingerprint = source_fingerprint(metadata, sample_dir)
    status = str(metadata.get("status") or "")
    if sample_kind == "negative":
        negative = read_negative_code(sample_dir, metadata)
        return AnonymizedSample(
            source_fingerprint=base_fingerprint,
            public_id=existing_ids.get(base_fingerprint, public_sample_id(base_fingerprint)),
            source_sample_kind=sample_kind,
            is_vulnerable=False,
            language=sample_language or negative.extension,
            extension=negative.extension,
            vulnerable_code=negative.negative_code,
            fixed_code=negative.negative_code,
            sample_dir=sample_dir,
            status=status,
        )
        

    pair = read_code_pair(sample_dir, metadata)
    return AnonymizedSample(
        source_fingerprint=base_fingerprint,
        public_id=existing_ids.get(base_fingerprint, public_sample_id(base_fingerprint)),
        source_sample_kind=sample_kind,
        is_vulnerable=True,
        language=sample_language or pair.extension,
        extension=pair.extension,
        vulnerable_code=pair.vulnerable_code,
        fixed_code=pair.fixed_code,
        sample_dir=sample_dir,
        status=status,
    )


def public_sample_id(source_fingerprint: str) -> str:
    token = source_fingerprint.removeprefix("sha256:").lower()
    return f"sample-{token[:20]}"


def read_code_pair(sample_dir: Path, metadata: dict[str, Any]) -> CodePair:
    vulnerable_files = sorted(sample_dir.glob("vulnerable.*"))
    fixed_files = sorted(sample_dir.glob("fixed.*"))
    if not vulnerable_files:
        raise ValueError(f"{sample_dir}: missing vulnerable.* snippet")
    if not fixed_files:
        raise ValueError(f"{sample_dir}: missing fixed.* snippet")

    vulnerable_path = vulnerable_files[0]
    fixed_path = fixed_files[0]
    extension = normalize_extension(str(metadata.get("language") or vulnerable_path.suffix.lstrip(".") or "txt"))
    if vulnerable_path.suffix:
        extension = vulnerable_path.suffix.lstrip(".")
    return CodePair(
        extension=extension,
        vulnerable_path=vulnerable_path,
        fixed_path=fixed_path,
        vulnerable_code=vulnerable_path.read_text(encoding="utf-8"),
        fixed_code=fixed_path.read_text(encoding="utf-8"),
    )


def read_negative_code(sample_dir: Path, metadata: dict[str, Any]) -> NegativeCode:
    negative_files = sorted(sample_dir.glob("negative.*"))
    if not negative_files:
        raise ValueError(f"{sample_dir}: missing negative.* snippet")

    negative_path = negative_files[0]
    extension = normalize_extension(str(metadata.get("language") or negative_path.suffix.lstrip(".") or "txt"))
    if negative_path.suffix:
        extension = negative_path.suffix.lstrip(".")
    return NegativeCode(
        extension=extension,
        negative_path=negative_path,
        negative_code=negative_path.read_text(encoding="utf-8"),
    )


def anonymize_code_pair(vulnerable_code: str, fixed_code: str, extension: str) -> dict[str, Any]:
    symbol_map: dict[str, str] = {}
    comments_removed = 0
    vulnerable_output, removed = transform_code(vulnerable_code, extension, symbol_map)
    comments_removed += removed
    fixed_output, removed = transform_code(fixed_code, extension, symbol_map)
    comments_removed += removed
    return {
        "vulnerable_code": vulnerable_output,
        "fixed_code": fixed_output,
        "symbol_map": symbol_map,
        "comments_removed": comments_removed,
    }


def anonymize_negative_code(negative_code: str, extension: str) -> dict[str, Any]:
    symbol_map: dict[str, str] = {}
    negative_output, comments_removed = transform_code(negative_code, extension, symbol_map)
    return {
        "negative_code": negative_output,
        "symbol_map": symbol_map,
        "comments_removed": comments_removed,
    }


def transform_code(code: str, extension: str, symbol_map: dict[str, str]) -> tuple[str, int]:
    spans = split_code_spans(code, extension)
    output: list[str] = []
    comments_removed = 0
    for kind, text in spans:
        if kind == "code":
            output.append(rename_identifiers(text, extension, symbol_map))
        elif kind == "comment":
            comments_removed += 1
            if "\n" in text:
                output.append("\n" * text.count("\n"))
        else:
            output.append(text)
    return "".join(output), comments_removed


def split_code_spans(code: str, extension: str) -> list[tuple[str, str]]:
    spans: list[tuple[str, str]] = []
    index = 0
    start = 0
    while index < len(code):
        if code[index] == "/" and extension in {"js", "ts"} and is_regex_literal_start(code, index):
            append_code_span(spans, code[start:index])
            stop = consume_regex_literal(code, index)
            spans.append(("string", code[index:stop]))
            index = stop
            start = index
            continue
        if code.startswith("/*", index):
            append_code_span(spans, code[start:index])
            end = code.find("*/", index + 2)
            stop = len(code) if end == -1 else end + 2
            spans.append(("comment", code[index:stop]))
            index = stop
            start = index
            continue
        if code.startswith("//", index) and extension not in {"py", "rb"}:
            append_code_span(spans, code[start:index])
            stop = find_line_end(code, index)
            spans.append(("comment", code[index:stop]))
            index = stop
            start = index
            continue
        if code[index] == "#" and extension in {"py", "rb", "sh"}:
            append_code_span(spans, code[start:index])
            stop = find_line_end(code, index)
            spans.append(("comment", code[index:stop]))
            index = stop
            start = index
            continue
        if code[index] in {"'", '"', "`"}:
            append_code_span(spans, code[start:index])
            quote = code[index]
            stop = consume_string(code, index, quote)
            spans.append(("string", code[index:stop]))
            index = stop
            start = index
            continue
        index += 1

    append_code_span(spans, code[start:])
    return spans


def append_code_span(spans: list[tuple[str, str]], text: str) -> None:
    if text:
        spans.append(("code", text))


def find_line_end(code: str, index: int) -> int:
    end = code.find("\n", index)
    return len(code) if end == -1 else end


def consume_string(code: str, index: int, quote: str) -> int:
    cursor = index + 1
    while cursor < len(code):
        if code[cursor] == "\\":
            cursor += 2
            continue
        if code[cursor] == quote:
            return cursor + 1
        cursor += 1
    return len(code)


def is_regex_literal_start(code: str, index: int) -> bool:
    if code.startswith("//", index) or code.startswith("/*", index):
        return False
    before = previous_nonspace(code, index)
    return before in {"", "(", "=", ":", ",", "[", "{", ";", "!", "?", "&", "|"} or previous_word(code, index) in {
        "return",
        "case",
        "throw",
        "typeof",
        "delete",
        "void",
    }


def previous_word(code: str, index: int) -> str:
    cursor = index - 1
    while cursor >= 0 and code[cursor].isspace():
        cursor -= 1
    end = cursor + 1
    while cursor >= 0 and (code[cursor].isalnum() or code[cursor] == "_"):
        cursor -= 1
    return code[cursor + 1 : end]


def consume_regex_literal(code: str, index: int) -> int:
    cursor = index + 1
    in_class = False
    while cursor < len(code):
        char = code[cursor]
        if char == "\\":
            cursor += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            cursor += 1
            while cursor < len(code) and code[cursor].isalpha():
                cursor += 1
            return cursor
        elif char == "\n":
            return cursor
        cursor += 1
    return len(code)


def rename_identifiers(text: str, extension: str, symbol_map: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        identifier = match.group(0)
        if not should_rename_identifier(text, match.start(), match.end(), identifier, extension):
            return identifier
        if identifier not in symbol_map:
            symbol_map[identifier] = f"sym_{len(symbol_map) + 1:04d}"
        return symbol_map[identifier]

    return IDENTIFIER_RE.sub(replace, text)


def should_rename_identifier(text: str, start: int, end: int, identifier: str, extension: str) -> bool:
    if len(identifier) <= 1:
        return False
    if identifier.lower() in keywords_for_extension(extension):
        return False
    if identifier.startswith("__") and identifier.endswith("__"):
        return False
    if identifier.isupper():
        return False

    before = previous_nonspace(text, start)
    after = next_nonspace(text, end)
    if before in {".", ":"}:
        return False
    if before == ">" and previous_nonspace(text, start, skip=1) == "-":
        return False
    if extension == "php" and before != "$" and after not in {"(", ":"}:
        return False
    return True


def keywords_for_extension(extension: str) -> set[str]:
    extension = extension.lower().lstrip(".")
    return KEYWORDS_BY_EXTENSION.get(extension, set()) | KEYWORDS_BY_EXTENSION.get("js", set())


def previous_nonspace(text: str, index: int, skip: int = 0) -> str:
    cursor = index - 1
    skipped = 0
    while cursor >= 0:
        char = text[cursor]
        if char.isspace():
            cursor -= 1
            continue
        if skipped < skip:
            skipped += 1
            cursor -= 1
            continue
        return char
    return ""


def next_nonspace(text: str, index: int) -> str:
    cursor = index
    while cursor < len(text):
        char = text[cursor]
        if not char.isspace():
            return char
        cursor += 1
    return ""


def source_fingerprint(metadata: dict[str, Any], sample_dir: Path) -> str:
    pieces = [
        str(metadata.get("sample_key") or ""),
        str(metadata.get("source_finding_key") or ""),
        str(metadata.get("cve_id") or ""),
        sample_dir.as_posix(),
    ]
    digest = hashlib.sha256("\n".join(pieces).encode("utf-8")).digest()
    return f"sha256:{base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')}"


def hashed_symbol_map(symbol_map: dict[str, str]) -> dict[str, str]:
    hashed: dict[str, str] = {}
    for original, anonymized in sorted(symbol_map.items(), key=lambda item: item[1]):
        digest = hashlib.sha256(original.encode("utf-8")).digest()
        hashed[f"sha256:{base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')}"] = anonymized
    return hashed


def render_public_review(metadata: dict[str, Any], result: dict[str, Any]) -> str:
    file_summary = "vulnerable and fixed snippets"
    return f"""# {metadata['sample_id']}

Status: {metadata['status']}
Sample kind: {metadata.get('sample_kind', 'positive')}
Label: {"vulnerable sample" if metadata.get("is_vulnerable") else "non-vulnerable sample"}
Language: {metadata['language']}
Transform: {metadata['transform_version']}
Source fingerprint: `{metadata['source_fingerprint']}`

## Review Notes

This is a generated anonymized copy of a canonical KEV sample. Public provenance has been replaced with a stable fingerprint, comments were removed, and ordinary identifiers were renamed consistently across the exported {file_summary}.

## Transform Summary

- Symbols renamed: {result['symbols_renamed']}
- Comments removed: {result['comments_removed']}
"""


def validate_anonymized_output(root: Path) -> list[str]:
    errors: list[str] = []
    forbidden = [re.compile(r"CVE-\d{4}-\d{4,}"), re.compile(r"https?://"), COMMIT_RE]
    if not root.exists():
        return errors
    for metadata_path in sorted(root.glob("*/metadata.json")):
        errors.extend(validate_anonymized_dir(metadata_path.parent))
    for path in sorted(root.glob("**/*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            if pattern.search(text):
                errors.append(f"{path}: contains public provenance marker matching {pattern.pattern}")
    return errors


def validate_anonymized_dir(item_dir: Path) -> list[str]:
    metadata_path = item_dir / "metadata.json"
    if not metadata_path.exists():
        return []

    try:
        metadata = read_json(metadata_path)
    except json.JSONDecodeError as exc:
        return [f"{metadata_path}: invalid JSON: {exc}"]
    if not isinstance(metadata, dict):
        return [f"{metadata_path}: metadata must be an object"]

    source_fingerprint = str(metadata.get("source_fingerprint") or "").strip()
    if not source_fingerprint:
        return []

    errors: list[str] = []
    files = metadata.get("files")
    if not isinstance(files, dict) or set(files.keys()) != {"vulnerable", "fixed"}:
        errors.append(f"{metadata_path}: anonymized sample must declare vulnerable and fixed snippet files")
        return errors

    for declared_name in files.values():
        snippet_path = item_dir / str(declared_name)
        if not snippet_path.exists():
            errors.append(f"{snippet_path}: missing anonymized snippet")

    snippet_files = [
        path
        for path in item_dir.iterdir()
        if path.is_file() and path.name not in {"metadata.json", "mapping.json", "review.md"}
    ]
    if len(snippet_files) != 2:
        errors.append(f"{item_dir}: anonymized sample must contain exactly two snippet files")

    if "is_vulnerable" not in metadata:
        errors.append(f"{metadata_path}: missing is_vulnerable")
    return errors


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path
