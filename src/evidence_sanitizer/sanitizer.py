"""Single-file sanitization behavior for milestone 1."""

from __future__ import annotations

import codecs
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

MAX_INPUT_BYTES = 10 * 1024 * 1024
RULE_ID_AUTHORIZATION_BEARER = "authorization.bearer"
REDACTION_MARKER = "<REDACTED:authorization.bearer>"

EXIT_INTERNAL_ERROR = 1
EXIT_UNSAFE_PATH = 3
EXIT_INPUT_ERROR = 4
EXIT_OUTPUT_ERROR = 5

AUTHORIZATION_BEARER_PATTERN = re.compile(
    r"^Authorization[ \t]*:[ \t]*Bearer[ \t]+"
    r"(?P<credential>\S+)(?P<trailing>[ \t]*)(?=\r?\n|$)",
    re.IGNORECASE | re.MULTILINE,
)


class SafeError(Exception):
    """Expected failure with a user-safe message and documented exit code."""

    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code


@dataclass(frozen=True)
class Finding:
    """A replacement span that never stores the matched credential."""

    rule_id: str
    start: int
    end: int
    replacement: str


@dataclass(frozen=True)
class SanitizationReport:
    """Safe report data for user-facing summaries."""

    counts_by_rule: dict[str, int]
    changed: bool


@dataclass(frozen=True)
class DecodedInput:
    """Decoded input plus BOM state needed for output preservation."""

    text: str
    had_bom: bool


@dataclass(frozen=True)
class SanitizationResult:
    """Application result for normal and dry-run execution."""

    report: SanitizationReport
    output_written: bool


def find_authorization_bearer(text: str) -> tuple[Finding, ...]:
    """Find HTTP-style Authorization: Bearer credentials."""
    findings: list[Finding] = []

    # Milestone 1 intentionally treats any exact header-like line as a header;
    # full HTTP message parsing and body-boundary awareness are deferred.
    for match in AUTHORIZATION_BEARER_PATTERN.finditer(text):
        credential = match.group("credential")
        if credential == REDACTION_MARKER:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID_AUTHORIZATION_BEARER,
                start=match.start("credential"),
                end=match.end("credential"),
                replacement=REDACTION_MARKER,
            )
        )

    return tuple(findings)


def apply_findings(text: str, findings: Sequence[Finding]) -> str:
    """Apply non-overlapping replacements from right to left."""
    sanitized = text
    next_start = len(text)

    for finding in sorted(findings, key=lambda item: item.start, reverse=True):
        if finding.start < 0 or finding.end < finding.start or finding.end > len(text):
            raise SafeError("internal sanitization error", EXIT_INTERNAL_ERROR)
        if finding.end > next_start:
            raise SafeError("internal sanitization error", EXIT_INTERNAL_ERROR)

        sanitized = (
            sanitized[: finding.start] + finding.replacement + sanitized[finding.end :]
        )
        next_start = finding.start

    return sanitized


def sanitize_text(text: str) -> tuple[str, SanitizationReport]:
    """Sanitize decoded text with the single milestone 1 rule."""
    findings = find_authorization_bearer(text)
    sanitized = apply_findings(text, findings)
    count = len(findings)
    counts = {RULE_ID_AUTHORIZATION_BEARER: count} if count else {}

    return sanitized, SanitizationReport(
        counts_by_rule=counts,
        changed=sanitized != text,
    )


def validate_paths(input_path: Path, output_path: Path) -> None:
    """Validate source and destination path safety for one-file processing."""
    try:
        if not input_path.is_file():
            raise SafeError(
                "input file is not a readable regular file", EXIT_INPUT_ERROR
            )
        input_resolved = input_path.resolve(strict=True)
    except SafeError:
        raise
    except OSError as exc:
        raise SafeError(
            "input file is not a readable regular file", EXIT_INPUT_ERROR
        ) from exc

    output_parent = output_path.parent
    try:
        if not output_parent.exists() or not output_parent.is_dir():
            raise SafeError("output parent directory does not exist", EXIT_UNSAFE_PATH)
        output_resolved = output_path.resolve(strict=False)
    except SafeError:
        raise
    except OSError as exc:
        raise SafeError("unsafe output path", EXIT_UNSAFE_PATH) from exc

    if input_resolved == output_resolved:
        raise SafeError(
            "output path must not resolve to the input file", EXIT_UNSAFE_PATH
        )

    try:
        if output_path.exists() or output_path.is_symlink():
            raise SafeError("output file already exists", EXIT_UNSAFE_PATH)
    except SafeError:
        raise
    except OSError as exc:
        raise SafeError("unsafe output path", EXIT_UNSAFE_PATH) from exc


def read_input_file(input_path: Path) -> DecodedInput:
    """Read and decode a UTF-8 text file without newline normalization."""
    try:
        if input_path.stat().st_size > MAX_INPUT_BYTES:
            raise SafeError("input exceeds 10 MiB limit", EXIT_INPUT_ERROR)
        data = input_path.read_bytes()
    except SafeError:
        raise
    except OSError as exc:
        raise SafeError(
            "input file is not a readable regular file", EXIT_INPUT_ERROR
        ) from exc

    if len(data) > MAX_INPUT_BYTES:
        raise SafeError("input exceeds 10 MiB limit", EXIT_INPUT_ERROR)
    if b"\x00" in data:
        raise SafeError("input contains NUL bytes", EXIT_INPUT_ERROR)

    had_bom = data.startswith(codecs.BOM_UTF8)
    payload = data[len(codecs.BOM_UTF8) :] if had_bom else data
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        pass
    else:
        return DecodedInput(text=text, had_bom=had_bom)

    raise SafeError("input is not valid UTF-8", EXIT_INPUT_ERROR) from None


def encode_output(text: str, had_bom: bool) -> bytes:
    """Encode sanitized text while preserving original UTF-8 BOM state."""
    encoded = text.encode("utf-8")
    return codecs.BOM_UTF8 + encoded if had_bom else encoded


def write_output_exclusive(output_path: Path, text: str, had_bom: bool) -> None:
    """Create and write the output file without overwriting existing paths."""
    data = encode_output(text, had_bom)
    created = False

    try:
        with output_path.open("xb") as output_file:
            created = True
            output_file.write(data)
    except FileExistsError as exc:
        raise SafeError("output file already exists", EXIT_UNSAFE_PATH) from exc
    except OSError as exc:
        if created:
            try:
                output_path.unlink()
            except OSError:
                pass
        raise SafeError("could not write output file", EXIT_OUTPUT_ERROR) from exc


def sanitize_file(
    input_path: Path, output_path: Path, dry_run: bool
) -> SanitizationResult:
    """Run milestone 1 sanitization for one input file."""
    validate_paths(input_path, output_path)
    decoded = read_input_file(input_path)
    sanitized, report = sanitize_text(decoded.text)

    if dry_run:
        return SanitizationResult(report=report, output_written=False)

    write_output_exclusive(output_path, sanitized, decoded.had_bom)
    return SanitizationResult(report=report, output_written=True)
