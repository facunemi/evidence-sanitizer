"""Single-file sanitization behavior."""

from __future__ import annotations

import codecs
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

MAX_INPUT_BYTES = 10 * 1024 * 1024
RULE_ID_AUTHORIZATION_BEARER = "authorization.bearer"
RULE_ID_AUTHORIZATION_BASIC = "authorization.basic"
RULE_ID_AUTHORIZATION_OTHER = "authorization.other"
RULE_ID_COOKIE_VALUE = "cookie.value"
RULE_ID_COOKIE_HEADER = "cookie.header"
RULE_ID_HEADER_SECRET = "header.secret"

REDACTION_MARKER_AUTHORIZATION_BEARER = "<REDACTED:authorization.bearer>"
REDACTION_MARKER_AUTHORIZATION_BASIC = "<REDACTED:authorization.basic>"
REDACTION_MARKER_AUTHORIZATION_CREDENTIALS = "<REDACTED:authorization.credentials>"
REDACTION_MARKER_COOKIE_VALUE = "<REDACTED:cookie.value>"
REDACTION_MARKER_COOKIE_HEADER = "<REDACTED:cookie.header>"
REDACTION_MARKER_HEADER_SECRET = "<REDACTED:header.secret>"
COOKIE_REDACTION_MARKER_PREFIX = "<REDACTED:cookie."
REDACTION_MARKER = REDACTION_MARKER_AUTHORIZATION_BEARER
APPROVED_REDACTION_MARKERS = frozenset(
    (
        REDACTION_MARKER_AUTHORIZATION_BEARER,
        REDACTION_MARKER_AUTHORIZATION_BASIC,
        REDACTION_MARKER_AUTHORIZATION_CREDENTIALS,
    )
)
APPROVED_COOKIE_REDACTION_MARKERS = frozenset(
    (
        REDACTION_MARKER_COOKIE_VALUE,
        REDACTION_MARKER_COOKIE_HEADER,
    )
)
COOKIE_HEADER_NAME = "Cookie"
HTTP_TOKEN_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
ASCII_ALPHANUMERIC_CHARACTERS = frozenset("0123456789abcdefghijklmnopqrstuvwxyz")
COOKIE_CATEGORY_SENSITIVE = "sensitive"
COOKIE_CATEGORY_TELEMETRY = "telemetry"
COOKIE_CATEGORY_HARMLESS = "harmless"
COOKIE_CATEGORY_UNKNOWN = "unknown"
SENSITIVE_COOKIE_NAMES = frozenset(
    (
        "session",
        "sessionid",
        "session_id",
        "sid",
        "auth",
        "auth_token",
        "access_token",
        "refresh_token",
        "token",
        "jwt",
        "sso",
        "sso_state",
        "username",
        "user",
        "userid",
        "user_id",
        "email",
        "identity",
        "account",
        "account_id",
        "customer",
        "customer_id",
        "tenant",
        "tenant_id",
        "portalauth",
        "asp.net_sessionid",
        "jsessionid",
        "phpsessid",
        "connect.sid",
        "laravel_session",
    )
)
TELEMETRY_COOKIE_NAMES = frozenset(
    (
        "_ga",
        "_gid",
        "_gat",
        "_fbp",
        "_fbc",
        "_hjid",
        "_clck",
        "_clsk",
        "ajs_anonymous_id",
        "ajs_user_id",
        "_mkto_trk",
        "hubspotutk",
        "__hstc",
        "__hssc",
        "__hssrc",
    )
)
TELEMETRY_COOKIE_PREFIXES = (
    "_ga_",
    "_gat_",
    "_hjsession_",
    "_hjsessionuser_",
    "amplitude_",
    "amp_",
    "mp_",
)
HARMLESS_COOKIE_NAMES = frozenset(("theme", "color_scheme", "display_mode"))
SENSITIVE_ASPSESSIONID_PREFIX = "aspsessionid"
SENSITIVE_REMEMBER_WEB_PREFIX = "remember_web_"
_SENSITIVE_HEADER_NAMES = frozenset(
    (
        "x-api-key",
        "api-key",
        "apikey",
        "x-apikey",
        "api_key",
        "x-api_key",
        "x-auth-token",
        "auth-token",
        "x-access-token",
        "access-token",
        "x-session-token",
        "session-token",
        "x-id-token",
        "id-token",
        "x-refresh-token",
        "refresh-token",
        "x-csrf-token",
        "csrf-token",
        "x-xsrf-token",
        "xsrf-token",
        "x-csrftoken",
        "csrftoken",
        "x-xsrftoken",
        "x-csrf",
        "csrf",
        "x-amz-security-token",
        "x-amz-credential",
        "x-amz-signature",
        "x-goog-api-key",
        "x-goog-signature",
        "x-ms-token-aad-access-token",
        "x-secret",
        "x-client-secret",
        "client-secret",
    )
)

EXIT_INTERNAL_ERROR = 1
EXIT_UNSAFE_PATH = 3
EXIT_INPUT_ERROR = 4
EXIT_OUTPUT_ERROR = 5

AUTHORIZATION_HEADER_PATTERN = re.compile(
    r"^Authorization[ \t]*:[ \t]*"
    r"(?P<scheme>[!#$%&'*+\-.^_`|~0-9A-Za-z]+)"
    r"[ \t]+"
    r"(?P<credential_section>[^\r\n]*)"
    r"(?=\r?\n|$)",
    re.IGNORECASE | re.MULTILINE | re.ASCII,
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


@dataclass(frozen=True)
class _ParsedCookieValue:
    """Transient parsed Cookie name and value span for classification."""

    name: str
    value_start: int
    value_end: int


def find_authorization_credentials(text: str) -> tuple[Finding, ...]:
    """Find HTTP-style Authorization credentials for milestone 2."""
    findings: list[Finding] = []

    # Milestone 2 intentionally treats any exact header-like line as a header;
    # full HTTP message parsing and body-boundary awareness are deferred.
    for match in AUTHORIZATION_HEADER_PATTERN.finditer(text):
        credential_section = match.group("credential_section")
        credential = credential_section.rstrip(" \t")
        if not credential or credential in APPROVED_REDACTION_MARKERS:
            continue

        scheme = match.group("scheme").lower()
        if scheme == "bearer":
            if not _is_single_credential_token(credential):
                continue
            rule_id = RULE_ID_AUTHORIZATION_BEARER
            replacement = REDACTION_MARKER_AUTHORIZATION_BEARER
        elif scheme == "basic":
            if not _is_single_credential_token(credential):
                continue
            rule_id = RULE_ID_AUTHORIZATION_BASIC
            replacement = REDACTION_MARKER_AUTHORIZATION_BASIC
        else:
            rule_id = RULE_ID_AUTHORIZATION_OTHER
            replacement = REDACTION_MARKER_AUTHORIZATION_CREDENTIALS

        start = match.start("credential_section")

        findings.append(
            Finding(
                rule_id=rule_id,
                start=start,
                end=start + len(credential),
                replacement=replacement,
            )
        )

    return tuple(findings)


def find_cookie_values(text: str) -> tuple[Finding, ...]:
    """Find exact line-start HTTP request Cookie header values."""
    findings: list[Finding] = []

    # Milestone 3 intentionally remains line-oriented. Full HTTP message
    # parsing and folded-header parsing are deferred.
    for line_start, line_content_end, next_line_start in _iter_physical_lines(text):
        line = text[line_start:line_content_end]
        value_start_in_line = _cookie_header_value_start(line)
        if value_start_in_line is None:
            continue
        if next_line_start < len(text) and text[next_line_start] in " \t":
            continue

        value_start = line_start + value_start_in_line
        header_value = text[value_start:line_content_end]
        trimmed_value_length = len(header_value.rstrip(" \t"))
        if trimmed_value_length == 0:
            continue

        trimmed_value = header_value[:trimmed_value_length]
        if trimmed_value in APPROVED_COOKIE_REDACTION_MARKERS:
            continue

        parsed_values = _parse_cookie_values(trimmed_value)
        if parsed_values is None:
            findings.append(
                Finding(
                    rule_id=RULE_ID_COOKIE_HEADER,
                    start=value_start,
                    end=value_start + trimmed_value_length,
                    replacement=REDACTION_MARKER_COOKIE_HEADER,
                )
            )
            continue

        for parsed_value in parsed_values:
            value = trimmed_value[parsed_value.value_start : parsed_value.value_end]
            if value in APPROVED_COOKIE_REDACTION_MARKERS:
                continue
            if _contains_cookie_redaction_marker_like(value):
                should_redact = True
            else:
                should_redact = (
                    _classify_cookie_name(parsed_value.name) != COOKIE_CATEGORY_HARMLESS
                )
            if not should_redact:
                continue
            findings.append(
                Finding(
                    rule_id=RULE_ID_COOKIE_VALUE,
                    start=value_start + parsed_value.value_start,
                    end=value_start + parsed_value.value_end,
                    replacement=REDACTION_MARKER_COOKIE_VALUE,
                )
            )

    return tuple(findings)


def _find_sensitive_header_values(text: str) -> tuple[Finding, ...]:
    """Find selected sensitive HTTP-like header values."""
    findings: list[Finding] = []

    for line_start, line_content_end, next_line_start in _iter_physical_lines(text):
        line = text[line_start:line_content_end]
        position = 0
        while position < len(line) and line[position] not in " \t:":
            position += 1

        header_name = line[:position]
        if header_name.lower() not in _SENSITIVE_HEADER_NAMES:
            continue

        while position < len(line) and line[position] in " \t":
            position += 1
        if position >= len(line) or line[position] != ":":
            continue

        if next_line_start < len(text) and text[next_line_start] in " \t":
            continue

        position += 1
        while position < len(line) and line[position] in " \t":
            position += 1

        value_start = line_start + position
        header_value = text[value_start:line_content_end]
        trimmed_value_length = len(header_value.rstrip(" \t"))
        if trimmed_value_length == 0:
            continue

        trimmed_value = header_value[:trimmed_value_length]
        if trimmed_value == REDACTION_MARKER_HEADER_SECRET:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID_HEADER_SECRET,
                start=value_start,
                end=value_start + trimmed_value_length,
                replacement=REDACTION_MARKER_HEADER_SECRET,
            )
        )

    return tuple(findings)


def _iter_physical_lines(text: str) -> tuple[tuple[int, int, int], ...]:
    """Return physical lines as start, content end, and next-line start."""
    lines: list[tuple[int, int, int]] = []
    position = 0

    while position < len(text):
        line_start = position
        while position < len(text) and text[position] not in "\r\n":
            position += 1
        line_content_end = position

        if position < len(text):
            if text[position] == "\r" and position + 1 < len(text):
                if text[position + 1] == "\n":
                    position += 2
                else:
                    position += 1
            else:
                position += 1

        lines.append((line_start, line_content_end, position))

    return tuple(lines)


def _cookie_header_value_start(line: str) -> int | None:
    """Return the Cookie value start offset within a physical line."""
    if len(line) < len(COOKIE_HEADER_NAME):
        return None
    if line[: len(COOKIE_HEADER_NAME)].lower() != COOKIE_HEADER_NAME.lower():
        return None

    position = len(COOKIE_HEADER_NAME)
    while position < len(line) and line[position] in " \t":
        position += 1
    if position >= len(line) or line[position] != ":":
        return None

    position += 1
    while position < len(line) and line[position] in " \t":
        position += 1
    return position


def _parse_cookie_values(value: str) -> tuple[_ParsedCookieValue, ...] | None:
    """Parse a complete Cookie value for later name-only classification."""
    parsed_values: list[_ParsedCookieValue] = []
    position = 0

    while position < len(value):
        name_start = position
        while position < len(value) and value[position] not in " \t=;":
            position += 1
        name = value[name_start:position]
        if not _is_cookie_name(name):
            return None

        while position < len(value) and value[position] in " \t":
            position += 1
        if position >= len(value) or value[position] != "=":
            return None

        position += 1
        while position < len(value) and value[position] in " \t":
            position += 1

        if position < len(value) and value[position] == '"':
            parsed = _parse_quoted_cookie_value(value, position)
        else:
            parsed = _parse_unquoted_cookie_value(value, position)
        if parsed is None:
            return None

        value_start, value_end, position = parsed
        parsed_values.append(
            _ParsedCookieValue(
                name=name,
                value_start=value_start,
                value_end=value_end,
            )
        )

        if position == len(value):
            break
        if value[position] != ";":
            return None

        position += 1
        while position < len(value) and value[position] in " \t":
            position += 1
        if position >= len(value):
            return None

    return tuple(parsed_values) if parsed_values else None


def _classify_cookie_name(name: str) -> str:
    """Classify an already validated Cookie name using approved name rules."""
    normalized = name.lower()

    if normalized in SENSITIVE_COOKIE_NAMES:
        return COOKIE_CATEGORY_SENSITIVE
    if _is_sensitive_cookie_family(normalized):
        return COOKIE_CATEGORY_SENSITIVE
    if normalized in TELEMETRY_COOKIE_NAMES:
        return COOKIE_CATEGORY_TELEMETRY
    if any(
        normalized.startswith(prefix) and len(normalized) > len(prefix)
        for prefix in TELEMETRY_COOKIE_PREFIXES
    ):
        return COOKIE_CATEGORY_TELEMETRY
    if normalized in HARMLESS_COOKIE_NAMES:
        return COOKIE_CATEGORY_HARMLESS
    return COOKIE_CATEGORY_UNKNOWN


def _contains_cookie_redaction_marker_like(value: str) -> bool:
    """Return whether a raw Cookie value contains a Cookie marker form."""
    if any(marker in value for marker in APPROVED_COOKIE_REDACTION_MARKERS):
        return True

    position = value.find(COOKIE_REDACTION_MARKER_PREFIX)
    while position != -1:
        marker_end = value.find(">", position + len(COOKIE_REDACTION_MARKER_PREFIX))
        if marker_end != -1:
            return True
        position = value.find(COOKIE_REDACTION_MARKER_PREFIX, position + 1)

    return False


def _is_sensitive_cookie_family(normalized_name: str) -> bool:
    """Return whether a lower-case Cookie name matches a sensitive family."""
    if normalized_name.startswith(SENSITIVE_ASPSESSIONID_PREFIX):
        suffix = normalized_name[len(SENSITIVE_ASPSESSIONID_PREFIX) :]
        return all(character in ASCII_ALPHANUMERIC_CHARACTERS for character in suffix)
    if normalized_name.startswith(SENSITIVE_REMEMBER_WEB_PREFIX):
        suffix = normalized_name[len(SENSITIVE_REMEMBER_WEB_PREFIX) :]
        return bool(suffix) and all(
            character in HTTP_TOKEN_CHARACTERS for character in suffix
        )
    return False


def _parse_quoted_cookie_value(
    value: str, quote_start: int
) -> tuple[int, int, int] | None:
    """Parse a quoted cookie value without decoding or normalizing it."""
    payload_start = quote_start + 1
    position = payload_start

    while position < len(value):
        character = value[position]
        if character == '"':
            payload_end = position
            position += 1
            while position < len(value) and value[position] in " \t":
                position += 1
            if position < len(value) and value[position] != ";":
                return None
            return payload_start, payload_end, position
        if character == "\\":
            if position + 1 >= len(value):
                return None
            escaped = value[position + 1]
            if _is_unsupported_cookie_control(escaped):
                return None
            position += 2
            continue
        if _is_unsupported_cookie_control(character):
            return None
        position += 1

    return None


def _parse_unquoted_cookie_value(
    value: str, value_start: int
) -> tuple[int, int, int] | None:
    """Parse an unquoted cookie value up to a semicolon or value end."""
    position = value_start
    while position < len(value) and value[position] != ";":
        position += 1

    value_end = position
    while value_end > value_start and value[value_end - 1] in " \t":
        value_end -= 1
    for character in value[value_start:value_end]:
        if character in " \t" or _is_unsupported_cookie_control(character):
            return None

    return value_start, value_end, position


def _is_cookie_name(value: str) -> bool:
    """Return whether a cookie name uses the approved ASCII token grammar."""
    return bool(value) and all(
        character in HTTP_TOKEN_CHARACTERS for character in value
    )


def _is_unsupported_cookie_control(character: str) -> bool:
    """Return whether a Cookie value character is an unsupported control."""
    codepoint = ord(character)
    return codepoint < 32 or codepoint == 127


def _is_single_credential_token(value: str) -> bool:
    """Return whether a specialized credential is one non-whitespace token."""
    return not any(character.isspace() for character in value)


def find_authorization_bearer(text: str) -> tuple[Finding, ...]:
    """Find HTTP-style Authorization: Bearer credentials."""
    return tuple(
        finding
        for finding in find_authorization_credentials(text)
        if finding.rule_id == RULE_ID_AUTHORIZATION_BEARER
    )


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
    """Sanitize decoded text with the approved rules."""
    findings = (
        find_authorization_credentials(text)
        + find_cookie_values(text)
        + _find_sensitive_header_values(text)
    )
    sanitized = apply_findings(text, findings)
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1

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
    """Run sanitization for one input file."""
    validate_paths(input_path, output_path)
    decoded = read_input_file(input_path)
    sanitized, report = sanitize_text(decoded.text)

    if dry_run:
        return SanitizationResult(report=report, output_written=False)

    write_output_exclusive(output_path, sanitized, decoded.had_bom)
    return SanitizationResult(report=report, output_written=True)
