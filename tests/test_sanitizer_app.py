"""Application-level tests for sanitization."""

from __future__ import annotations

import codecs
from pathlib import Path
from typing import Any

import pytest

from evidence_sanitizer.sanitizer import (
    EXIT_INPUT_ERROR,
    EXIT_OUTPUT_ERROR,
    EXIT_UNSAFE_PATH,
    MAX_INPUT_BYTES,
    REDACTION_MARKER,
    REDACTION_MARKER_AUTHORIZATION_BASIC,
    REDACTION_MARKER_AUTHORIZATION_CREDENTIALS,
    REDACTION_MARKER_COOKIE_HEADER,
    REDACTION_MARKER_COOKIE_VALUE,
    REDACTION_MARKER_HEADER_SECRET,
    REDACTION_MARKER_JSON_VALUE,
    REDACTION_MARKER_QUERY_SECRET,
    RULE_ID_AUTHORIZATION_BASIC,
    RULE_ID_AUTHORIZATION_BEARER,
    RULE_ID_AUTHORIZATION_OTHER,
    RULE_ID_COOKIE_HEADER,
    RULE_ID_COOKIE_VALUE,
    RULE_ID_HEADER_SECRET,
    RULE_ID_JSON_VALUE,
    RULE_ID_QUERY_SECRET,
    SafeError,
    sanitize_file,
)

TOKEN = "eyJhbGciOiJIUzI1NiJ9.synthetic-token"
BASIC_TOKEN = "synthetic-basic-token+/="
CUSTOM_CREDENTIAL = "appId:synthetic-signature:nonce:timestamp"
COOKIE_SESSION_VALUE = "synthetic-cookie-session"
COOKIE_HARMLESS_THEME_VALUE = "synthetic-cookie-theme"
COOKIE_FALLBACK_VALUE = "synthetic-cookie-fallback"
COOKIE_FALLBACK_THEME_VALUE = "synthetic-cookie-fallback-theme"
HEADER_SECRET_VALUE = "synthetic-sensitive-header-value"
QUERY_ACCESS_TOKEN = "synthetic-query-access-token"
QUERY_REQUEST_SIG = "synthetic-query-request-sig"
QUERY_COOKIE_SIG = "synthetic-query-cookie-sig"
QUERY_LOCATION_TOKEN = "synthetic-query-location-token"
QUERY_HEADER_JWT = "synthetic-query-header-jwt"
QUERY_BODY_API_KEY = "synthetic-query-body-api-key"
QUERY_BODY_CLIENT_SECRET = "synthetic-query-body-client-secret"
QUERY_BODY_SIGNATURE = "synthetic-query-body-signature"
QUERY_EMBEDDED = f"prefix{REDACTION_MARKER_QUERY_SECRET}suffix"
QUERY_NEAR_MISS = "synthetic-query-near-miss"
JSON_ACCESS_TOKEN = "synthetic-json-access-token"
JSON_PASSWORD = "synthetic-json-password"
SENSITIVE_VALUES = (
    TOKEN,
    BASIC_TOKEN,
    CUSTOM_CREDENTIAL,
    COOKIE_SESSION_VALUE,
    COOKIE_FALLBACK_VALUE,
    COOKIE_FALLBACK_THEME_VALUE,
    HEADER_SECRET_VALUE,
    QUERY_ACCESS_TOKEN,
    QUERY_REQUEST_SIG,
    QUERY_COOKIE_SIG,
    QUERY_LOCATION_TOKEN,
    QUERY_HEADER_JWT,
    QUERY_BODY_API_KEY,
    QUERY_BODY_CLIENT_SECRET,
    QUERY_BODY_SIGNATURE,
    QUERY_EMBEDDED,
    JSON_ACCESS_TOKEN,
    JSON_PASSWORD,
)


def assert_source_unchanged(path: Path, expected: bytes) -> None:
    if path.read_bytes() != expected:
        pytest.fail("source file changed")


def assert_sanitized_output(path: Path, expected: bytes) -> None:
    actual = path.read_bytes()
    if any(value.encode() in actual for value in SENSITIVE_VALUES):
        pytest.fail("sanitized output leaked synthetic credential")
    assert actual == expected


def test_source_unchanged_and_sanitized_output_correct(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    source = (
        "GET /api/profile HTTP/1.1\n"
        "Host: example.test\n"
        f"Authorization: Bearer {TOKEN}\n"
        "Accept: application/json\n"
    ).encode()
    expected = source.replace(TOKEN.encode(), REDACTION_MARKER.encode())
    input_path.write_bytes(source)

    result = sanitize_file(input_path, output_path, dry_run=False)

    assert result.output_written
    assert result.report.counts_by_rule == {RULE_ID_AUTHORIZATION_BEARER: 1}
    assert_sanitized_output(output_path, expected)
    assert_source_unchanged(input_path, source)


def test_multiple_authorization_schemes_sanitized_and_reported(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    source = (
        "GET /api/profile HTTP/1.1\n"
        "Host: example.test\n"
        f"Authorization: Bearer {TOKEN}\n"
        f"Authorization: Basic {BASIC_TOKEN}\n"
        f"Authorization: AMX {CUSTOM_CREDENTIAL}\n"
        "Accept: application/json\n"
    ).encode()
    expected = (
        "GET /api/profile HTTP/1.1\n"
        "Host: example.test\n"
        f"Authorization: Bearer {REDACTION_MARKER}\n"
        f"Authorization: Basic {REDACTION_MARKER_AUTHORIZATION_BASIC}\n"
        "Authorization: AMX "
        f"{REDACTION_MARKER_AUTHORIZATION_CREDENTIALS}\n"
        "Accept: application/json\n"
    ).encode()
    input_path.write_bytes(source)

    result = sanitize_file(input_path, output_path, dry_run=False)

    assert result.output_written
    assert result.report.counts_by_rule == {
        RULE_ID_AUTHORIZATION_BEARER: 1,
        RULE_ID_AUTHORIZATION_BASIC: 1,
        RULE_ID_AUTHORIZATION_OTHER: 1,
    }
    assert_sanitized_output(output_path, expected)
    assert_source_unchanged(input_path, source)


def test_authorization_and_cookie_headers_sanitized_and_reported(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    source = (
        "GET /api/profile HTTP/1.1\n"
        "Host: example.test\n"
        f"Cookie: session={COOKIE_SESSION_VALUE}; theme={COOKIE_HARMLESS_THEME_VALUE}\n"
        "Cookie: broken="
        f"{COOKIE_FALLBACK_VALUE}; malformed; theme={COOKIE_FALLBACK_THEME_VALUE}\n"
        f"Authorization: Bearer {TOKEN}\n"
        f"Authorization: Basic {BASIC_TOKEN}\n"
        f"Authorization: AMX {CUSTOM_CREDENTIAL}\n"
        f"X-API-Key: {HEADER_SECRET_VALUE}\n"
        "Accept: application/json\n"
    ).encode()
    expected = (
        "GET /api/profile HTTP/1.1\n"
        "Host: example.test\n"
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}; "
        f"theme={COOKIE_HARMLESS_THEME_VALUE}\n"
        f"Cookie: {REDACTION_MARKER_COOKIE_HEADER}\n"
        f"Authorization: Bearer {REDACTION_MARKER}\n"
        f"Authorization: Basic {REDACTION_MARKER_AUTHORIZATION_BASIC}\n"
        "Authorization: AMX "
        f"{REDACTION_MARKER_AUTHORIZATION_CREDENTIALS}\n"
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n"
        "Accept: application/json\n"
    ).encode()
    input_path.write_bytes(source)

    result = sanitize_file(input_path, output_path, dry_run=False)

    assert result.output_written
    assert result.report.counts_by_rule == {
        RULE_ID_COOKIE_VALUE: 1,
        RULE_ID_COOKIE_HEADER: 1,
        RULE_ID_AUTHORIZATION_BEARER: 1,
        RULE_ID_AUTHORIZATION_BASIC: 1,
        RULE_ID_AUTHORIZATION_OTHER: 1,
        RULE_ID_HEADER_SECRET: 1,
    }
    assert_sanitized_output(output_path, expected)
    assert_source_unchanged(input_path, source)


def test_milestone_9_combined_rule_integration(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    second_output_path = tmp_path / "evidence.sanitized-again.txt"
    source = (
        f"GET /oauth/callback?access_token={QUERY_ACCESS_TOKEN}"
        "&state=keep&code=keep HTTP/1.1\n"
        "Host: example.test\n"
        f"Authorization: Bearer {TOKEN}\n"
        f"Authorization: Basic {BASIC_TOKEN}\n"
        f"Authorization: AMX {CUSTOM_CREDENTIAL}\n"
        f"Cookie: session={COOKIE_SESSION_VALUE}; "
        f"theme=https://app.test/?sig={QUERY_COOKIE_SIG}\n"
        f"Cookie: broken={COOKIE_FALLBACK_VALUE}; malformed; "
        f"theme={COOKIE_FALLBACK_THEME_VALUE}\n"
        f"Referer: https://app.test/?signature={QUERY_REQUEST_SIG}\n"
        f"Location: /redirect?token={QUERY_LOCATION_TOKEN}\n"
        f"X-API-Key: https://api.test/?jwt={QUERY_HEADER_JWT}\n"
        "Accept: application/json\n"
        "Body: https://x.test/?"
        f"api-key={QUERY_BODY_API_KEY}&"
        f"client_secret={QUERY_BODY_CLIENT_SECRET}&"
        f"signature={QUERY_BODY_SIGNATURE}\n"
        f"?token={REDACTION_MARKER_QUERY_SECRET}\n"
        f"?token={QUERY_EMBEDDED}\n"
        f"?token={REDACTION_MARKER_HEADER_SECRET}\n"
        f"?access_token_expires={QUERY_NEAR_MISS}\n"
        f'Body: {{"access_token":"{JSON_ACCESS_TOKEN}",'
        f'"password":"{JSON_PASSWORD}","user_id":"user-123"}}\n'
    ).encode()
    expected = (
        "GET /oauth/callback?"
        f"access_token={REDACTION_MARKER_QUERY_SECRET}"
        "&state=keep&code=keep HTTP/1.1\n"
        "Host: example.test\n"
        f"Authorization: Bearer {REDACTION_MARKER}\n"
        f"Authorization: Basic {REDACTION_MARKER_AUTHORIZATION_BASIC}\n"
        "Authorization: AMX "
        f"{REDACTION_MARKER_AUTHORIZATION_CREDENTIALS}\n"
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}; "
        f"theme=https://app.test/?sig={REDACTION_MARKER_QUERY_SECRET}\n"
        f"Cookie: {REDACTION_MARKER_COOKIE_HEADER}\n"
        f"Referer: https://app.test/?signature={REDACTION_MARKER_QUERY_SECRET}\n"
        f"Location: /redirect?token={REDACTION_MARKER_QUERY_SECRET}\n"
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n"
        "Accept: application/json\n"
        "Body: https://x.test/?"
        f"api-key={REDACTION_MARKER_QUERY_SECRET}&"
        f"client_secret={REDACTION_MARKER_QUERY_SECRET}&"
        f"signature={REDACTION_MARKER_QUERY_SECRET}\n"
        f"?token={REDACTION_MARKER_QUERY_SECRET}\n"
        f"?token={REDACTION_MARKER_QUERY_SECRET}\n"
        f"?token={REDACTION_MARKER_QUERY_SECRET}\n"
        f"?access_token_expires={QUERY_NEAR_MISS}\n"
        f'Body: {{"access_token":"{REDACTION_MARKER_JSON_VALUE}",'
        f'"password":"{REDACTION_MARKER_JSON_VALUE}","user_id":"user-123"}}\n'
    ).encode()
    input_path.write_bytes(source)

    result = sanitize_file(input_path, output_path, dry_run=False)

    assert result.output_written
    assert result.report.counts_by_rule == {
        RULE_ID_AUTHORIZATION_BEARER: 1,
        RULE_ID_AUTHORIZATION_BASIC: 1,
        RULE_ID_AUTHORIZATION_OTHER: 1,
        RULE_ID_COOKIE_VALUE: 1,
        RULE_ID_COOKIE_HEADER: 1,
        RULE_ID_HEADER_SECRET: 1,
        RULE_ID_QUERY_SECRET: 9,
        RULE_ID_JSON_VALUE: 2,
    }
    assert_sanitized_output(output_path, expected)
    assert_source_unchanged(input_path, source)
    for name in (
        "access_token",
        "signature",
        "token",
        "api-key",
        "client_secret",
        "password",
    ):
        if any(name in rule_id for rule_id in result.report.counts_by_rule):
            pytest.fail("report included a query parameter or json field name")

    second_result = sanitize_file(output_path, second_output_path, dry_run=False)
    assert second_result.report.counts_by_rule == {}
    assert second_output_path.read_bytes() == output_path.read_bytes()

    dry_run_output_path = tmp_path / "dry-run.sanitized.txt"
    dry_run_result = sanitize_file(input_path, dry_run_output_path, dry_run=True)
    assert not dry_run_result.output_written
    assert not dry_run_output_path.exists()
    assert dry_run_result.report.counts_by_rule == {
        RULE_ID_AUTHORIZATION_BEARER: 1,
        RULE_ID_AUTHORIZATION_BASIC: 1,
        RULE_ID_AUTHORIZATION_OTHER: 1,
        RULE_ID_COOKIE_VALUE: 1,
        RULE_ID_COOKIE_HEADER: 1,
        RULE_ID_HEADER_SECRET: 1,
        RULE_ID_QUERY_SECRET: 9,
        RULE_ID_JSON_VALUE: 2,
    }


def test_output_created_only_on_success(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    input_path.write_bytes(b"invalid\x00input")

    with pytest.raises(SafeError) as error_info:
        sanitize_file(input_path, output_path, dry_run=False)

    assert error_info.value.exit_code == EXIT_INPUT_ERROR
    assert not output_path.exists()


def test_existing_output_rejected_and_not_overwritten(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    input_path.write_text(f"Authorization: Bearer {TOKEN}\n", encoding="utf-8")
    existing = b"existing output\n"
    output_path.write_bytes(existing)

    with pytest.raises(SafeError) as error_info:
        sanitize_file(input_path, output_path, dry_run=False)

    assert error_info.value.exit_code == EXIT_UNSAFE_PATH
    assert output_path.read_bytes() == existing


def test_missing_output_parent_rejected(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "missing" / "evidence.sanitized.txt"
    input_path.write_text("no findings\n", encoding="utf-8")

    with pytest.raises(SafeError) as error_info:
        sanitize_file(input_path, output_path, dry_run=False)

    assert error_info.value.exit_code == EXIT_UNSAFE_PATH


def test_same_textual_input_output_path_rejected(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    input_path.write_text("no findings\n", encoding="utf-8")

    with pytest.raises(SafeError) as error_info:
        sanitize_file(input_path, input_path, dry_run=False)

    assert error_info.value.exit_code == EXIT_UNSAFE_PATH


def test_input_symlink_to_regular_file_allowed(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    link_path = tmp_path / "evidence-link.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    source = f"Authorization: Bearer {TOKEN}\n".encode()
    expected = f"Authorization: Bearer {REDACTION_MARKER}\n".encode()
    input_path.write_bytes(source)
    try:
        link_path.symlink_to(input_path)
    except OSError:
        pytest.skip("symlink creation is not available on this platform")

    sanitize_file(link_path, output_path, dry_run=False)

    assert_sanitized_output(output_path, expected)
    assert_source_unchanged(input_path, source)


def test_input_directory_rejected(tmp_path: Path) -> None:
    output_path = tmp_path / "output.txt"

    with pytest.raises(SafeError) as error_info:
        sanitize_file(tmp_path, output_path, dry_run=False)

    assert error_info.value.exit_code == EXIT_INPUT_ERROR


def test_missing_input_rejected(tmp_path: Path) -> None:
    input_path = tmp_path / "missing.txt"
    output_path = tmp_path / "output.txt"

    with pytest.raises(SafeError) as error_info:
        sanitize_file(input_path, output_path, dry_run=False)

    assert error_info.value.exit_code == EXIT_INPUT_ERROR


def test_unreadable_input_behavior_is_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    input_path.write_text("no findings\n", encoding="utf-8")
    original_read_bytes = Path.read_bytes

    def fake_read_bytes(path: Path) -> bytes:
        if path == input_path:
            raise PermissionError("synthetic read failure")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fake_read_bytes)

    with pytest.raises(SafeError) as error_info:
        sanitize_file(input_path, output_path, dry_run=False)

    assert error_info.value.exit_code == EXIT_INPUT_ERROR
    assert "synthetic read failure" not in error_info.value.message
    assert not output_path.exists()


def test_dry_run_creates_no_output_and_reports_counts(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    source = (
        f"Cookie: session={COOKIE_SESSION_VALUE}\n"
        f"Authorization: Bearer {TOKEN}\n"
        f"X-API-Key: {HEADER_SECRET_VALUE}\n"
    ).encode()
    input_path.write_bytes(source)

    result = sanitize_file(input_path, output_path, dry_run=True)

    assert not result.output_written
    assert result.report.counts_by_rule == {
        RULE_ID_COOKIE_VALUE: 1,
        RULE_ID_AUTHORIZATION_BEARER: 1,
        RULE_ID_HEADER_SECRET: 1,
    }
    assert not output_path.exists()
    assert_source_unchanged(input_path, source)


def test_no_match_file_creates_identical_output(tmp_path: Path) -> None:
    input_path = tmp_path / "notes.txt"
    output_path = tmp_path / "notes.sanitized.txt"
    source = b"The documentation says to use Bearer authentication.\n"
    input_path.write_bytes(source)

    result = sanitize_file(input_path, output_path, dry_run=False)

    assert result.output_written
    assert result.report.counts_by_rule == {}
    assert output_path.read_bytes() == source


def test_utf8_bom_is_preserved(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    source_text = f"Cookie: session={COOKIE_SESSION_VALUE}\n"
    expected_text = f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}\n"
    source = codecs.BOM_UTF8 + source_text.encode()
    expected = codecs.BOM_UTF8 + expected_text.encode()
    input_path.write_bytes(source)

    sanitize_file(input_path, output_path, dry_run=False)

    assert_sanitized_output(output_path, expected)


def test_lf_crlf_and_final_newline_presence_are_preserved(tmp_path: Path) -> None:
    cases = (
        (
            f"Cookie: session={COOKIE_SESSION_VALUE}\nAccept: application/json\n",
            f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}\n"
            "Accept: application/json\n",
        ),
        (
            f"Cookie: session={COOKIE_SESSION_VALUE}\r\nAccept: application/json\r\n",
            f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}\r\n"
            "Accept: application/json\r\n",
        ),
        (
            f"Cookie: session={COOKIE_SESSION_VALUE}",
            f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}",
        ),
    )
    for index, (source_text, expected_text) in enumerate(cases):
        input_path = tmp_path / f"evidence-{index}.txt"
        output_path = tmp_path / f"evidence-{index}.sanitized.txt"
        input_path.write_bytes(source_text.encode())

        sanitize_file(input_path, output_path, dry_run=False)

        assert_sanitized_output(output_path, expected_text.encode())


def test_mixed_newlines_are_preserved_byte_for_byte(tmp_path: Path) -> None:
    input_path = tmp_path / "mixed-newlines.txt"
    output_path = tmp_path / "mixed-newlines.sanitized.txt"
    source = (
        b"GET /api/profile HTTP/1.1\r\n"
        b"Host: example.test\n"
        b"Cookie: session=" + COOKIE_SESSION_VALUE.encode() + b"\n"
        b"Authorization: Bearer " + TOKEN.encode() + b"\r\n"
        b"Accept: application/json\n"
        b"Final-Line: no-newline"
    )
    expected = (
        b"GET /api/profile HTTP/1.1\r\n"
        b"Host: example.test\n"
        b"Cookie: session=" + REDACTION_MARKER_COOKIE_VALUE.encode() + b"\n"
        b"Authorization: Bearer " + REDACTION_MARKER.encode() + b"\r\n"
        b"Accept: application/json\n"
        b"Final-Line: no-newline"
    )
    input_path.write_bytes(source)

    sanitize_file(input_path, output_path, dry_run=False)

    assert_sanitized_output(output_path, expected)
    assert_source_unchanged(input_path, source)


def test_file_level_idempotence(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    first_output_path = tmp_path / "evidence.sanitized.txt"
    second_output_path = tmp_path / "evidence.sanitized-again.txt"
    source = (
        f"Cookie: session={COOKIE_SESSION_VALUE}; theme={COOKIE_HARMLESS_THEME_VALUE}\n"
        f"Authorization: Bearer {TOKEN}\n"
        f"X-API-Key: {HEADER_SECRET_VALUE}\n"
    ).encode()
    input_path.write_bytes(source)

    first_result = sanitize_file(input_path, first_output_path, dry_run=False)
    first_output = first_output_path.read_bytes()
    second_result = sanitize_file(first_output_path, second_output_path, dry_run=False)

    assert first_result.report.counts_by_rule == {
        RULE_ID_COOKIE_VALUE: 1,
        RULE_ID_AUTHORIZATION_BEARER: 1,
        RULE_ID_HEADER_SECRET: 1,
    }
    assert second_result.report.counts_by_rule == {}
    assert second_output_path.read_bytes() == first_output
    assert_source_unchanged(input_path, source)


def test_nul_byte_input_rejected(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    input_path.write_bytes(b"abc\x00def")

    with pytest.raises(SafeError) as error_info:
        sanitize_file(input_path, output_path, dry_run=False)

    assert error_info.value.exit_code == EXIT_INPUT_ERROR
    assert not output_path.exists()


def test_invalid_utf8_rejected(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    invalid_bytes = b"\xff"
    input_path.write_bytes(invalid_bytes)

    with pytest.raises(SafeError) as error_info:
        sanitize_file(input_path, output_path, dry_run=False)

    error = error_info.value
    assert error.exit_code == EXIT_INPUT_ERROR
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__suppress_context__
    assert error.message == "input is not valid UTF-8"
    assert "0xff" not in error.message
    assert "position" not in error.message
    assert repr(invalid_bytes) not in error.message
    assert not output_path.exists()


def test_input_over_10_mib_rejected(tmp_path: Path) -> None:
    input_path = tmp_path / "large.txt"
    output_path = tmp_path / "large.sanitized.txt"
    input_path.write_bytes(b"a" * (MAX_INPUT_BYTES + 1))

    with pytest.raises(SafeError) as error_info:
        sanitize_file(input_path, output_path, dry_run=False)

    assert error_info.value.exit_code == EXIT_INPUT_ERROR
    assert not output_path.exists()


def test_controlled_write_failure_attempts_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    input_path.write_text(f"Authorization: Bearer {TOKEN}\n", encoding="utf-8")
    original_open = Path.open

    class FailingWriter:
        def __init__(self, path: Path) -> None:
            self.path = path
            self.file: Any = None

        def __enter__(self) -> FailingWriter:
            self.file = original_open(self.path, "xb")
            return self

        def write(self, data: bytes) -> int:
            self.file.write(data[:1])
            raise OSError("synthetic write failure")

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            self.file.close()

    def fake_open(path: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if path == output_path and mode == "xb":
            return FailingWriter(path)
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fake_open)

    with pytest.raises(SafeError) as error_info:
        sanitize_file(input_path, output_path, dry_run=False)

    assert error_info.value.exit_code == EXIT_OUTPUT_ERROR
    assert "synthetic write failure" not in error_info.value.message
    assert not output_path.exists()


def test_exclusive_create_rejects_racing_output_without_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    racing_content = b"racing destination\n"
    input_path.write_text(f"Authorization: Bearer {TOKEN}\n", encoding="utf-8")
    original_open = Path.open

    def fake_open(path: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if path == output_path and mode == "xb":
            with original_open(path, "wb") as racing_file:
                racing_file.write(racing_content)
            return original_open(path, mode, *args, **kwargs)
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fake_open)

    with pytest.raises(SafeError) as error_info:
        sanitize_file(input_path, output_path, dry_run=False)

    assert error_info.value.exit_code == EXIT_UNSAFE_PATH
    assert error_info.value.message == "output file already exists"
    assert output_path.read_bytes() == racing_content
