"""Behavioral tests for the CLI."""

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from evidence_sanitizer.sanitizer import (
    REDACTION_MARKER,
    REDACTION_MARKER_AUTHORIZATION_BASIC,
    REDACTION_MARKER_AUTHORIZATION_CREDENTIALS,
    REDACTION_MARKER_COOKIE_HEADER,
    REDACTION_MARKER_COOKIE_VALUE,
    REDACTION_MARKER_HEADER_SECRET,
    REDACTION_MARKER_JSON_VALUE,
    REDACTION_MARKER_QUERY_SECRET,
)

PRODUCT_DESCRIPTION = (
    "Local-first CLI for creating sanitized copies of authorized "
    "penetration-testing evidence."
)
ENTRYPOINTS = ("console", "module")
SYNTHETIC_CREDENTIAL = "eyJhbGciOiJIUzI1NiJ9.synthetic-token"
SYNTHETIC_BASIC_CREDENTIAL = "synthetic-basic-token+/="
SYNTHETIC_CUSTOM_CREDENTIAL = "appId:synthetic-signature:nonce:timestamp"
SYNTHETIC_COOKIE_VALUE = "synthetic-cookie-value"
SYNTHETIC_HARMLESS_COOKIE_VALUE = "synthetic-second-cookie-value"
SYNTHETIC_FALLBACK_COOKIE_VALUE = "synthetic-fallback-cookie-value"
SYNTHETIC_HEADER_SECRET_VALUE = "synthetic-sensitive-header-value"
SYNTHETIC_QUERY_VALUE = "synthetic-query-value"
SYNTHETIC_JSON_ACCESS_TOKEN = "synthetic-json-access-token"
SYNTHETIC_JSON_PASSWORD = "synthetic-json-password"
OUTPUT_FORBIDDEN_VALUES = (
    SYNTHETIC_CREDENTIAL,
    SYNTHETIC_BASIC_CREDENTIAL,
    SYNTHETIC_CUSTOM_CREDENTIAL,
    SYNTHETIC_COOKIE_VALUE,
    SYNTHETIC_FALLBACK_COOKIE_VALUE,
    SYNTHETIC_HEADER_SECRET_VALUE,
    SYNTHETIC_QUERY_VALUE,
    SYNTHETIC_JSON_ACCESS_TOKEN,
    SYNTHETIC_JSON_PASSWORD,
)
CLI_FORBIDDEN_VALUES = OUTPUT_FORBIDDEN_VALUES + (SYNTHETIC_HARMLESS_COOKIE_VALUE,)


def run_entrypoint(
    entrypoint: str, args: Sequence[str]
) -> subprocess.CompletedProcess[str]:
    if entrypoint == "console":
        command = ["evidence-sanitizer", *args]
    elif entrypoint == "module":
        command = [sys.executable, "-m", "evidence_sanitizer", *args]
    else:
        raise ValueError(f"unknown test entry point: {entrypoint}")

    return subprocess.run(command, capture_output=True, text=True, check=False)


def combined_output(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + result.stderr


def normalize_whitespace(text: str) -> str:
    return " ".join(text.split())


def assert_help_displayed(result: subprocess.CompletedProcess[str]) -> None:
    output = combined_output(result)
    assert result.returncode == 0, output
    assert PRODUCT_DESCRIPTION in normalize_whitespace(output)
    assert "--help" in output


def assert_rejected(
    result: subprocess.CompletedProcess[str], expected_text: str
) -> None:
    output = combined_output(result)
    assert result.returncode != 0, output
    assert expected_text in output


def assert_no_cli_leak(result: subprocess.CompletedProcess[str]) -> None:
    output = combined_output(result)
    if any(value in output for value in CLI_FORBIDDEN_VALUES):
        pytest.fail("CLI output leaked synthetic credential")


def assert_file_unchanged(path: Path, expected: bytes) -> None:
    if path.read_bytes() != expected:
        pytest.fail("source file changed")


def assert_output_bytes(path: Path, expected: bytes) -> None:
    actual = path.read_bytes()
    if any(value.encode() in actual for value in OUTPUT_FORBIDDEN_VALUES):
        pytest.fail("sanitized output leaked synthetic credential")
    assert actual == expected


def test_root_help_exits_zero_and_contains_description() -> None:
    for entrypoint in ENTRYPOINTS:
        assert_help_displayed(run_entrypoint(entrypoint, ["--help"]))


def test_console_script_and_module_help_are_consistent() -> None:
    console_result = run_entrypoint("console", ["--help"])
    module_result = run_entrypoint("module", ["--help"])

    assert console_result.returncode == module_result.returncode == 0
    for result in (console_result, module_result):
        output = combined_output(result)
        assert PRODUCT_DESCRIPTION in normalize_whitespace(output)
        assert "--help" in output


def test_no_argument_execution_displays_help_and_exits_zero() -> None:
    for entrypoint in ENTRYPOINTS:
        assert_help_displayed(run_entrypoint(entrypoint, []))


def test_sanitize_help_is_available() -> None:
    for entrypoint in ENTRYPOINTS:
        result = run_entrypoint(entrypoint, ["sanitize", "--help"])
        output = combined_output(result)

        assert result.returncode == 0, output
        assert "sanitize" in output
        assert "--output" in output
        assert "--dry-run" in output


def test_sanitize_success_for_console_and_module_entrypoints(tmp_path: Path) -> None:
    for entrypoint in ENTRYPOINTS:
        case_dir = tmp_path / entrypoint
        case_dir.mkdir()
        input_path = case_dir / "evidence.txt"
        output_path = case_dir / "evidence.sanitized.txt"
        source = (
            f"GET /api/profile?token={SYNTHETIC_QUERY_VALUE} HTTP/1.1\n"
            "Host: example.test\n"
            f"Cookie: session={SYNTHETIC_COOKIE_VALUE}; "
            f"theme={SYNTHETIC_HARMLESS_COOKIE_VALUE}\n"
            f"Cookie: bad={SYNTHETIC_FALLBACK_COOKIE_VALUE}; malformed\n"
            f"Authorization: Bearer {SYNTHETIC_CREDENTIAL}\n"
            f"Authorization: Basic {SYNTHETIC_BASIC_CREDENTIAL}\n"
            f"Authorization: AMX {SYNTHETIC_CUSTOM_CREDENTIAL}\n"
            f"X-API-Key: {SYNTHETIC_HEADER_SECRET_VALUE}\n"
            "Accept: application/json\n"
            f"Body: https://x.test/?api-key={SYNTHETIC_QUERY_VALUE}\n"
            f'JSON: {{"access_token":"{SYNTHETIC_JSON_ACCESS_TOKEN}",'
            f'"password":"{SYNTHETIC_JSON_PASSWORD}","user_id":"user-123"}}\n'
        ).encode()
        expected = (
            f"GET /api/profile?token={REDACTION_MARKER_QUERY_SECRET} HTTP/1.1\n"
            "Host: example.test\n"
            f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}; "
            f"theme={SYNTHETIC_HARMLESS_COOKIE_VALUE}\n"
            f"Cookie: {REDACTION_MARKER_COOKIE_HEADER}\n"
            f"Authorization: Bearer {REDACTION_MARKER}\n"
            f"Authorization: Basic {REDACTION_MARKER_AUTHORIZATION_BASIC}\n"
            "Authorization: AMX "
            f"{REDACTION_MARKER_AUTHORIZATION_CREDENTIALS}\n"
            f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n"
            "Accept: application/json\n"
            f"Body: https://x.test/?api-key={REDACTION_MARKER_QUERY_SECRET}\n"
            f'JSON: {{"access_token":"{REDACTION_MARKER_JSON_VALUE}",'
            f'"password":"{REDACTION_MARKER_JSON_VALUE}","user_id":"user-123"}}\n'
        ).encode()
        input_path.write_bytes(source)

        result = run_entrypoint(
            entrypoint, ["sanitize", str(input_path), "--output", str(output_path)]
        )

        assert_no_cli_leak(result)
        assert result.returncode == 0
        output = combined_output(result)
        assert "Rules triggered:" in output
        assert "authorization.basic: 1" in output
        assert "authorization.bearer: 1" in output
        assert "authorization.other: 1" in output
        assert "cookie.header: 1" in output
        assert "cookie.value: 1" in output
        assert "header.secret: 1" in output
        assert "json.value: 2" in output
        assert "query.secret: 2" in output
        assert "Authorization:" not in output
        assert "Cookie:" not in output
        assert "X-API-Key:" not in output
        assert "access_token" not in output
        assert "password" not in output
        assert_output_bytes(output_path, expected)
        assert_file_unchanged(input_path, source)


def test_sanitize_dry_run_reports_counts_without_creating_output(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    input_path.write_text(
        f"Cookie: session={SYNTHETIC_COOKIE_VALUE}\n"
        f"Authorization: Bearer {SYNTHETIC_CREDENTIAL}\n"
        f"X-Auth-Token: {SYNTHETIC_HEADER_SECRET_VALUE}\n"
        f'{{"token":"{SYNTHETIC_JSON_ACCESS_TOKEN}"}}\n',
        encoding="utf-8",
    )

    result = run_entrypoint(
        "console",
        ["sanitize", str(input_path), "--output", str(output_path), "--dry-run"],
    )

    assert_no_cli_leak(result)
    assert result.returncode == 0
    output = combined_output(result)
    assert "Dry run: no output written" in output
    assert "authorization.bearer: 1" in output
    assert "cookie.value: 1" in output
    assert "header.secret: 1" in output
    assert "json.value: 1" in output
    assert "token:" not in output
    assert not output_path.exists()


def test_sanitize_no_match_succeeds_and_reports_none(tmp_path: Path) -> None:
    input_path = tmp_path / "notes.txt"
    output_path = tmp_path / "notes.sanitized.txt"
    source = (
        b"The documentation says to use Bearer authentication and Cookie headers.\n"
    )
    input_path.write_bytes(source)

    result = run_entrypoint(
        "console", ["sanitize", str(input_path), "--output", str(output_path)]
    )

    assert result.returncode == 0, combined_output(result)
    assert "Rules triggered: none" in combined_output(result)
    assert output_path.read_bytes() == source


def test_sanitize_requires_output_option(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    input_path.write_text("no findings\n", encoding="utf-8")

    result = run_entrypoint("console", ["sanitize", str(input_path)])

    assert result.returncode == 2, combined_output(result)
    assert "output" in combined_output(result).lower()


def test_sanitize_rejects_extra_input_argument(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    extra_path = tmp_path / "extra.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    input_path.write_text("no findings\n", encoding="utf-8")
    extra_path.write_text("no findings\n", encoding="utf-8")

    result = run_entrypoint(
        "console",
        ["sanitize", str(input_path), str(extra_path), "--output", str(output_path)],
    )

    assert result.returncode == 2, combined_output(result)


def test_sanitize_existing_output_exits_three_without_leaking(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "evidence.txt"
    output_path = tmp_path / "evidence.sanitized.txt"
    input_path.write_text(
        f"Authorization: Bearer {SYNTHETIC_CREDENTIAL}\n", encoding="utf-8"
    )
    output_path.write_text("existing\n", encoding="utf-8")

    result = run_entrypoint(
        "console", ["sanitize", str(input_path), "--output", str(output_path)]
    )

    assert_no_cli_leak(result)
    assert result.returncode == 3
    assert "output file already exists" in combined_output(result)


def test_sanitize_invalid_input_exits_four(tmp_path: Path) -> None:
    input_path = tmp_path / "invalid.bin"
    output_path = tmp_path / "invalid.sanitized.txt"
    input_path.write_bytes(b"\xff")

    result = run_entrypoint(
        "console", ["sanitize", str(input_path), "--output", str(output_path)]
    )

    assert result.returncode == 4, combined_output(result)
    assert "valid UTF-8" in combined_output(result)


def test_root_does_not_accept_sanitize_options() -> None:
    for entrypoint in ENTRYPOINTS:
        for option in ("--output", "--dry-run"):
            assert_rejected(run_entrypoint(entrypoint, [option]), option)
