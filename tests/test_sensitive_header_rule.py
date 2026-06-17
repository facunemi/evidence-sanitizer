"""Unit tests for selected sensitive API/auth header sanitization."""

from __future__ import annotations

import pytest

from evidence_sanitizer.sanitizer import (
    REDACTION_MARKER,
    REDACTION_MARKER_AUTHORIZATION_BASIC,
    REDACTION_MARKER_COOKIE_VALUE,
    REDACTION_MARKER_HEADER_SECRET,
    RULE_ID_AUTHORIZATION_BEARER,
    RULE_ID_COOKIE_VALUE,
    RULE_ID_HEADER_SECRET,
    _find_sensitive_header_values,
    sanitize_text,
)

HEADER_VALUE = "synthetic-sensitive-header-value"
SECOND_HEADER_VALUE = "synthetic-second-sensitive-header-value"
AUTHORIZATION_VALUE = "synthetic-authorization-value"
COOKIE_VALUE = "synthetic-cookie-value"
APPROVED_HEADER_NAMES = (
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
NEAR_MISS_HEADER_NAMES = (
    "x-forwarded-for",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "x-client-ip",
    "x-client-id",
    "client-id",
    "x-tenant-id",
    "tenant-id",
    "x-user-id",
    "user-id",
    "proxy-authorization",
    "x-token",
    "token",
    "x-jwt",
    "jwt",
    "x-api-secret",
    "authorization-token",
    "x-api-key-name",
    "x-access-token-expires",
    "x-csrf-token-enabled",
    "monkey",
    "keyboard",
    "x-tokenizer-mode",
    "x-author-theme",
)


def assert_sanitized(
    source: str,
    expected: str,
    sensitive_values: tuple[str, ...] = (HEADER_VALUE,),
    counts_by_rule: dict[str, int] | None = None,
) -> None:
    sanitized, report = sanitize_text(source)
    for value in sensitive_values:
        if value and value in sanitized:
            pytest.fail("sanitized text leaked synthetic sensitive header value")
    assert sanitized == expected
    expected_counts = (
        {RULE_ID_HEADER_SECRET: len(sensitive_values)}
        if counts_by_rule is None
        else counts_by_rule
    )
    assert report.counts_by_rule == expected_counts
    assert report.changed == (sanitized != source)


def assert_unchanged(source: str) -> None:
    sanitized, report = sanitize_text(source)
    if sanitized != source:
        pytest.fail("text changed unexpectedly")
    assert report.counts_by_rule == {}
    assert not report.changed


@pytest.mark.parametrize("name", APPROVED_HEADER_NAMES)
def test_sensitive_header_redacts_every_approved_header_name(name: str) -> None:
    assert_sanitized(
        f"{name}: {HEADER_VALUE}\n",
        f"{name}: {REDACTION_MARKER_HEADER_SECRET}\n",
    )


def test_sensitive_header_name_matching_is_case_insensitive() -> None:
    assert_sanitized(
        f"X-aPi-KeY: {HEADER_VALUE}\n",
        f"X-aPi-KeY: {REDACTION_MARKER_HEADER_SECRET}\n",
    )


def test_sensitive_header_preserves_casing_and_spacing() -> None:
    assert_sanitized(
        f"X-API-Key \t: \t{HEADER_VALUE}\t \n",
        f"X-API-Key \t: \t{REDACTION_MARKER_HEADER_SECRET}\t \n",
    )


def test_sensitive_header_supports_final_line_without_newline() -> None:
    assert_sanitized(
        f"X-API-Key: {HEADER_VALUE}",
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}",
    )


def test_sensitive_header_preserves_lf_crlf_and_mixed_newlines() -> None:
    source = (
        f"X-API-Key: {HEADER_VALUE}\n"
        "Accept: application/json\r\n"
        f"X-Auth-Token:\t{SECOND_HEADER_VALUE}\r\n"
    )
    expected = (
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n"
        "Accept: application/json\r\n"
        f"X-Auth-Token:\t{REDACTION_MARKER_HEADER_SECRET}\r\n"
    )

    assert_sanitized(
        source,
        expected,
        sensitive_values=(HEADER_VALUE, SECOND_HEADER_VALUE),
        counts_by_rule={RULE_ID_HEADER_SECRET: 2},
    )


def test_sensitive_header_empty_and_whitespace_values_remain_unchanged() -> None:
    assert_unchanged("X-API-Key:\n")
    assert_unchanged("X-API-Key: \t \n")


def test_sensitive_header_exact_marker_is_idempotent() -> None:
    assert_unchanged(f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n")
    assert_unchanged(f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\t \n")


def test_sensitive_header_embedded_marker_is_redacted() -> None:
    value = f"prefix{REDACTION_MARKER_HEADER_SECRET}suffix"

    assert_sanitized(
        f"X-API-Key: {value}\n",
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n",
        sensitive_values=(value,),
    )


def test_sensitive_header_unapproved_marker_like_value_is_redacted() -> None:
    value = "<REDACTED:header.api_key>"

    assert_sanitized(
        f"X-API-Key: {value}\n",
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n",
        sensitive_values=(value,),
    )


@pytest.mark.parametrize("marker", (REDACTION_MARKER, REDACTION_MARKER_COOKIE_VALUE))
def test_sensitive_header_wrong_family_markers_are_redacted(marker: str) -> None:
    assert_sanitized(
        f"X-Auth-Token: {marker}\n",
        f"X-Auth-Token: {REDACTION_MARKER_HEADER_SECRET}\n",
        sensitive_values=(marker,),
    )


@pytest.mark.parametrize("name", NEAR_MISS_HEADER_NAMES)
def test_sensitive_header_near_miss_names_remain_unchanged(name: str) -> None:
    assert_unchanged(f"{name}: {HEADER_VALUE}\n")


def test_sensitive_header_indented_line_remains_unchanged() -> None:
    assert_unchanged(f" X-API-Key: {HEADER_VALUE}\n")


def test_sensitive_header_folded_form_remains_completely_unchanged() -> None:
    assert_unchanged(f"X-API-Key: {HEADER_VALUE}\n continued-value\n")


def test_sensitive_header_repeated_headers_count_per_changed_line() -> None:
    source = (
        f"X-API-Key: {HEADER_VALUE}\n"
        f"X-API-Key: {SECOND_HEADER_VALUE}\n"
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n"
    )
    expected = (
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n"
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n"
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n"
    )

    assert_sanitized(
        source,
        expected,
        sensitive_values=(HEADER_VALUE, SECOND_HEADER_VALUE),
        counts_by_rule={RULE_ID_HEADER_SECRET: 2},
    )


def test_sensitive_header_combines_with_authorization_and_cookie_findings() -> None:
    source = (
        f"Authorization: Bearer {AUTHORIZATION_VALUE}\n"
        f"Cookie: session={COOKIE_VALUE}\n"
        f"X-API-Key: {HEADER_VALUE}\n"
    )
    expected = (
        f"Authorization: Bearer {REDACTION_MARKER}\n"
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}\n"
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n"
    )

    assert_sanitized(
        source,
        expected,
        sensitive_values=(AUTHORIZATION_VALUE, COOKIE_VALUE, HEADER_VALUE),
        counts_by_rule={
            RULE_ID_AUTHORIZATION_BEARER: 1,
            RULE_ID_COOKIE_VALUE: 1,
            RULE_ID_HEADER_SECRET: 1,
        },
    )


def test_sensitive_header_finder_does_not_match_excluded_headers() -> None:
    source = (
        f"Authorization: Basic {HEADER_VALUE}\n"
        f"Cookie: session={HEADER_VALUE}\n"
        f"Set-Cookie: session={HEADER_VALUE}\n"
        f"Proxy-Authorization: Basic {HEADER_VALUE}\n"
    )

    assert _find_sensitive_header_values(source) == ()


def test_sensitive_header_findings_store_no_raw_value_or_header_name() -> None:
    source = f"X-API-Key: {HEADER_VALUE}\n"

    findings = _find_sensitive_header_values(source)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ID_HEADER_SECRET
    assert finding.replacement == REDACTION_MARKER_HEADER_SECRET
    assert finding.start == len("X-API-Key: ")
    assert finding.end == finding.start + len(HEADER_VALUE)
    finding_repr = repr(finding)
    if HEADER_VALUE in finding_repr or "X-API-Key" in finding_repr:
        pytest.fail("finding stored sensitive header value or header name")


def test_sensitive_header_basic_marker_like_value_is_redacted() -> None:
    assert_sanitized(
        f"X-API-Key: {REDACTION_MARKER_AUTHORIZATION_BASIC}\n",
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n",
        sensitive_values=(REDACTION_MARKER_AUTHORIZATION_BASIC,),
    )
