"""Unit tests for the milestone 1 bearer authorization rule."""

from __future__ import annotations

import time

import pytest

from evidence_sanitizer.sanitizer import (
    EXIT_INTERNAL_ERROR,
    REDACTION_MARKER,
    RULE_ID_AUTHORIZATION_BEARER,
    Finding,
    SafeError,
    apply_findings,
    find_authorization_bearer,
    sanitize_text,
)

TOKEN = "synthetic-token-123"
SECOND_TOKEN = "second.synthetic-token"


def assert_sanitized(
    source: str, expected: str, tokens: tuple[str, ...] = (TOKEN,)
) -> None:
    sanitized, report = sanitize_text(source)
    for token in tokens:
        if token in sanitized:
            pytest.fail("sanitized text leaked synthetic credential")
    assert sanitized == expected
    assert report.counts_by_rule == {RULE_ID_AUTHORIZATION_BEARER: len(tokens)}


def assert_unchanged(source: str) -> None:
    sanitized, report = sanitize_text(source)
    if sanitized != source:
        pytest.fail("text changed unexpectedly")
    assert report.counts_by_rule == {}
    assert not report.changed


def test_standard_header() -> None:
    assert_sanitized(
        f"Authorization: Bearer {TOKEN}\n",
        f"Authorization: Bearer {REDACTION_MARKER}\n",
    )


def test_case_insensitive_header_name() -> None:
    assert_sanitized(
        f"authorization: Bearer {TOKEN}\n",
        f"authorization: Bearer {REDACTION_MARKER}\n",
    )


def test_case_insensitive_bearer_scheme() -> None:
    assert_sanitized(
        f"Authorization: bearer {TOKEN}\n",
        f"Authorization: bearer {REDACTION_MARKER}\n",
    )


def test_preserved_spacing_and_tabs() -> None:
    cases = (
        (
            f"Authorization:Bearer {TOKEN}\n",
            f"Authorization:Bearer {REDACTION_MARKER}\n",
        ),
        (
            f"Authorization : Bearer {TOKEN}\n",
            f"Authorization : Bearer {REDACTION_MARKER}\n",
        ),
        (
            f"Authorization:    Bearer    {TOKEN}\n",
            f"Authorization:    Bearer    {REDACTION_MARKER}\n",
        ),
        (
            f"Authorization:\tBearer\t{TOKEN}\n",
            f"Authorization:\tBearer\t{REDACTION_MARKER}\n",
        ),
    )
    for source, expected in cases:
        assert_sanitized(source, expected)


def test_lf_crlf_and_final_line_without_newline() -> None:
    assert_sanitized(
        f"GET / HTTP/1.1\nAuthorization: Bearer {TOKEN}\n",
        f"GET / HTTP/1.1\nAuthorization: Bearer {REDACTION_MARKER}\n",
    )
    assert_sanitized(
        f"GET / HTTP/1.1\r\nAuthorization: Bearer {TOKEN}\r\n",
        f"GET / HTTP/1.1\r\nAuthorization: Bearer {REDACTION_MARKER}\r\n",
    )
    assert_sanitized(
        f"Authorization: Bearer {TOKEN}",
        f"Authorization: Bearer {REDACTION_MARKER}",
    )


def test_multiple_bearer_headers() -> None:
    source = (
        f"Authorization: Bearer {TOKEN}\n"
        "Accept: application/json\n"
        f"Authorization: Bearer {SECOND_TOKEN}\n"
    )
    expected = (
        f"Authorization: Bearer {REDACTION_MARKER}\n"
        "Accept: application/json\n"
        f"Authorization: Bearer {REDACTION_MARKER}\n"
    )

    assert_sanitized(source, expected, tokens=(TOKEN, SECOND_TOKEN))


def test_punctuation_credentials_and_trailing_spaces() -> None:
    cases = (
        "abc.def.ghi",
        "abc+/=~",
        "token-with_punctuation",
    )
    for token in cases:
        sanitized, report = sanitize_text(f"Authorization: Bearer {token}   \n")
        if token in sanitized:
            pytest.fail("sanitized text leaked synthetic credential")
        assert sanitized == f"Authorization: Bearer {REDACTION_MARKER}   \n"
        assert report.counts_by_rule == {RULE_ID_AUTHORIZATION_BEARER: 1}


def test_already_redacted_marker_is_not_redacted_again() -> None:
    assert_unchanged(f"Authorization: Bearer {REDACTION_MARKER}\n")


def test_unrelated_prose_is_not_redacted() -> None:
    assert_unchanged("The documentation says to use Bearer authentication.\n")


def test_malformed_headers_do_not_match() -> None:
    cases = (
        " Authorization: Bearer abc123\n",
        "Authorization Bearer abc123\n",
        "Authorization: Basic abc123\n",
        "X-Authorization: Bearer abc123\n",
        "Authorization:Bearerabc123\n",
        "Authorization: Bearer this is explanatory prose\n",
        "Authorization: Bearer this\tprose\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_empty_or_whitespace_only_credentials_do_not_match() -> None:
    assert_unchanged("Authorization: Bearer\n")
    assert_unchanged("Authorization: Bearer    \n")
    assert_unchanged("Authorization: Bearer\t\t\n")


def test_adversarial_long_header_line_is_bounded() -> None:
    source = "Authorization: Bearer " + ("a" * (1024 * 1024)) + " prose\n"

    started = time.perf_counter()
    findings = find_authorization_bearer(source)
    elapsed = time.perf_counter() - started

    assert findings == ()
    assert elapsed < 2.0


def test_findings_are_non_overlapping() -> None:
    findings = find_authorization_bearer(
        f"Authorization: Bearer {TOKEN}\nAuthorization: Bearer {SECOND_TOKEN}\n"
    )

    previous_end = 0
    for finding in findings:
        assert previous_end <= finding.start
        previous_end = finding.end


def test_overlapping_findings_are_internal_errors() -> None:
    findings = (
        Finding(RULE_ID_AUTHORIZATION_BEARER, 0, 3, REDACTION_MARKER),
        Finding(RULE_ID_AUTHORIZATION_BEARER, 2, 4, REDACTION_MARKER),
    )

    with pytest.raises(SafeError) as error_info:
        apply_findings("abcd", findings)

    assert error_info.value.exit_code == EXIT_INTERNAL_ERROR


def test_idempotence() -> None:
    source = f"Authorization: Bearer {TOKEN}\n"
    first, first_report = sanitize_text(source)
    second, second_report = sanitize_text(first)

    if TOKEN in first or TOKEN in second:
        pytest.fail("sanitized text leaked synthetic credential")
    assert first == second
    assert first_report.counts_by_rule == {RULE_ID_AUTHORIZATION_BEARER: 1}
    assert second_report.counts_by_rule == {}


def test_finding_does_not_store_original_credential() -> None:
    findings = find_authorization_bearer(f"Authorization: Bearer {TOKEN}\n")

    assert len(findings) == 1
    finding = findings[0]
    stored_values = (
        finding.rule_id,
        str(finding.start),
        str(finding.end),
        finding.replacement,
        repr(finding),
    )
    if any(TOKEN in value for value in stored_values):
        pytest.fail("finding stored synthetic credential")
