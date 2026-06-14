"""Unit tests for Cookie header sanitization rules."""

from __future__ import annotations

import time

import pytest

from evidence_sanitizer.sanitizer import (
    REDACTION_MARKER_COOKIE_HEADER,
    REDACTION_MARKER_COOKIE_VALUE,
    RULE_ID_AUTHORIZATION_BEARER,
    RULE_ID_COOKIE_HEADER,
    RULE_ID_COOKIE_VALUE,
    find_authorization_credentials,
    find_cookie_values,
    sanitize_text,
)

COOKIE_VALUE = "synthetic-cookie-value"
SECOND_COOKIE_VALUE = "synthetic-second-cookie-value"
THIRD_COOKIE_VALUE = "synthetic-third-cookie-value"
COOKIE_VALUE_WITH_EQUALS = "synthetic=a=b=c"
COOKIE_PUNCTUATION_VALUE = "synthetic,one:two/path!~()+[]"
COOKIE_NON_ASCII_VALUE = "synthetic-valüe"
COOKIE_EMBEDDED_MARKER_VALUE = f"prefix{REDACTION_MARKER_COOKIE_VALUE}suffix"


def assert_sanitized(
    source: str,
    expected: str,
    sensitive_values: tuple[str, ...],
    counts_by_rule: dict[str, int],
) -> None:
    sanitized, report = sanitize_text(source)
    for value in sensitive_values:
        if value and value in sanitized:
            pytest.fail("sanitized text leaked synthetic cookie value")
    assert sanitized == expected
    assert report.counts_by_rule == counts_by_rule
    assert report.changed == (sanitized != source)


def assert_unchanged(source: str) -> None:
    sanitized, report = sanitize_text(source)
    if sanitized != source:
        pytest.fail("text changed unexpectedly")
    assert report.counts_by_rule == {}
    assert not report.changed


def test_cookie_simple_one_pair() -> None:
    assert_sanitized(
        f"Cookie: session={COOKIE_VALUE}\n",
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}\n",
        (COOKIE_VALUE,),
        {RULE_ID_COOKIE_VALUE: 1},
    )


def test_cookie_multiple_pairs_preserve_names_order_and_counts() -> None:
    source = (
        f"Cookie: session={COOKIE_VALUE}; "
        f"username={SECOND_COOKIE_VALUE}; theme={THIRD_COOKIE_VALUE}\n"
    )
    expected = (
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}; "
        f"username={REDACTION_MARKER_COOKIE_VALUE}; "
        f"theme={REDACTION_MARKER_COOKIE_VALUE}\n"
    )

    assert_sanitized(
        source,
        expected,
        (COOKIE_VALUE, SECOND_COOKIE_VALUE, THIRD_COOKIE_VALUE),
        {RULE_ID_COOKIE_VALUE: 3},
    )


def test_cookie_case_insensitive_header_name() -> None:
    assert_sanitized(
        f"cOoKiE: session={COOKIE_VALUE}\n",
        f"cOoKiE: session={REDACTION_MARKER_COOKIE_VALUE}\n",
        (COOKIE_VALUE,),
        {RULE_ID_COOKIE_VALUE: 1},
    )


def test_cookie_preserves_spacing_tabs_and_duplicate_names() -> None:
    source = (
        f"Cookie\t :\t session \t = \t {COOKIE_VALUE} \t ;\t "
        f"session= {SECOND_COOKIE_VALUE}\t \n"
    )
    expected = (
        f"Cookie\t :\t session \t = \t {REDACTION_MARKER_COOKIE_VALUE} \t ;\t "
        f"session= {REDACTION_MARKER_COOKIE_VALUE}\t \n"
    )

    assert_sanitized(
        source,
        expected,
        (COOKIE_VALUE, SECOND_COOKIE_VALUE),
        {RULE_ID_COOKIE_VALUE: 2},
    )


def test_cookie_empty_values_are_redacted() -> None:
    assert_sanitized(
        "Cookie: session=; theme=\t \n",
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}; "
        f"theme={REDACTION_MARKER_COOKIE_VALUE}\t \n",
        (),
        {RULE_ID_COOKIE_VALUE: 2},
    )


def test_cookie_unquoted_supported_value_characters_and_dollar_name() -> None:
    source = (
        f"Cookie: $Version={COOKIE_VALUE_WITH_EQUALS}; "
        f"locale={COOKIE_NON_ASCII_VALUE}; punctuation={COOKIE_PUNCTUATION_VALUE}\n"
    )
    expected = (
        f"Cookie: $Version={REDACTION_MARKER_COOKIE_VALUE}; "
        f"locale={REDACTION_MARKER_COOKIE_VALUE}; "
        f"punctuation={REDACTION_MARKER_COOKIE_VALUE}\n"
    )

    assert_sanitized(
        source,
        expected,
        (COOKIE_VALUE_WITH_EQUALS, COOKIE_NON_ASCII_VALUE, COOKIE_PUNCTUATION_VALUE),
        {RULE_ID_COOKIE_VALUE: 3},
    )


def test_cookie_quoted_values_semicolons_and_escapes() -> None:
    escaped_quote_value = 'synthetic\\"quoted'
    escaped_backslash_value = "synthetic\\\\path"
    source = (
        'Cookie: preference="dark;compact"; '
        f'quoted="{escaped_quote_value}"; escaped="{escaped_backslash_value}"\n'
    )
    expected = (
        f'Cookie: preference="{REDACTION_MARKER_COOKIE_VALUE}"; '
        f'quoted="{REDACTION_MARKER_COOKIE_VALUE}"; '
        f'escaped="{REDACTION_MARKER_COOKIE_VALUE}"\n'
    )

    assert_sanitized(
        source,
        expected,
        ("dark;compact", escaped_quote_value, escaped_backslash_value),
        {RULE_ID_COOKIE_VALUE: 3},
    )


@pytest.mark.parametrize(
    "source",
    (
        'Cookie: quoted="synthetic-unterminated\n',
        'Cookie: quoted="synthetic-dangling\\\n',
        f'Cookie: quoted="{COOKIE_VALUE}"junk; theme={SECOND_COOKIE_VALUE}\n',
    ),
)
def test_cookie_malformed_quoted_values_fallback(source: str) -> None:
    assert_sanitized(
        source,
        f"Cookie: {REDACTION_MARKER_COOKIE_HEADER}\n",
        (COOKIE_VALUE, SECOND_COOKIE_VALUE, "synthetic-unterminated"),
        {RULE_ID_COOKIE_HEADER: 1},
    )


@pytest.mark.parametrize(
    "source",
    (
        "Cookie: synthetic-malformed\n",
        f"Cookie: session={COOKIE_VALUE}; synthetic-malformed; "
        f"theme={SECOND_COOKIE_VALUE}\n",
        f"Cookie: ; session={COOKIE_VALUE}\n",
        f"Cookie: session={COOKIE_VALUE};\n",
        f"Cookie: session={COOKIE_VALUE};;theme={SECOND_COOKIE_VALUE}\n",
    ),
)
def test_cookie_mandatory_malformed_cases_fallback(source: str) -> None:
    assert_sanitized(
        source,
        f"Cookie: {REDACTION_MARKER_COOKIE_HEADER}\n",
        (COOKIE_VALUE, SECOND_COOKIE_VALUE, "synthetic-malformed"),
        {RULE_ID_COOKIE_HEADER: 1},
    )


@pytest.mark.parametrize(
    "source",
    (
        "Cookie: =synthetic-empty-name\n",
        "Cookie: bad/name=synthetic-invalid-name\n",
        "Cookie: café=synthetic-non-ascii-name\n",
        "Cookie: session=synthetic\x1fcontrol\n",
        "Cookie: session=synthetic value\n",
    ),
)
def test_cookie_invalid_names_controls_and_ambiguous_whitespace_fallback(
    source: str,
) -> None:
    assert_sanitized(
        source,
        f"Cookie: {REDACTION_MARKER_COOKIE_HEADER}\n",
        (
            "synthetic-empty-name",
            "synthetic-invalid-name",
            "synthetic-non-ascii-name",
            "synthetic\x1fcontrol",
            "synthetic value",
        ),
        {RULE_ID_COOKIE_HEADER: 1},
    )


def test_cookie_whole_header_fallback_preserves_formatting() -> None:
    source = f"cOOkie \t : \t session={COOKIE_VALUE}; malformed   \r\n"
    expected = f"cOOkie \t : \t {REDACTION_MARKER_COOKIE_HEADER}   \r\n"

    assert_sanitized(
        source,
        expected,
        (COOKIE_VALUE,),
        {RULE_ID_COOKIE_HEADER: 1},
    )


def test_cookie_empty_and_whitespace_only_headers_are_unchanged() -> None:
    for source in ("Cookie:\n", "Cookie:    \n", "cookie\t:\t"):
        assert_unchanged(source)


def test_cookie_exact_markers_are_idempotent() -> None:
    cases = (
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}\n",
        f"Cookie: session={REDACTION_MARKER_COOKIE_HEADER}\n",
        f'Cookie: session="{REDACTION_MARKER_COOKIE_VALUE}"\n',
        f"Cookie: {REDACTION_MARKER_COOKIE_HEADER}\n",
        f"Cookie: {REDACTION_MARKER_COOKIE_VALUE}\n",
        f"Cookie: {REDACTION_MARKER_COOKIE_HEADER}\t \n",
    )
    for source in cases:
        assert_unchanged(source)


def test_cookie_mixed_raw_and_already_redacted_values() -> None:
    source = (
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}; "
        f"theme={COOKIE_VALUE}; other={REDACTION_MARKER_COOKIE_HEADER}\n"
    )
    expected = (
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}; "
        f"theme={REDACTION_MARKER_COOKIE_VALUE}; "
        f"other={REDACTION_MARKER_COOKIE_HEADER}\n"
    )

    assert_sanitized(
        source,
        expected,
        (COOKIE_VALUE,),
        {RULE_ID_COOKIE_VALUE: 1},
    )


def test_cookie_embedded_marker_inside_raw_value_is_redacted() -> None:
    assert_sanitized(
        f"Cookie: session={COOKIE_EMBEDDED_MARKER_VALUE}\n",
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}\n",
        (COOKIE_EMBEDDED_MARKER_VALUE,),
        {RULE_ID_COOKIE_VALUE: 1},
    )


def test_cookie_multiple_headers_counts_values_and_fallbacks() -> None:
    source = (
        f"Cookie: session={COOKIE_VALUE}\n"
        "Cookie: synthetic-malformed\n"
        f"Cookie: theme={SECOND_COOKIE_VALUE}\n"
    )
    expected = (
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}\n"
        f"Cookie: {REDACTION_MARKER_COOKIE_HEADER}\n"
        f"Cookie: theme={REDACTION_MARKER_COOKIE_VALUE}\n"
    )

    assert_sanitized(
        source,
        expected,
        (COOKIE_VALUE, SECOND_COOKIE_VALUE, "synthetic-malformed"),
        {RULE_ID_COOKIE_VALUE: 2, RULE_ID_COOKIE_HEADER: 1},
    )


def test_cookie_unsupported_header_forms_are_unchanged() -> None:
    cases = (
        "Set-Cookie: session=synthetic-set-cookie\n",
        "X-Cookie: session=synthetic-x-cookie\n",
        " Cookie: session=synthetic-indented\n",
        "The Cookie: header is documented here\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_cookie_folded_header_block_is_unchanged() -> None:
    source = (
        "Cookie: session=synthetic-folded\n"
        " theme=synthetic-folded-theme\n"
        f"Cookie: other={COOKIE_VALUE}\n"
    )
    expected = (
        "Cookie: session=synthetic-folded\n"
        " theme=synthetic-folded-theme\n"
        f"Cookie: other={REDACTION_MARKER_COOKIE_VALUE}\n"
    )

    assert_sanitized(
        source,
        expected,
        (COOKIE_VALUE,),
        {RULE_ID_COOKIE_VALUE: 1},
    )


def test_cookie_only_immediate_indented_next_line_is_folded() -> None:
    source = f"Cookie: session={COOKIE_VALUE}\nHeader: synthetic\n indented later\n"
    expected = (
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}\n"
        "Header: synthetic\n indented later\n"
    )

    assert_sanitized(
        source,
        expected,
        (COOKIE_VALUE,),
        {RULE_ID_COOKIE_VALUE: 1},
    )


def test_cookie_idempotence() -> None:
    source = f"Cookie: session={COOKIE_VALUE}; theme={SECOND_COOKIE_VALUE}\n"
    first, first_report = sanitize_text(source)
    second, second_report = sanitize_text(first)

    for value in (COOKIE_VALUE, SECOND_COOKIE_VALUE):
        if value in first or value in second:
            pytest.fail("sanitized text leaked synthetic cookie value")
    assert first == second
    assert first_report.counts_by_rule == {RULE_ID_COOKIE_VALUE: 2}
    assert second_report.counts_by_rule == {}


def test_cookie_findings_do_not_overlap_authorization_findings() -> None:
    source = (
        "Authorization: Bearer synthetic-auth-token\n"
        f"Cookie: session={COOKIE_VALUE}; theme={SECOND_COOKIE_VALUE}\n"
    )
    findings = find_authorization_credentials(source) + find_cookie_values(source)

    assert [finding.rule_id for finding in findings] == [
        RULE_ID_AUTHORIZATION_BEARER,
        RULE_ID_COOKIE_VALUE,
        RULE_ID_COOKIE_VALUE,
    ]
    previous_end = 0
    for finding in findings:
        assert previous_end <= finding.start
        previous_end = finding.end


def test_cookie_finding_does_not_store_values_or_names() -> None:
    source = f"Cookie: syntheticName={COOKIE_VALUE}; otherName={SECOND_COOKIE_VALUE}\n"
    findings = find_cookie_values(source)

    assert len(findings) == 2
    stored_values = tuple(
        value
        for finding in findings
        for value in (
            finding.rule_id,
            str(finding.start),
            str(finding.end),
            finding.replacement,
            repr(finding),
        )
    )
    for sensitive_text in (
        COOKIE_VALUE,
        SECOND_COOKIE_VALUE,
        "syntheticName",
        "otherName",
    ):
        if any(sensitive_text in value for value in stored_values):
            pytest.fail("finding stored synthetic cookie data")


def test_cookie_long_malformed_line_is_bounded() -> None:
    source = "Cookie: " + ("a" * (1024 * 1024)) + "\n"

    started = time.perf_counter()
    findings = find_cookie_values(source)
    elapsed = time.perf_counter() - started

    assert len(findings) == 1
    assert findings[0].rule_id == RULE_ID_COOKIE_HEADER
    assert elapsed < 2.0
