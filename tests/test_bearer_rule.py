"""Unit tests for Authorization header sanitization rules."""

from __future__ import annotations

import time

import pytest

from evidence_sanitizer.sanitizer import (
    EXIT_INTERNAL_ERROR,
    REDACTION_MARKER,
    REDACTION_MARKER_AUTHORIZATION_BASIC,
    REDACTION_MARKER_AUTHORIZATION_CREDENTIALS,
    RULE_ID_AUTHORIZATION_BASIC,
    RULE_ID_AUTHORIZATION_BEARER,
    RULE_ID_AUTHORIZATION_OTHER,
    Finding,
    SafeError,
    apply_findings,
    find_authorization_bearer,
    find_authorization_credentials,
    sanitize_text,
)

TOKEN = "synthetic-token-123"
SECOND_TOKEN = "second.synthetic-token"
BASIC_TOKEN = "synthetic-basic-token+/="
SECOND_BASIC_TOKEN = "second-basic-token"
CUSTOM_TOKEN = "synthetic-custom-token"
APPROVED_MARKERS = (
    REDACTION_MARKER,
    REDACTION_MARKER_AUTHORIZATION_BASIC,
    REDACTION_MARKER_AUTHORIZATION_CREDENTIALS,
)


def assert_sanitized(
    source: str,
    expected: str,
    tokens: tuple[str, ...] = (TOKEN,),
    counts_by_rule: dict[str, int] | None = None,
) -> None:
    sanitized, report = sanitize_text(source)
    for token in tokens:
        if token in sanitized:
            pytest.fail("sanitized text leaked synthetic credential")
    assert sanitized == expected
    expected_counts = (
        {RULE_ID_AUTHORIZATION_BEARER: len(tokens)}
        if counts_by_rule is None
        else counts_by_rule
    )
    assert report.counts_by_rule == expected_counts


def assert_unchanged(source: str) -> None:
    sanitized, report = sanitize_text(source)
    if sanitized != source:
        pytest.fail("text changed unexpectedly")
    assert report.counts_by_rule == {}
    assert not report.changed


def test_bearer_standard_header() -> None:
    assert_sanitized(
        f"Authorization: Bearer {TOKEN}\n",
        f"Authorization: Bearer {REDACTION_MARKER}\n",
    )


def test_bearer_case_insensitive_header_name() -> None:
    assert_sanitized(
        f"authorization: Bearer {TOKEN}\n",
        f"authorization: Bearer {REDACTION_MARKER}\n",
    )


def test_bearer_case_insensitive_scheme() -> None:
    assert_sanitized(
        f"Authorization: bearer {TOKEN}\n",
        f"Authorization: bearer {REDACTION_MARKER}\n",
    )


def test_bearer_preserved_spacing_and_tabs() -> None:
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


def test_bearer_lf_crlf_and_final_line_without_newline() -> None:
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


def test_bearer_multiple_headers() -> None:
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


def test_bearer_punctuation_credentials_and_trailing_spaces() -> None:
    cases = (
        "abc.def.ghi",
        "abc+/=~",
        "token-with_punctuation",
    )
    for token in cases:
        assert_sanitized(
            f"Authorization: Bearer {token}   \n",
            f"Authorization: Bearer {REDACTION_MARKER}   \n",
            tokens=(token,),
        )


def test_bearer_approved_markers_are_not_redacted_again() -> None:
    for marker in APPROVED_MARKERS:
        assert_unchanged(f"Authorization: Bearer {marker}\n")
        assert_unchanged(f"Authorization: Bearer {marker}\t \n")


def test_bearer_generic_fallback_does_not_capture_bearer_lines() -> None:
    sanitized, report = sanitize_text(f"Authorization: Bearer {TOKEN}\n")

    if TOKEN in sanitized:
        pytest.fail("sanitized text leaked synthetic credential")
    assert sanitized == f"Authorization: Bearer {REDACTION_MARKER}\n"
    assert report.counts_by_rule == {RULE_ID_AUTHORIZATION_BEARER: 1}


def test_bearer_validation_failures_do_not_fall_through_to_generic() -> None:
    cases = (
        "Authorization: Bearer\n",
        "Authorization: Bearer    \n",
        "Authorization: Bearer\t\t\n",
        "Authorization: Bearer this is explanatory prose\n",
        "Authorization: Bearer this\tprose\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_unrelated_bearer_prose_is_not_redacted() -> None:
    assert_unchanged("The documentation says to use Bearer authentication.\n")


def test_malformed_authorization_headers_do_not_match() -> None:
    cases = (
        " Authorization: Bearer abc123\n",
        "Authorization Bearer abc123\n",
        "X-Authorization: Bearer abc123\n",
        "Authorization:Bearerabc123\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_bearer_adversarial_long_header_line_is_bounded() -> None:
    source = "Authorization: Bearer " + ("a" * (1024 * 1024)) + " prose\n"

    started = time.perf_counter()
    findings = find_authorization_bearer(source)
    elapsed = time.perf_counter() - started

    assert findings == ()
    assert elapsed < 2.0


def test_basic_standard_header() -> None:
    assert_sanitized(
        f"Authorization: Basic {BASIC_TOKEN}\n",
        f"Authorization: Basic {REDACTION_MARKER_AUTHORIZATION_BASIC}\n",
        tokens=(BASIC_TOKEN,),
        counts_by_rule={RULE_ID_AUTHORIZATION_BASIC: 1},
    )


def test_basic_case_insensitive_scheme() -> None:
    assert_sanitized(
        f"Authorization: bAsIc {BASIC_TOKEN}\n",
        f"Authorization: bAsIc {REDACTION_MARKER_AUTHORIZATION_BASIC}\n",
        tokens=(BASIC_TOKEN,),
        counts_by_rule={RULE_ID_AUTHORIZATION_BASIC: 1},
    )


def test_basic_zero_spacing_after_colon() -> None:
    assert_sanitized(
        f"Authorization:Basic {BASIC_TOKEN}\n",
        f"Authorization:Basic {REDACTION_MARKER_AUTHORIZATION_BASIC}\n",
        tokens=(BASIC_TOKEN,),
        counts_by_rule={RULE_ID_AUTHORIZATION_BASIC: 1},
    )


def test_basic_preserved_spacing_casing_and_tabs() -> None:
    cases = (
        (
            f"authorization : BASIC {BASIC_TOKEN}\n",
            f"authorization : BASIC {REDACTION_MARKER_AUTHORIZATION_BASIC}\n",
        ),
        (
            f"Authorization:\tBasic\t{BASIC_TOKEN}\t \n",
            f"Authorization:\tBasic\t{REDACTION_MARKER_AUTHORIZATION_BASIC}\t \n",
        ),
    )
    for source, expected in cases:
        assert_sanitized(
            source,
            expected,
            tokens=(BASIC_TOKEN,),
            counts_by_rule={RULE_ID_AUTHORIZATION_BASIC: 1},
        )


def test_basic_punctuation_and_no_base64_validation() -> None:
    token = "not-base64!+/=~"

    assert_sanitized(
        f"Authorization: Basic {token}\n",
        f"Authorization: Basic {REDACTION_MARKER_AUTHORIZATION_BASIC}\n",
        tokens=(token,),
        counts_by_rule={RULE_ID_AUTHORIZATION_BASIC: 1},
    )


def test_basic_empty_whitespace_and_internal_whitespace_do_not_match() -> None:
    cases = (
        "Authorization: Basic\n",
        "Authorization: Basic    \n",
        "Authorization: Basic\t\t\n",
        "Authorization: Basic first second\n",
        "Authorization: Basic first\tsecond\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_basic_approved_markers_are_not_redacted_again() -> None:
    for marker in APPROVED_MARKERS:
        assert_unchanged(f"Authorization: Basic {marker}\n")
        assert_unchanged(f"Authorization: Basic {marker}  \n")


def test_basic_multiple_headers_and_counts() -> None:
    source = (
        f"Authorization: Basic {BASIC_TOKEN}\n"
        f"Authorization: BASIC {SECOND_BASIC_TOKEN}\n"
    )
    expected = (
        f"Authorization: Basic {REDACTION_MARKER_AUTHORIZATION_BASIC}\n"
        f"Authorization: BASIC {REDACTION_MARKER_AUTHORIZATION_BASIC}\n"
    )

    assert_sanitized(
        source,
        expected,
        tokens=(BASIC_TOKEN, SECOND_BASIC_TOKEN),
        counts_by_rule={RULE_ID_AUTHORIZATION_BASIC: 2},
    )


def test_basic_idempotence() -> None:
    source = f"Authorization: Basic {BASIC_TOKEN}\n"
    first, first_report = sanitize_text(source)
    second, second_report = sanitize_text(first)

    if BASIC_TOKEN in first or BASIC_TOKEN in second:
        pytest.fail("sanitized text leaked synthetic credential")
    assert first == second
    assert first_report.counts_by_rule == {RULE_ID_AUTHORIZATION_BASIC: 1}
    assert second_report.counts_by_rule == {}


def test_generic_amx_like_credential() -> None:
    credential = "appId:synthetic-signature:nonce:timestamp"

    assert_sanitized(
        f"Authorization: AMX {credential}\n",
        f"Authorization: AMX {REDACTION_MARKER_AUTHORIZATION_CREDENTIALS}\n",
        tokens=(credential,),
        counts_by_rule={RULE_ID_AUTHORIZATION_OTHER: 1},
    )


def test_generic_digest_style_structured_credentials() -> None:
    credential = (
        'username="synthetic-user", realm="api", '
        'nonce="synthetic-nonce", response="synthetic-response"'
    )

    assert_sanitized(
        f"Authorization: Digest {credential}\n",
        f"Authorization: Digest {REDACTION_MARKER_AUTHORIZATION_CREDENTIALS}\n",
        tokens=(credential,),
        counts_by_rule={RULE_ID_AUTHORIZATION_OTHER: 1},
    )


def test_generic_aws_style_structured_credentials() -> None:
    credential = (
        "Credential=synthetic/20260614/us-east-1/service/aws4_request, "
        "SignedHeaders=host;x-amz-date, Signature=synthetic-signature"
    )

    assert_sanitized(
        f"Authorization: AWS4-HMAC-SHA256 {credential}\n",
        "Authorization: AWS4-HMAC-SHA256 "
        f"{REDACTION_MARKER_AUTHORIZATION_CREDENTIALS}\n",
        tokens=(credential,),
        counts_by_rule={RULE_ID_AUTHORIZATION_OTHER: 1},
    )


def test_generic_custom_one_token_credential() -> None:
    assert_sanitized(
        f"Authorization: ApiKey {CUSTOM_TOKEN}\n",
        f"Authorization: ApiKey {REDACTION_MARKER_AUTHORIZATION_CREDENTIALS}\n",
        tokens=(CUSTOM_TOKEN,),
        counts_by_rule={RULE_ID_AUTHORIZATION_OTHER: 1},
    )


def test_generic_custom_credential_with_internal_spaces() -> None:
    credential = "opaque synthetic value with parameters"

    assert_sanitized(
        f"Authorization: CustomScheme {credential}\n",
        f"Authorization: CustomScheme {REDACTION_MARKER_AUTHORIZATION_CREDENTIALS}\n",
        tokens=(credential,),
        counts_by_rule={RULE_ID_AUTHORIZATION_OTHER: 1},
    )


def test_generic_credentials_with_structured_punctuation() -> None:
    credential = 'opaque="synthetic", path=/api/v1:443, equals=a=b=c'

    assert_sanitized(
        f"Authorization: Signature {credential}\n",
        f"Authorization: Signature {REDACTION_MARKER_AUTHORIZATION_CREDENTIALS}\n",
        tokens=(credential,),
        counts_by_rule={RULE_ID_AUTHORIZATION_OTHER: 1},
    )


def test_generic_preserves_scheme_casing_formatting_and_trailing_spaces() -> None:
    assert_sanitized(
        f"authorization : cUsToM\t{CUSTOM_TOKEN}  \n",
        f"authorization : cUsToM\t{REDACTION_MARKER_AUTHORIZATION_CREDENTIALS}  \n",
        tokens=(CUSTOM_TOKEN,),
        counts_by_rule={RULE_ID_AUTHORIZATION_OTHER: 1},
    )


def test_generic_empty_or_scheme_only_headers_do_not_match() -> None:
    cases = (
        "Authorization:\n",
        "Authorization:    \n",
        "Authorization: Custom\n",
        "Authorization: Custom    \n",
        "Authorization: Custom\t\t\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_generic_malformed_and_unicode_schemes_do_not_match() -> None:
    cases = (
        "Authorization: My/Auth token\n",
        "Authorization: My@Auth token\n",
        "Authorization: Münch token\n",
        "Authorization: 認証 token\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_generic_non_authorization_lines_do_not_match() -> None:
    cases = (
        " Authorization: Custom token\n",
        "X-Authorization: Custom token\n",
        "The Authorization: header is documented here\n",
        "Authorization is required\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_generic_approved_markers_are_not_redacted_again() -> None:
    for marker in APPROVED_MARKERS:
        assert_unchanged(f"Authorization: Custom {marker}\n")
        assert_unchanged(f"Authorization: Custom {marker}  \n")


def test_generic_embedded_marker_inside_larger_value_is_redacted() -> None:
    credential = f"prefix{REDACTION_MARKER_AUTHORIZATION_BASIC}suffix"

    assert_sanitized(
        f"Authorization: Custom {credential}\n",
        f"Authorization: Custom {REDACTION_MARKER_AUTHORIZATION_CREDENTIALS}\n",
        tokens=(credential,),
        counts_by_rule={RULE_ID_AUTHORIZATION_OTHER: 1},
    )


def test_generic_idempotence() -> None:
    source = f"Authorization: Token {CUSTOM_TOKEN} with context\n"
    first, first_report = sanitize_text(source)
    second, second_report = sanitize_text(first)

    if CUSTOM_TOKEN in first or CUSTOM_TOKEN in second:
        pytest.fail("sanitized text leaked synthetic credential")
    assert first == second
    assert first_report.counts_by_rule == {RULE_ID_AUTHORIZATION_OTHER: 1}
    assert second_report.counts_by_rule == {}


def test_findings_are_non_overlapping_and_one_per_authorization_line() -> None:
    findings = find_authorization_credentials(
        f"Authorization: Bearer {TOKEN}\n"
        f"Authorization: Basic {BASIC_TOKEN}\n"
        f"Authorization: AMX {CUSTOM_TOKEN}\n"
    )

    assert [finding.rule_id for finding in findings] == [
        RULE_ID_AUTHORIZATION_BEARER,
        RULE_ID_AUTHORIZATION_BASIC,
        RULE_ID_AUTHORIZATION_OTHER,
    ]
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


def test_bearer_idempotence() -> None:
    source = f"Authorization: Bearer {TOKEN}\n"
    first, first_report = sanitize_text(source)
    second, second_report = sanitize_text(first)

    if TOKEN in first or TOKEN in second:
        pytest.fail("sanitized text leaked synthetic credential")
    assert first == second
    assert first_report.counts_by_rule == {RULE_ID_AUTHORIZATION_BEARER: 1}
    assert second_report.counts_by_rule == {}


def test_finding_does_not_store_original_credential() -> None:
    findings = find_authorization_credentials(
        f"Authorization: Bearer {TOKEN}\n"
        f"Authorization: Basic {BASIC_TOKEN}\n"
        f"Authorization: Custom {CUSTOM_TOKEN}\n"
    )

    assert len(findings) == 3
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
    for token in (TOKEN, BASIC_TOKEN, CUSTOM_TOKEN):
        if any(token in value for value in stored_values):
            pytest.fail("finding stored synthetic credential")
