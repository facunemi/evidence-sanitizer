"""Unit tests for selected sensitive form-urlencoded field sanitization."""

from __future__ import annotations

import pytest

from evidence_sanitizer.sanitizer import (
    REDACTION_MARKER,
    REDACTION_MARKER_AUTHORIZATION_BEARER,
    REDACTION_MARKER_COOKIE_VALUE,
    REDACTION_MARKER_FORM_VALUE,
    REDACTION_MARKER_HEADER_SECRET,
    REDACTION_MARKER_JSON_VALUE,
    REDACTION_MARKER_QUERY_SECRET,
    RULE_ID_AUTHORIZATION_BEARER,
    RULE_ID_COOKIE_VALUE,
    RULE_ID_FORM_VALUE,
    RULE_ID_HEADER_SECRET,
    RULE_ID_QUERY_SECRET,
    _find_form_urlencoded_values,
    sanitize_text,
)

FORM_VALUE = "synthetic-form-value"
SECOND_FORM_VALUE = "synthetic-second-form-value"
FORM_BODY_PREFIX = "Content-Type: application/x-www-form-urlencoded\n\n"

APPROVED_FORM_NAMES = (
    "access_token",
    "accessToken",
    "auth_token",
    "authToken",
    "id_token",
    "idToken",
    "jwt",
    "refresh_token",
    "refreshToken",
    "session",
    "session_id",
    "sessionId",
    "sid",
    "token",
    "api-key",
    "api_key",
    "apiKey",
    "apikey",
    "x_api_key",
    "xApiKey",
    "client_secret",
    "clientSecret",
    "shared_secret",
    "sharedSecret",
    "private_key",
    "privateKey",
    "password",
    "passwd",
    "pwd",
    "client_assertion",
    "clientAssertion",
    "saml_response",
    "samlResponse",
    "samlresponse",
    "sig",
    "signature",
    "x-amz-credential",
    "x-amz-security-token",
    "x-amz-signature",
    "x-goog-credential",
    "x-goog-signature",
    "x_amz_signature",
    "xAmzSignature",
    "x_goog_signature",
    "xGoogSignature",
    "csrf",
    "csrf_token",
    "xsrf",
    "xsrf_token",
)

DEFERRED_FORM_NAMES = (
    "key",
    "secret",
    "code",
    "state",
    "nonce",
    "assertion",
    "sign",
    "signed",
    "expires",
    "expiry",
    "timestamp",
    "redirect_uri",
    "url",
    "email",
    "user",
    "user_id",
    "username",
    "client_id",
    "tenant_id",
    "account_id",
    "customer_id",
    "grant_type",
    "scope",
    "otp",
    "mfa_code",
    "se",
    "sp",
    "sv",
    "sr",
    "st",
    "utm_source",
    "gclid",
    "fbclid",
)

NEAR_MISS_FORM_NAMES = (
    "password_policy",
    "access_token_expires",
    "client_secret_name",
    "tokenizer",
    "state_name",
    "code_challenge",
    "code_challenge_method",
)

WRONG_FAMILY_MARKERS = (
    REDACTION_MARKER_QUERY_SECRET,
    REDACTION_MARKER_HEADER_SECRET,
    REDACTION_MARKER_COOKIE_VALUE,
    REDACTION_MARKER_AUTHORIZATION_BEARER,
    REDACTION_MARKER_JSON_VALUE,
)


def assert_sanitized(
    source: str,
    expected: str,
    sensitive_values: tuple[str, ...] = (FORM_VALUE,),
    counts_by_rule: dict[str, int] | None = None,
) -> None:
    sanitized, report = sanitize_text(source)
    for value in sensitive_values:
        if value and value in sanitized:
            pytest.fail("sanitized text leaked synthetic form value")
    assert sanitized == expected
    expected_counts = (
        {RULE_ID_FORM_VALUE: len(sensitive_values)}
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


@pytest.mark.parametrize("name", APPROVED_FORM_NAMES)
def test_form_redacts_every_approved_field_name(name: str) -> None:
    assert_sanitized(
        f"{FORM_BODY_PREFIX}{name}={FORM_VALUE}",
        f"{FORM_BODY_PREFIX}{name}={REDACTION_MARKER_FORM_VALUE}",
    )


@pytest.mark.parametrize("name", DEFERRED_FORM_NAMES)
def test_form_deferred_names_remain_unchanged(name: str) -> None:
    assert_unchanged(f"{FORM_BODY_PREFIX}{name}={FORM_VALUE}")


def test_form_missing_content_type_unchanged() -> None:
    assert_unchanged(f"access_token={FORM_VALUE}")


def test_form_unsupported_content_type_unchanged() -> None:
    assert_unchanged(f"Content-Type: text/plain\n\naccess_token={FORM_VALUE}")


def test_form_content_type_with_parameters_supported() -> None:
    assert_sanitized(
        f"Content-Type: application/x-www-form-urlencoded; charset=utf-8\n\n"
        f"access_token={FORM_VALUE}",
        f"Content-Type: application/x-www-form-urlencoded; charset=utf-8\n\n"
        f"access_token={REDACTION_MARKER_FORM_VALUE}",
    )


def test_form_immediate_first_body_line_only() -> None:
    source = (
        f"{FORM_BODY_PREFIX}access_token={FORM_VALUE}\n"
        f"refresh_token={SECOND_FORM_VALUE}"
    )
    expected = (
        f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}\n"
        f"refresh_token={SECOND_FORM_VALUE}"
    )
    assert_sanitized(
        source,
        expected,
        sensitive_values=(FORM_VALUE,),
        counts_by_rule={RULE_ID_FORM_VALUE: 1},
    )


def test_form_blank_immediate_body_line_means_no_scan() -> None:
    assert_unchanged(
        "Content-Type: application/x-www-form-urlencoded\n\n"
        f"\naccess_token={FORM_VALUE}"
    )


def test_form_ampersand_separator() -> None:
    assert_sanitized(
        f"{FORM_BODY_PREFIX}access_token={FORM_VALUE}&theme=dark&sig={SECOND_FORM_VALUE}",
        f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}"
        f"&theme=dark&sig={REDACTION_MARKER_FORM_VALUE}",
        sensitive_values=(FORM_VALUE, SECOND_FORM_VALUE),
        counts_by_rule={RULE_ID_FORM_VALUE: 2},
    )


def test_form_semicolon_is_not_separator() -> None:
    assert_sanitized(
        f"{FORM_BODY_PREFIX}access_token={FORM_VALUE};theme=dark",
        f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}",
        sensitive_values=("synthetic-form-value;theme=dark",),
    )


def test_form_empty_value_redacts() -> None:
    assert_sanitized(
        f"{FORM_BODY_PREFIX}access_token=",
        f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}",
        sensitive_values=(),
        counts_by_rule={RULE_ID_FORM_VALUE: 1},
    )


def test_form_bare_no_value_unchanged() -> None:
    assert_unchanged(f"{FORM_BODY_PREFIX}access_token")


def test_form_additional_equals_inside_value() -> None:
    assert_sanitized(
        f"{FORM_BODY_PREFIX}access_token=a=b=c",
        f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}",
        sensitive_values=("a=b=c",),
    )


def test_form_no_percent_decoding_names() -> None:
    assert_unchanged(f"{FORM_BODY_PREFIX}access%5Ftoken={FORM_VALUE}")


def test_form_raw_plus_value_redacts_when_field_name_approved() -> None:
    assert_sanitized(
        f"{FORM_BODY_PREFIX}password=hello+world",
        f"{FORM_BODY_PREFIX}password={REDACTION_MARKER_FORM_VALUE}",
        sensitive_values=("hello+world",),
    )


def test_form_exact_marker_is_idempotent() -> None:
    assert_unchanged(f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}")


@pytest.mark.parametrize("marker", WRONG_FAMILY_MARKERS)
def test_form_wrong_family_marker_is_redacted(marker: str) -> None:
    assert_sanitized(
        f"{FORM_BODY_PREFIX}access_token={marker}",
        f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}",
        sensitive_values=(marker,),
    )


def test_form_overlap_with_query_inside_approved_form_value() -> None:
    source = (
        f"{FORM_BODY_PREFIX}access_token=https://api.example.test/cb?token={FORM_VALUE}"
    )
    expected = f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}"
    assert_sanitized(
        source,
        expected,
        sensitive_values=(FORM_VALUE,),
        counts_by_rule={RULE_ID_FORM_VALUE: 1},
    )


def test_form_overlap_with_json_inside_approved_form_value() -> None:
    source = f'{FORM_BODY_PREFIX}access_token={{"token":"{FORM_VALUE}"}}'
    expected = f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}"
    assert_sanitized(
        source,
        expected,
        sensitive_values=(FORM_VALUE,),
        counts_by_rule={RULE_ID_FORM_VALUE: 1},
    )


def test_form_query_redacts_inside_non_sensitive_form_field() -> None:
    source = f"{FORM_BODY_PREFIX}theme=https://x.test/?sig={FORM_VALUE}"
    expected = (
        f"{FORM_BODY_PREFIX}theme=https://x.test/?sig={REDACTION_MARKER_QUERY_SECRET}"
    )
    assert_sanitized(
        source,
        expected,
        sensitive_values=(FORM_VALUE,),
        counts_by_rule={RULE_ID_QUERY_SECRET: 1},
    )


def test_form_overlapping_authorization_finding_is_skipped() -> None:
    assert_sanitized(
        f"Authorization: Bearer access_token={FORM_VALUE}",
        f"Authorization: Bearer {REDACTION_MARKER}",
        sensitive_values=(FORM_VALUE,),
        counts_by_rule={RULE_ID_AUTHORIZATION_BEARER: 1},
    )


def test_form_overlapping_sensitive_header_finding_is_skipped() -> None:
    assert_sanitized(
        f"X-API-Key: access_token={FORM_VALUE}",
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}",
        sensitive_values=(FORM_VALUE,),
        counts_by_rule={RULE_ID_HEADER_SECRET: 1},
    )


def test_form_overlapping_cookie_finding_is_skipped() -> None:
    assert_sanitized(
        f"Cookie: session=access_token={FORM_VALUE}",
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}",
        sensitive_values=(FORM_VALUE,),
        counts_by_rule={RULE_ID_COOKIE_VALUE: 1},
    )


def test_form_idempotence_of_sanitize_text() -> None:
    source = f"{FORM_BODY_PREFIX}access_token={FORM_VALUE}&password={SECOND_FORM_VALUE}"
    first, first_report = sanitize_text(source)
    second, second_report = sanitize_text(first)

    assert FORM_VALUE not in first and FORM_VALUE not in second
    assert SECOND_FORM_VALUE not in first and SECOND_FORM_VALUE not in second
    assert first == second
    assert first_report.counts_by_rule == {RULE_ID_FORM_VALUE: 2}
    assert second_report.counts_by_rule == {}
    assert not second_report.changed


def test_form_findings_do_not_store_raw_values_or_field_names() -> None:
    source = f"{FORM_BODY_PREFIX}access_token={FORM_VALUE}&password={SECOND_FORM_VALUE}"
    findings = _find_form_urlencoded_values(source, ())

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
    for sensitive_text in (FORM_VALUE, SECOND_FORM_VALUE, "access_token", "password"):
        if any(sensitive_text in value for value in stored_values):
            pytest.fail("finding stored synthetic form data")


@pytest.mark.parametrize("name", NEAR_MISS_FORM_NAMES)
def test_form_near_miss_names_remain_unchanged(name: str) -> None:
    assert_unchanged(f"{FORM_BODY_PREFIX}{name}={FORM_VALUE}")


def test_form_embedded_approved_marker_is_redacted() -> None:
    value = f"prefix{REDACTION_MARKER_FORM_VALUE}suffix"
    assert_sanitized(
        f"{FORM_BODY_PREFIX}access_token={value}",
        f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}",
        sensitive_values=(value,),
    )


def test_form_unapproved_marker_like_value_is_redacted() -> None:
    value = "<REDACTED:form.token>"
    assert_sanitized(
        f"{FORM_BODY_PREFIX}access_token={value}",
        f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}",
        sensitive_values=(value,),
    )


def test_form_percent_encoded_value_redacts_raw_when_name_matches() -> None:
    value = "synthetic%2Dtoken"
    assert_sanitized(
        f"{FORM_BODY_PREFIX}access_token={value}",
        f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}",
        sensitive_values=(value,),
    )


def test_form_case_insensitive_matching() -> None:
    assert_sanitized(
        f"{FORM_BODY_PREFIX}ACCESS_TOKEN={FORM_VALUE}&Client_Secret={SECOND_FORM_VALUE}",
        f"{FORM_BODY_PREFIX}ACCESS_TOKEN={REDACTION_MARKER_FORM_VALUE}"
        f"&Client_Secret={REDACTION_MARKER_FORM_VALUE}",
        sensitive_values=(FORM_VALUE, SECOND_FORM_VALUE),
        counts_by_rule={RULE_ID_FORM_VALUE: 2},
    )


def test_form_punctuation_distinction() -> None:
    assert_unchanged(f"{FORM_BODY_PREFIX}api.key={FORM_VALUE}")


def test_form_repeated_same_name_fields_redact_and_count() -> None:
    assert_sanitized(
        f"{FORM_BODY_PREFIX}access_token=one&access_token=two",
        f"{FORM_BODY_PREFIX}access_token={REDACTION_MARKER_FORM_VALUE}"
        f"&access_token={REDACTION_MARKER_FORM_VALUE}",
        sensitive_values=("one", "two"),
        counts_by_rule={RULE_ID_FORM_VALUE: 2},
    )


def test_form_duplicate_content_type_headers_scan_body_once() -> None:
    source = (
        "POST /oauth/token HTTP/1.1\n"
        "Host: api.example.test\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "Content-Type: application/x-www-form-urlencoded; charset=utf-8\n"
        "\n"
        f"access_token={FORM_VALUE}&client_secret={SECOND_FORM_VALUE}"
    )
    expected = (
        "POST /oauth/token HTTP/1.1\n"
        "Host: api.example.test\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "Content-Type: application/x-www-form-urlencoded; charset=utf-8\n"
        "\n"
        f"access_token={REDACTION_MARKER_FORM_VALUE}"
        f"&client_secret={REDACTION_MARKER_FORM_VALUE}"
    )
    assert_sanitized(
        source,
        expected,
        sensitive_values=(FORM_VALUE, SECOND_FORM_VALUE),
        counts_by_rule={RULE_ID_FORM_VALUE: 2},
    )


def test_form_content_type_trailing_spaces_supported() -> None:
    assert_sanitized(
        "Content-Type: application/x-www-form-urlencoded   \n\n"
        f"access_token={FORM_VALUE}",
        "Content-Type: application/x-www-form-urlencoded   \n\n"
        f"access_token={REDACTION_MARKER_FORM_VALUE}",
    )


def test_form_content_type_space_before_semicolon_supported() -> None:
    assert_sanitized(
        "Content-Type: application/x-www-form-urlencoded ; charset=utf-8\n\n"
        f"access_token={FORM_VALUE}",
        "Content-Type: application/x-www-form-urlencoded ; charset=utf-8\n\n"
        f"access_token={REDACTION_MARKER_FORM_VALUE}",
    )


def test_form_content_type_invalid_suffix_unchanged() -> None:
    assert_unchanged(
        "Content-Type: application/x-www-form-urlencoded invalid\n\n"
        f"access_token={FORM_VALUE}"
    )


def test_form_content_type_slash_suffix_unchanged() -> None:
    assert_unchanged(
        "Content-Type: application/x-www-form-urlencoded/extra\n\n"
        f"access_token={FORM_VALUE}"
    )


def test_form_content_type_trailing_letter_suffix_unchanged() -> None:
    assert_unchanged(
        f"Content-Type: application/x-www-form-urlencodedx\n\naccess_token={FORM_VALUE}"
    )
