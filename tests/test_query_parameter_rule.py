"""Unit tests for selected sensitive URL query parameter sanitization."""

from __future__ import annotations

import pytest

from evidence_sanitizer.sanitizer import (
    REDACTION_MARKER,
    REDACTION_MARKER_COOKIE_HEADER,
    REDACTION_MARKER_COOKIE_VALUE,
    REDACTION_MARKER_HEADER_SECRET,
    REDACTION_MARKER_QUERY_SECRET,
    RULE_ID_AUTHORIZATION_BEARER,
    RULE_ID_COOKIE_HEADER,
    RULE_ID_COOKIE_VALUE,
    RULE_ID_HEADER_SECRET,
    RULE_ID_QUERY_SECRET,
    _find_query_parameter_values,
    sanitize_text,
)

QUERY_VALUE = "synthetic-query-value"
SECOND_QUERY_VALUE = "synthetic-second-query-value"
THIRD_QUERY_VALUE = "synthetic-third-query-value"
APPROVED_QUERY_NAMES = (
    "access_token",
    "auth_token",
    "id_token",
    "jwt",
    "refresh_token",
    "session",
    "session_id",
    "sid",
    "token",
    "api-key",
    "api_key",
    "apikey",
    "client_secret",
    "sig",
    "signature",
    "x-amz-credential",
    "x-amz-security-token",
    "x-amz-signature",
    "x-goog-credential",
    "x-goog-signature",
)
DEFERRED_QUERY_NAMES = (
    "key",
    "code",
    "state",
    "nonce",
    "secret",
    "sign",
    "signed",
    "se",
    "sp",
    "sv",
    "sr",
    "st",
    "expires",
    "expiry",
    "timestamp",
    "redirect_uri",
    "url",
    "email",
    "user",
    "user_id",
    "bearer",
    "sessionid",
    "app_key",
    "subscription-key",
    "ocp-apim-subscription-key",
    "client_assertion",
    "assertion",
    "samlresponse",
    "saml_response",
    "idp_token",
    "password",
    "passwd",
    "pwd",
    "shared_secret",
    "private_key",
    "csrf",
    "csrf_token",
    "xsrf",
    "xsrf_token",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "gclid",
    "fbclid",
    "msclkid",
    "_ga",
)
NEAR_MISS_QUERY_NAMES = (
    "keyboard",
    "monkey",
    "tokenizer",
    "access_token_expires",
    "signature_algorithm",
    "design",
    "signal",
    "signed_in",
    "code_verifier",
    "postcode",
    "state_name",
    "nonces",
    "api_key_name",
)
WRONG_FAMILY_MARKERS = (
    REDACTION_MARKER_HEADER_SECRET,
    REDACTION_MARKER_COOKIE_VALUE,
    REDACTION_MARKER,
)


def assert_sanitized(
    source: str,
    expected: str,
    sensitive_values: tuple[str, ...] = (QUERY_VALUE,),
    counts_by_rule: dict[str, int] | None = None,
) -> None:
    sanitized, report = sanitize_text(source)
    for value in sensitive_values:
        if value and value in sanitized:
            pytest.fail("sanitized text leaked synthetic query value")
    assert sanitized == expected
    expected_counts = (
        {RULE_ID_QUERY_SECRET: len(sensitive_values)}
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


@pytest.mark.parametrize("name", APPROVED_QUERY_NAMES)
def test_query_redacts_every_approved_parameter_name(name: str) -> None:
    assert_sanitized(
        f"?{name}={QUERY_VALUE}",
        f"?{name}={REDACTION_MARKER_QUERY_SECRET}",
    )


def test_query_sig_and_signature_redact() -> None:
    assert_sanitized(
        f"?sig={QUERY_VALUE}&signature={SECOND_QUERY_VALUE}",
        f"?sig={REDACTION_MARKER_QUERY_SECRET}"
        f"&signature={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(QUERY_VALUE, SECOND_QUERY_VALUE),
        counts_by_rule={RULE_ID_QUERY_SECRET: 2},
    )


def test_query_case_insensitive_parameter_names() -> None:
    assert_sanitized(
        f"?AcCeSs_Token={QUERY_VALUE}&SIG={SECOND_QUERY_VALUE}",
        f"?AcCeSs_Token={REDACTION_MARKER_QUERY_SECRET}"
        f"&SIG={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(QUERY_VALUE, SECOND_QUERY_VALUE),
        counts_by_rule={RULE_ID_QUERY_SECRET: 2},
    )


@pytest.mark.parametrize("name", DEFERRED_QUERY_NAMES)
def test_query_deferred_names_remain_unchanged(name: str) -> None:
    assert_unchanged(f"?{name}={QUERY_VALUE}")


@pytest.mark.parametrize("name", NEAR_MISS_QUERY_NAMES)
def test_query_near_miss_names_remain_unchanged(name: str) -> None:
    assert_unchanged(f"?{name}={QUERY_VALUE}")


def test_query_percent_encoded_names_remain_unchanged() -> None:
    assert_unchanged(f"?access%5Ftoken={QUERY_VALUE}")


def test_query_ampersand_separator() -> None:
    assert_sanitized(
        f"?token={QUERY_VALUE}&theme=dark&session={SECOND_QUERY_VALUE}",
        f"?token={REDACTION_MARKER_QUERY_SECRET}"
        "&theme=dark"
        f"&session={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(QUERY_VALUE, SECOND_QUERY_VALUE),
        counts_by_rule={RULE_ID_QUERY_SECRET: 2},
    )


def test_query_semicolon_separator() -> None:
    assert_sanitized(
        f"?token={QUERY_VALUE};theme=dark;sig={SECOND_QUERY_VALUE}",
        f"?token={REDACTION_MARKER_QUERY_SECRET}"
        ";theme=dark"
        f";sig={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(QUERY_VALUE, SECOND_QUERY_VALUE),
        counts_by_rule={RULE_ID_QUERY_SECRET: 2},
    )


def test_query_hash_fragment_boundary() -> None:
    assert_sanitized(
        f"?token={QUERY_VALUE}#section",
        f"?token={REDACTION_MARKER_QUERY_SECRET}#section",
    )
    assert_sanitized(
        f"?token={QUERY_VALUE}#sig={SECOND_QUERY_VALUE}",
        f"?token={REDACTION_MARKER_QUERY_SECRET}#sig={SECOND_QUERY_VALUE}",
        sensitive_values=(QUERY_VALUE,),
    )


@pytest.mark.parametrize(
    "boundary",
    (
        " ",
        "\t",
        "\r",
        "\n",
        '"',
        "'",
        "`",
        "<",
        ">",
    ),
)
def test_query_token_terminator_boundaries(boundary: str) -> None:
    assert_sanitized(
        f"?token={QUERY_VALUE}{boundary}remaining",
        f"?token={REDACTION_MARKER_QUERY_SECRET}{boundary}remaining",
    )


def test_query_angle_wrapped_url() -> None:
    assert_sanitized(
        f"<https://x.test/?sig={QUERY_VALUE}>",
        f"<https://x.test/?sig={REDACTION_MARKER_QUERY_SECRET}>",
    )


def test_query_repeated_parameters() -> None:
    assert_sanitized(
        f"?token={QUERY_VALUE}&token={SECOND_QUERY_VALUE}",
        f"?token={REDACTION_MARKER_QUERY_SECRET}&token={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(QUERY_VALUE, SECOND_QUERY_VALUE),
        counts_by_rule={RULE_ID_QUERY_SECRET: 2},
    )


def test_query_multiple_tokens_on_one_line() -> None:
    assert_sanitized(
        f"prefix?token={QUERY_VALUE} suffix?sig={SECOND_QUERY_VALUE}",
        f"prefix?token={REDACTION_MARKER_QUERY_SECRET} "
        f"suffix?sig={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(QUERY_VALUE, SECOND_QUERY_VALUE),
        counts_by_rule={RULE_ID_QUERY_SECRET: 2},
    )


def test_query_repeated_question_inside_one_token_is_data() -> None:
    assert_sanitized(
        f"?token={QUERY_VALUE}?{SECOND_QUERY_VALUE}&sig={THIRD_QUERY_VALUE}",
        f"?token={REDACTION_MARKER_QUERY_SECRET}&sig={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(QUERY_VALUE, SECOND_QUERY_VALUE, THIRD_QUERY_VALUE),
        counts_by_rule={RULE_ID_QUERY_SECRET: 2},
    )


def test_query_only_string() -> None:
    assert_sanitized(
        f"?token={QUERY_VALUE}",
        f"?token={REDACTION_MARKER_QUERY_SECRET}",
    )


def test_query_absolute_url() -> None:
    assert_sanitized(
        f"https://example.test/a?token={QUERY_VALUE}&theme=dark",
        f"https://example.test/a?token={REDACTION_MARKER_QUERY_SECRET}&theme=dark",
    )


def test_query_relative_path() -> None:
    assert_sanitized(
        f"/api/v1?token={QUERY_VALUE}&theme=dark",
        f"/api/v1?token={REDACTION_MARKER_QUERY_SECRET}&theme=dark",
    )


def test_query_http_request_line() -> None:
    assert_sanitized(
        f"GET /resource?token={QUERY_VALUE} HTTP/1.1",
        f"GET /resource?token={REDACTION_MARKER_QUERY_SECRET} HTTP/1.1",
    )


def test_query_referer_and_location_values() -> None:
    assert_sanitized(
        f"Referer: https://x.test/?sig={QUERY_VALUE}\r\n"
        f"Location: /path?token={SECOND_QUERY_VALUE}\r\n",
        f"Referer: https://x.test/?sig={REDACTION_MARKER_QUERY_SECRET}\r\n"
        f"Location: /path?token={REDACTION_MARKER_QUERY_SECRET}\r\n",
        sensitive_values=(QUERY_VALUE, SECOND_QUERY_VALUE),
        counts_by_rule={RULE_ID_QUERY_SECRET: 2},
    )


def test_query_raw_body_or_log_text() -> None:
    assert_sanitized(
        f"log: user clicked https://app.test/?jwt={QUERY_VALUE}",
        f"log: user clicked https://app.test/?jwt={REDACTION_MARKER_QUERY_SECRET}",
    )


def test_query_explicit_empty_value_is_redacted() -> None:
    assert_sanitized(
        "?token=",
        f"?token={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(),
        counts_by_rule={RULE_ID_QUERY_SECRET: 1},
    )


def test_query_bare_no_value_parameter_remains_unchanged() -> None:
    assert_unchanged("?token")
    assert_unchanged(f"?token&foo={QUERY_VALUE}")


def test_query_exact_marker_is_idempotent() -> None:
    assert_unchanged(f"?token={REDACTION_MARKER_QUERY_SECRET}")
    assert_unchanged(
        f"?token={REDACTION_MARKER_QUERY_SECRET}&sig={REDACTION_MARKER_QUERY_SECRET}"
    )


def test_query_embedded_marker_is_redacted() -> None:
    embedded_value = f"prefix{REDACTION_MARKER_QUERY_SECRET}suffix"
    assert_sanitized(
        f"?token={embedded_value}",
        f"?token={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(embedded_value,),
    )


def test_query_unapproved_marker_like_value_is_redacted() -> None:
    raw_value = "<REDACTED:query.token>"
    assert_sanitized(
        f"?token={raw_value}",
        f"?token={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(raw_value,),
    )


@pytest.mark.parametrize("marker", WRONG_FAMILY_MARKERS)
def test_query_wrong_family_markers_are_redacted(marker: str) -> None:
    assert_sanitized(
        f"?token={marker}",
        f"?token={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(marker,),
    )


def test_query_value_with_additional_equals_is_redacted() -> None:
    assert_sanitized(
        "?token=a=b=c",
        f"?token={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=("a=b=c",),
    )


def test_query_angle_bracket_not_part_of_marker_terminates_token() -> None:
    assert_sanitized(
        f"?token={QUERY_VALUE}<def",
        f"?token={REDACTION_MARKER_QUERY_SECRET}<def",
    )


def test_query_overlapping_authorization_findings_are_skipped() -> None:
    assert_sanitized(
        f"Authorization: Bearer https://x.test/?token={QUERY_VALUE}",
        f"Authorization: Bearer {REDACTION_MARKER}",
        sensitive_values=(QUERY_VALUE,),
        counts_by_rule={RULE_ID_AUTHORIZATION_BEARER: 1},
    )


def test_query_overlapping_cookie_findings_are_skipped() -> None:
    assert_sanitized(
        f"Cookie: session=https://x.test/?token={QUERY_VALUE}",
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}",
        sensitive_values=(QUERY_VALUE,),
        counts_by_rule={RULE_ID_COOKIE_VALUE: 1},
    )


def test_query_overlapping_sensitive_header_findings_are_skipped() -> None:
    assert_sanitized(
        f"X-API-Key: https://x.test/?sig={QUERY_VALUE}",
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}",
        sensitive_values=(QUERY_VALUE,),
        counts_by_rule={RULE_ID_HEADER_SECRET: 1},
    )


def test_query_inside_preserved_harmless_cookie_value_is_redacted() -> None:
    assert_sanitized(
        f"Cookie: theme=https://x.test/?sig={QUERY_VALUE}",
        f"Cookie: theme=https://x.test/?sig={REDACTION_MARKER_QUERY_SECRET}",
    )


def test_query_idempotence() -> None:
    source = f"?token={QUERY_VALUE}&sig={SECOND_QUERY_VALUE}"
    first, first_report = sanitize_text(source)
    second, second_report = sanitize_text(first)

    if QUERY_VALUE in first or QUERY_VALUE in second:
        pytest.fail("sanitized text leaked synthetic query value")
    if SECOND_QUERY_VALUE in first or SECOND_QUERY_VALUE in second:
        pytest.fail("sanitized text leaked synthetic query value")
    assert first == second
    assert first_report.counts_by_rule == {RULE_ID_QUERY_SECRET: 2}
    assert second_report.counts_by_rule == {}


def test_query_findings_store_no_raw_value_url_or_name() -> None:
    source = f"https://example.test/path?token={QUERY_VALUE}&theme=dark"
    findings = _find_query_parameter_values(source, ())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ID_QUERY_SECRET
    assert finding.replacement == REDACTION_MARKER_QUERY_SECRET
    finding_repr = repr(finding)
    for sensitive_text in (
        QUERY_VALUE,
        "https://example.test/path",
        "?token=",
        "token",
        "theme",
    ):
        if sensitive_text in finding_repr:
            pytest.fail("finding stored synthetic query data")


def test_query_empty_value_inside_authorization_is_skipped() -> None:
    assert_sanitized(
        "Authorization: Bearer https://x.test/?token=\n",
        f"Authorization: Bearer {REDACTION_MARKER}\n",
        sensitive_values=(),
        counts_by_rule={RULE_ID_AUTHORIZATION_BEARER: 1},
    )


def test_query_empty_value_inside_sensitive_header_is_skipped() -> None:
    assert_sanitized(
        "X-API-Key: https://x.test/?token=\n",
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n",
        sensitive_values=(),
        counts_by_rule={RULE_ID_HEADER_SECRET: 1},
    )


def test_query_empty_value_inside_cookie_value_is_skipped() -> None:
    assert_sanitized(
        "Cookie: session=https://x.test/?token=\n",
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}\n",
        sensitive_values=(),
        counts_by_rule={RULE_ID_COOKIE_VALUE: 1},
    )


def test_query_empty_value_inside_cookie_fallback_is_skipped() -> None:
    assert_sanitized(
        "Cookie: bad; malformed=https://x.test/?token=\n",
        f"Cookie: {REDACTION_MARKER_COOKIE_HEADER}\n",
        sensitive_values=(),
        counts_by_rule={RULE_ID_COOKIE_HEADER: 1},
    )


def test_query_fragment_question_mark_is_not_a_new_query_candidate() -> None:
    assert_unchanged("https://x.test/path?theme=dark#frag?token=value")
    assert_sanitized(
        "https://x.test/path?sig=abc#frag?token=value",
        f"https://x.test/path?sig={REDACTION_MARKER_QUERY_SECRET}#frag?token=value",
        sensitive_values=("abc",),
        counts_by_rule={RULE_ID_QUERY_SECRET: 1},
    )


def test_query_fragment_with_multiple_hashes_is_skipped() -> None:
    assert_unchanged("https://x.test/path?theme=dark#frag#still-frag?token=value")
    assert_sanitized(
        "https://x.test/path?sig=abc#frag#still-frag?token=value",
        f"https://x.test/path?sig={REDACTION_MARKER_QUERY_SECRET}"
        f"#frag#still-frag?token=value",
        sensitive_values=("abc",),
        counts_by_rule={RULE_ID_QUERY_SECRET: 1},
    )


def test_query_separate_token_after_fragment_is_found() -> None:
    assert_sanitized(
        "https://x.test/path?theme=dark#frag?token=value "
        f"https://x.test/next?token={QUERY_VALUE}",
        "https://x.test/path?theme=dark#frag?token=value "
        f"https://x.test/next?token={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(QUERY_VALUE,),
    )


def test_query_ampersand_entity_is_not_decoded() -> None:
    # Raw parsing does not decode "&amp;" to "&". Because the scanner treats
    # ";" as a parameter separator, "&amp;token" is seen as a bare
    # "amp" parameter followed by a "token" parameter, and the token value
    # is still redacted. The important invariant is that no decoding happens:
    # the output still contains "&amp;" unchanged.
    assert_sanitized(
        f"https://x.test/path?theme=dark&amp;token={QUERY_VALUE}",
        f"https://x.test/path?theme=dark&amp;token={REDACTION_MARKER_QUERY_SECRET}",
        sensitive_values=(QUERY_VALUE,),
    )
    # A literal raw ampersand separator still works as expected.
    assert_sanitized(
        f"https://x.test/path?theme=dark&token={QUERY_VALUE}",
        f"https://x.test/path?theme=dark&token={REDACTION_MARKER_QUERY_SECRET}",
    )


def test_query_parameter_names_do_not_become_report_ids() -> None:
    sanitized, report = sanitize_text(f"?token={QUERY_VALUE}&sig={SECOND_QUERY_VALUE}")

    if QUERY_VALUE in sanitized or SECOND_QUERY_VALUE in sanitized:
        pytest.fail("sanitized text leaked synthetic query value")
    assert report.counts_by_rule == {RULE_ID_QUERY_SECRET: 2}
    for name in ("token", "sig"):
        if any(name in rule_id for rule_id in report.counts_by_rule):
            pytest.fail("report included a query parameter name")
