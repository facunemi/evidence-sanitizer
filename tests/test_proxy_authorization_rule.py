"""Unit tests for Proxy-Authorization header sanitization rules."""

from __future__ import annotations

import pytest

from evidence_sanitizer.sanitizer import (
    REDACTION_MARKER_AUTHORIZATION_BASIC,
    REDACTION_MARKER_AUTHORIZATION_BEARER,
    REDACTION_MARKER_AUTHORIZATION_CREDENTIALS,
    REDACTION_MARKER_COOKIE_HEADER,
    REDACTION_MARKER_COOKIE_VALUE,
    REDACTION_MARKER_FORM_VALUE,
    REDACTION_MARKER_HEADER_SECRET,
    REDACTION_MARKER_JSON_VALUE,
    REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC,
    REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER,
    REDACTION_MARKER_PROXY_AUTHORIZATION_CREDENTIALS,
    REDACTION_MARKER_QUERY_SECRET,
    RULE_ID_FORM_VALUE,
    RULE_ID_JSON_VALUE,
    RULE_ID_PROXY_AUTHORIZATION_BASIC,
    RULE_ID_PROXY_AUTHORIZATION_BEARER,
    RULE_ID_PROXY_AUTHORIZATION_OTHER,
    RULE_ID_QUERY_SECRET,
    _find_proxy_authorization_credentials,
    sanitize_text,
)

BEARER_TOKEN = "synthetic-proxy-bearer-token"
BASIC_TOKEN = "synthetic-proxy-basic-token+/="
DIGEST_CREDENTIAL = (
    'username="synthetic-proxy-user", realm="api", '
    'nonce="synthetic-proxy-nonce", response="synthetic-proxy-response"'
)
NEGOTIATE_TOKEN = "synthetic-negotiate-token"
CUSTOM_TOKEN = "synthetic-custom-proxy-token"

PROXY_MARKERS = (
    REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER,
    REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC,
    REDACTION_MARKER_PROXY_AUTHORIZATION_CREDENTIALS,
)

NON_PROXY_MARKERS = (
    REDACTION_MARKER_AUTHORIZATION_BEARER,
    REDACTION_MARKER_AUTHORIZATION_BASIC,
    REDACTION_MARKER_AUTHORIZATION_CREDENTIALS,
    REDACTION_MARKER_HEADER_SECRET,
    REDACTION_MARKER_QUERY_SECRET,
    REDACTION_MARKER_JSON_VALUE,
    REDACTION_MARKER_FORM_VALUE,
    REDACTION_MARKER_COOKIE_VALUE,
    REDACTION_MARKER_COOKIE_HEADER,
)


def assert_sanitized(
    source: str,
    expected: str,
    tokens: tuple[str, ...] = (),
    counts_by_rule: dict[str, int] | None = None,
) -> None:
    sanitized, report = sanitize_text(source)
    for token in tokens:
        if token in sanitized:
            pytest.fail("sanitized text leaked synthetic credential")
    assert sanitized == expected
    if counts_by_rule is not None:
        assert report.counts_by_rule == counts_by_rule


def assert_unchanged(source: str) -> None:
    sanitized, report = sanitize_text(source)
    if sanitized != source:
        pytest.fail("text changed unexpectedly")
    assert report.counts_by_rule == {}
    assert not report.changed


def test_bearer_credential_redaction() -> None:
    assert_sanitized(
        f"Proxy-Authorization: Bearer {BEARER_TOKEN}\n",
        f"Proxy-Authorization: Bearer {REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n",
        tokens=(BEARER_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BEARER: 1},
    )


def test_basic_credential_redaction() -> None:
    assert_sanitized(
        f"Proxy-Authorization: Basic {BASIC_TOKEN}\n",
        f"Proxy-Authorization: Basic {REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC}\n",
        tokens=(BASIC_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BASIC: 1},
    )


def test_generic_digest_redaction() -> None:
    assert_sanitized(
        f"Proxy-Authorization: Digest {DIGEST_CREDENTIAL}\n",
        "Proxy-Authorization: Digest "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_CREDENTIALS}\n",
        tokens=(DIGEST_CREDENTIAL,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_OTHER: 1},
    )


def test_generic_negotiate_redaction() -> None:
    assert_sanitized(
        f"Proxy-Authorization: Negotiate {NEGOTIATE_TOKEN}\n",
        "Proxy-Authorization: Negotiate "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_CREDENTIALS}\n",
        tokens=(NEGOTIATE_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_OTHER: 1},
    )


def test_generic_ntlm_redaction() -> None:
    token = "synthetic-ntlm-token"
    assert_sanitized(
        f"Proxy-Authorization: NTLM {token}\n",
        "Proxy-Authorization: NTLM "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_CREDENTIALS}\n",
        tokens=(token,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_OTHER: 1},
    )


def test_generic_custom_valid_scheme_redaction() -> None:
    assert_sanitized(
        f"Proxy-Authorization: ProxyScheme {CUSTOM_TOKEN}\n",
        "Proxy-Authorization: ProxyScheme "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_CREDENTIALS}\n",
        tokens=(CUSTOM_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_OTHER: 1},
    )


def test_scheme_casing_preservation() -> None:
    assert_sanitized(
        f"Proxy-Authorization: bearer {BEARER_TOKEN}\n",
        f"Proxy-Authorization: bearer {REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n",
        tokens=(BEARER_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BEARER: 1},
    )
    assert_sanitized(
        f"Proxy-Authorization: bAsIc {BASIC_TOKEN}\n",
        f"Proxy-Authorization: bAsIc {REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC}\n",
        tokens=(BASIC_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BASIC: 1},
    )
    assert_sanitized(
        f"Proxy-Authorization: DiGeSt {DIGEST_CREDENTIAL}\n",
        "Proxy-Authorization: DiGeSt "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_CREDENTIALS}\n",
        tokens=(DIGEST_CREDENTIAL,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_OTHER: 1},
    )


def test_header_name_casing_preservation() -> None:
    assert_sanitized(
        f"proxy-authorization: Bearer {BEARER_TOKEN}\n",
        f"proxy-authorization: Bearer {REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n",
        tokens=(BEARER_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BEARER: 1},
    )
    assert_sanitized(
        f"PROXY-AUTHORIZATION: Basic {BASIC_TOKEN}\n",
        f"PROXY-AUTHORIZATION: Basic {REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC}\n",
        tokens=(BASIC_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BASIC: 1},
    )


def test_spaces_and_tabs_around_colon() -> None:
    cases = (
        (
            f"Proxy-Authorization:Bearer {BEARER_TOKEN}\n",
            "Proxy-Authorization:Bearer "
            f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n",
        ),
        (
            f"Proxy-Authorization : Bearer {BEARER_TOKEN}\n",
            "Proxy-Authorization : Bearer "
            f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n",
        ),
        (
            f"Proxy-Authorization:\tBasic\t{BASIC_TOKEN}\n",
            "Proxy-Authorization:\tBasic\t"
            f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC}\n",
        ),
    )
    for source, expected in cases:
        assert_sanitized(
            source,
            expected,
            tokens=(BEARER_TOKEN,),
            counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BEARER: 1},
        ) if "Bearer" in source else assert_sanitized(
            source,
            expected,
            tokens=(BASIC_TOKEN,),
            counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BASIC: 1},
        )


def test_spaces_and_tabs_before_credentials() -> None:
    assert_sanitized(
        f"Proxy-Authorization: Bearer    {BEARER_TOKEN}\n",
        "Proxy-Authorization: Bearer    "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n",
        tokens=(BEARER_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BEARER: 1},
    )
    assert_sanitized(
        f"Proxy-Authorization: Basic\t\t{BASIC_TOKEN}\n",
        f"Proxy-Authorization: Basic\t\t{REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC}\n",
        tokens=(BASIC_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BASIC: 1},
    )


def test_trailing_spaces_and_tabs() -> None:
    assert_sanitized(
        f"Proxy-Authorization: Bearer {BEARER_TOKEN}   \n",
        "Proxy-Authorization: Bearer "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}   \n",
        tokens=(BEARER_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BEARER: 1},
    )
    assert_sanitized(
        f"Proxy-Authorization: Basic {BASIC_TOKEN}\t \n",
        f"Proxy-Authorization: Basic {REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC}\t \n",
        tokens=(BASIC_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BASIC: 1},
    )


def test_crlf_and_lf() -> None:
    assert_sanitized(
        f"Proxy-Authorization: Bearer {BEARER_TOKEN}\n",
        f"Proxy-Authorization: Bearer {REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n",
        tokens=(BEARER_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BEARER: 1},
    )
    assert_sanitized(
        f"Proxy-Authorization: Bearer {BEARER_TOKEN}\r\n",
        "Proxy-Authorization: Bearer "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\r\n",
        tokens=(BEARER_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BEARER: 1},
    )


def test_final_line_without_newline() -> None:
    assert_sanitized(
        f"Proxy-Authorization: Bearer {BEARER_TOKEN}",
        f"Proxy-Authorization: Bearer {REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}",
        tokens=(BEARER_TOKEN,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BEARER: 1},
    )


def test_multiple_proxy_authorization_headers() -> None:
    source = (
        f"Proxy-Authorization: Bearer {BEARER_TOKEN}\n"
        "Accept: application/json\n"
        f"Proxy-Authorization: Basic {BASIC_TOKEN}\n"
        f"Proxy-Authorization: Digest {DIGEST_CREDENTIAL}\n"
    )
    expected = (
        "Proxy-Authorization: Bearer "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n"
        "Accept: application/json\n"
        "Proxy-Authorization: Basic "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC}\n"
        "Proxy-Authorization: Digest "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_CREDENTIALS}\n"
    )

    assert_sanitized(
        source,
        expected,
        tokens=(BEARER_TOKEN, BASIC_TOKEN, DIGEST_CREDENTIAL),
        counts_by_rule={
            RULE_ID_PROXY_AUTHORIZATION_BEARER: 1,
            RULE_ID_PROXY_AUTHORIZATION_BASIC: 1,
            RULE_ID_PROXY_AUTHORIZATION_OTHER: 1,
        },
    )


def test_counts_per_proxy_rule_id() -> None:
    source = (
        f"Proxy-Authorization: Bearer {BEARER_TOKEN}\n"
        f"Proxy-Authorization: Bearer {BEARER_TOKEN}-second\n"
        f"Proxy-Authorization: Basic {BASIC_TOKEN}\n"
        f"Proxy-Authorization: Digest {DIGEST_CREDENTIAL}\n"
    )
    _, report = sanitize_text(source)
    assert report.counts_by_rule == {
        RULE_ID_PROXY_AUTHORIZATION_BEARER: 2,
        RULE_ID_PROXY_AUTHORIZATION_BASIC: 1,
        RULE_ID_PROXY_AUTHORIZATION_OTHER: 1,
    }


def test_exact_proxy_marker_idempotence() -> None:
    for marker in PROXY_MARKERS:
        assert_unchanged(f"Proxy-Authorization: Bearer {marker}\n")
        assert_unchanged(f"Proxy-Authorization: Basic {marker}\n")
        assert_unchanged(f"Proxy-Authorization: Custom {marker}\n")
        assert_unchanged(f"Proxy-Authorization: Bearer {marker}\t \n")


def test_wrong_proxy_marker_under_another_scheme_accepted() -> None:
    assert_unchanged(
        f"Proxy-Authorization: Bearer {REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC}\n"
    )
    assert_unchanged(
        f"Proxy-Authorization: Basic {REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n"
    )
    assert_unchanged(
        f"Proxy-Authorization: Custom {REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n"
    )


def test_embedded_proxy_marker_redacted() -> None:
    credential = f"prefix{REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}suffix"
    assert_sanitized(
        f"Proxy-Authorization: Bearer {credential}\n",
        f"Proxy-Authorization: Bearer {REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n",
        tokens=(credential,),
        counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BEARER: 1},
    )


def test_wrong_family_non_proxy_markers_re_redacted() -> None:
    for marker in NON_PROXY_MARKERS:
        assert_sanitized(
            f"Proxy-Authorization: Bearer {marker}\n",
            "Proxy-Authorization: Bearer "
            f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n",
            counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BEARER: 1},
        )
        assert_sanitized(
            f"Proxy-Authorization: Basic {marker}\n",
            "Proxy-Authorization: Basic "
            f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC}\n",
            counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_BASIC: 1},
        )
        assert_sanitized(
            f"Proxy-Authorization: Custom {marker}\n",
            "Proxy-Authorization: Custom "
            f"{REDACTION_MARKER_PROXY_AUTHORIZATION_CREDENTIALS}\n",
            counts_by_rule={RULE_ID_PROXY_AUTHORIZATION_OTHER: 1},
        )


def test_empty_and_whitespace_only_values_unchanged() -> None:
    cases = (
        "Proxy-Authorization:\n",
        "Proxy-Authorization:    \n",
        "Proxy-Authorization:\t\t\n",
        "Proxy-Authorization: Bearer\n",
        "Proxy-Authorization: Bearer    \n",
        "Proxy-Authorization: Bearer\t\t\n",
        "Proxy-Authorization: Basic\n",
        "Proxy-Authorization: Custom\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_malformed_bearer_basic_unchanged() -> None:
    cases = (
        "Proxy-Authorization: Bearer first second\n",
        "Proxy-Authorization: Bearer first\tsecond\n",
        "Proxy-Authorization: Basic first second\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_unicode_auth_scheme_unchanged() -> None:
    cases = (
        "Proxy-Authorization: Münch token\n",
        "Proxy-Authorization: 認証 token\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_indented_and_folded_forms_unchanged() -> None:
    cases = (
        " Proxy-Authorization: Bearer token\n",
        "Proxy-Authorization: Bearer token\n continuation\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_proxy_authenticate_www_authenticate_x_proxy_unchanged() -> None:
    cases = (
        "Proxy-Authenticate: Bearer token\n",
        "WWW-Authenticate: Bearer token\n",
        "X-Proxy-Authorization: Bearer token\n",
        "Forwarded: for=proxy\n",
        "X-Forwarded-For: proxy\n",
        "X-Original-Url: /api\n",
        "Via: 1.1 proxy\n",
    )
    for source in cases:
        assert_unchanged(source)


def test_prose_unchanged() -> None:
    assert_unchanged("The proxy uses Bearer authentication.\n")


def test_overlap_suppresses_nested_query_json_form_inside_credentials() -> None:
    source = (
        "Proxy-Authorization: Bearer https://x.test/?token=synthetic-nested-token\n"
        'Proxy-Authorization: Custom {"token":"synthetic-nested-json"}\n'
        "Proxy-Authorization: Basic access_token=synthetic-nested-form\n"
    )
    expected = (
        "Proxy-Authorization: Bearer "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n"
        "Proxy-Authorization: Custom "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_CREDENTIALS}\n"
        "Proxy-Authorization: Basic "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC}\n"
    )

    assert_sanitized(
        source,
        expected,
        tokens=(
            "synthetic-nested-token",
            "synthetic-nested-json",
            "synthetic-nested-form",
        ),
        counts_by_rule={
            RULE_ID_PROXY_AUTHORIZATION_BEARER: 1,
            RULE_ID_PROXY_AUTHORIZATION_OTHER: 1,
            RULE_ID_PROXY_AUTHORIZATION_BASIC: 1,
        },
    )


def test_normal_query_strings_outside_proxy_credentials_still_redacted() -> None:
    source = (
        "Proxy-Authorization: Bearer token\n"
        "Referer: https://app.test/?token=synthetic-referer-token\n"
    )
    expected = (
        "Proxy-Authorization: Bearer "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER}\n"
        f"Referer: https://app.test/?token={REDACTION_MARKER_QUERY_SECRET}\n"
    )

    assert_sanitized(
        source,
        expected,
        tokens=("synthetic-referer-token",),
        counts_by_rule={
            RULE_ID_PROXY_AUTHORIZATION_BEARER: 1,
            RULE_ID_QUERY_SECRET: 1,
        },
    )


def test_findings_do_not_store_raw_credentials() -> None:
    source = (
        f"Proxy-Authorization: Bearer {BEARER_TOKEN}\n"
        f"Proxy-Authorization: Basic {BASIC_TOKEN}\n"
        f"Proxy-Authorization: Digest {DIGEST_CREDENTIAL}\n"
    )
    findings = _find_proxy_authorization_credentials(source)

    assert len(findings) == 3
    stored = tuple(
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
    for token in (BEARER_TOKEN, BASIC_TOKEN, DIGEST_CREDENTIAL):
        if any(token in value for value in stored):
            pytest.fail("finding stored synthetic proxy credential")


def test_proxy_authorization_idempotence() -> None:
    source = (
        f"Proxy-Authorization: Bearer {BEARER_TOKEN}\n"
        f"Proxy-Authorization: Basic {BASIC_TOKEN}\n"
        f"Proxy-Authorization: Digest {DIGEST_CREDENTIAL}\n"
    )
    first, first_report = sanitize_text(source)
    second, second_report = sanitize_text(first)

    assert first == second
    assert first_report.counts_by_rule == {
        RULE_ID_PROXY_AUTHORIZATION_BEARER: 1,
        RULE_ID_PROXY_AUTHORIZATION_BASIC: 1,
        RULE_ID_PROXY_AUTHORIZATION_OTHER: 1,
    }
    assert second_report.counts_by_rule == {}


def test_folded_proxy_authorization_with_query_like_credential_unchanged() -> None:
    source = (
        "Proxy-Authorization: Custom https://proxy.example.test/cb?token=synthetic-token\n"
        " continuation\n"
    )
    sanitized, report = sanitize_text(source)

    assert sanitized == source
    assert not report.changed
    assert report.counts_by_rule == {}
    assert report.counts_by_rule.get(RULE_ID_QUERY_SECRET) is None


def test_folded_proxy_authorization_with_json_like_credential_unchanged() -> None:
    source = (
        'Proxy-Authorization: Custom {"access_token":"synthetic-token"}\n'
        " continuation\n"
    )
    sanitized, report = sanitize_text(source)

    assert sanitized == source
    assert not report.changed
    assert report.counts_by_rule == {}
    assert report.counts_by_rule.get(RULE_ID_JSON_VALUE) is None


def test_folded_proxy_authorization_with_form_like_credential_unchanged() -> None:
    source = (
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        "Proxy-Authorization: Custom "
        "access_token=synthetic-token&client_secret=synthetic-secret\n"
        " continuation\n"
    )
    sanitized, report = sanitize_text(source)

    assert sanitized == source
    assert not report.changed
    assert report.counts_by_rule == {}
    assert report.counts_by_rule.get(RULE_ID_FORM_VALUE) is None
    assert report.counts_by_rule.get(RULE_ID_QUERY_SECRET) is None


def test_non_folded_proxy_authorization_with_nested_query_redacts_proxy() -> None:
    token = "synthetic-nested-query-token"
    source = f"Proxy-Authorization: Digest token=https://x.test/?sig={token}\n"
    expected = (
        "Proxy-Authorization: Digest "
        f"{REDACTION_MARKER_PROXY_AUTHORIZATION_CREDENTIALS}\n"
    )

    sanitized, report = sanitize_text(source)

    assert sanitized == expected
    assert token not in sanitized
    assert report.counts_by_rule == {RULE_ID_PROXY_AUTHORIZATION_OTHER: 1}
    assert report.counts_by_rule.get(RULE_ID_QUERY_SECRET) is None


def test_query_string_outside_folded_proxy_still_redacted() -> None:
    source = (
        "Proxy-Authorization: Bearer synthetic-token\n"
        " continuation\n"
        "Referer: https://app.test/?token=synthetic-referer-token\n"
    )
    expected = (
        "Proxy-Authorization: Bearer synthetic-token\n"
        " continuation\n"
        f"Referer: https://app.test/?token={REDACTION_MARKER_QUERY_SECRET}\n"
    )

    sanitized, report = sanitize_text(source)

    assert sanitized == expected
    assert report.counts_by_rule == {RULE_ID_QUERY_SECRET: 1}
    assert report.counts_by_rule.get(RULE_ID_PROXY_AUTHORIZATION_BEARER) is None
