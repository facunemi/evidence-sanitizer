"""Unit tests for JSON-like sensitive field sanitization rules."""

from __future__ import annotations

import pytest

from evidence_sanitizer.sanitizer import (
    REDACTION_MARKER,
    REDACTION_MARKER_AUTHORIZATION_BASIC,
    REDACTION_MARKER_COOKIE_HEADER,
    REDACTION_MARKER_COOKIE_VALUE,
    REDACTION_MARKER_HEADER_SECRET,
    REDACTION_MARKER_JSON_VALUE,
    REDACTION_MARKER_QUERY_SECRET,
    RULE_ID_AUTHORIZATION_BEARER,
    RULE_ID_COOKIE_VALUE,
    RULE_ID_HEADER_SECRET,
    RULE_ID_JSON_VALUE,
    RULE_ID_QUERY_SECRET,
    _find_json_field_values,
    sanitize_text,
)

JSON_VALUE = "synthetic-json-value"
SECOND_JSON_VALUE = "synthetic-second-json-value"
THIRD_JSON_VALUE = "synthetic-third-json-value"
APPROVED_JSON_NAMES = (
    "token",
    "access_token",
    "accessToken",
    "refresh_token",
    "refreshToken",
    "id_token",
    "idToken",
    "auth_token",
    "authToken",
    "jwt",
    "session",
    "session_id",
    "sessionId",
    "sid",
    "api_key",
    "apiKey",
    "apikey",
    "x_api_key",
    "xApiKey",
    "password",
    "passwd",
    "pwd",
    "client_secret",
    "clientSecret",
    "shared_secret",
    "sharedSecret",
    "private_key",
    "privateKey",
    "sig",
    "signature",
    "x_amz_signature",
    "xAmzSignature",
    "x_goog_signature",
    "xGoogSignature",
    "client_assertion",
    "clientAssertion",
    "saml_response",
    "samlResponse",
    "samlresponse",
)
DEFERRED_JSON_NAMES = (
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
    "client_id",
    "tenant_id",
    "account_id",
    "customer_id",
    "csrf",
    "csrf_token",
    "xsrf",
    "xsrf_token",
    "code_verifier",
    "state_name",
    "tokenizer",
    "access_token_expires",
    "password_policy",
    "secret_name",
    "signature_algorithm",
    "private_key_id",
)
NEAR_MISS_JSON_NAMES = (
    "tokenizer",
    "access_token_expires",
    "password_policy",
    "secret_name",
    "signature_algorithm",
    "code_verifier",
    "state_name",
    "private_key_id",
)
WRONG_FAMILY_MARKERS = (
    REDACTION_MARKER,
    REDACTION_MARKER_AUTHORIZATION_BASIC,
    REDACTION_MARKER_COOKIE_VALUE,
    REDACTION_MARKER_COOKIE_HEADER,
    REDACTION_MARKER_HEADER_SECRET,
    REDACTION_MARKER_QUERY_SECRET,
)


def assert_sanitized(
    source: str,
    expected: str,
    sensitive_values: tuple[str, ...] = (JSON_VALUE,),
    counts_by_rule: dict[str, int] | None = None,
) -> None:
    sanitized, report = sanitize_text(source)
    for value in sensitive_values:
        if value and value in sanitized:
            pytest.fail("sanitized text leaked synthetic json value")
    assert sanitized == expected
    expected_counts = (
        {RULE_ID_JSON_VALUE: len(sensitive_values)}
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


@pytest.mark.parametrize("name", APPROVED_JSON_NAMES)
def test_json_redacts_every_approved_field_name(name: str) -> None:
    assert_sanitized(
        f'{{"{name}": "{JSON_VALUE}"}}',
        f'{{"{name}": "{REDACTION_MARKER_JSON_VALUE}"}}',
    )


def test_json_snake_case_and_camel_case_variants() -> None:
    source = (
        '{"access_token": "alpha", "accessToken": "beta", '
        '"id_token": "gamma", "idToken": "delta"}'
    )
    expected = (
        '{"access_token": "<REDACTED:json.value>", '
        '"accessToken": "<REDACTED:json.value>", '
        '"id_token": "<REDACTED:json.value>", '
        '"idToken": "<REDACTED:json.value>"}'
    )

    assert_sanitized(
        source,
        expected,
        sensitive_values=("alpha", "beta", "gamma", "delta"),
        counts_by_rule={RULE_ID_JSON_VALUE: 4},
    )


def test_json_case_insensitive_field_name_matching() -> None:
    assert_sanitized(
        '{"ACCESS_TOKEN": "abc", "ApiKey": "def"}',
        '{"ACCESS_TOKEN": "<REDACTED:json.value>", "ApiKey": "<REDACTED:json.value>"}',
        sensitive_values=("abc", "def"),
        counts_by_rule={RULE_ID_JSON_VALUE: 2},
    )


@pytest.mark.parametrize("name", DEFERRED_JSON_NAMES)
def test_json_deferred_names_remain_unchanged(name: str) -> None:
    assert_unchanged(f'{{"{name}": "{JSON_VALUE}"}}')


@pytest.mark.parametrize("name", NEAR_MISS_JSON_NAMES)
def test_json_near_miss_names_remain_unchanged(name: str) -> None:
    assert_unchanged(f'{{"{name}": "{JSON_VALUE}"}}')


def test_json_exact_matching_only() -> None:
    assert_unchanged('{"my_token": "abc"}')
    assert_unchanged('{"token_value": "abc"}')
    assert_unchanged('{"prefixtoken": "abc"}')


def test_json_punctuation_is_distinct() -> None:
    source = (
        '{"api_key": "alpha", "api-key": "beta", "apikey": "gamma", '
        '"apiKey": "delta", "x_api_key": "echo", '
        '"xApiKey": "foxtrot", "api.key": "golf"}'
    )
    expected = (
        '{"api_key": "<REDACTED:json.value>", "api-key": "beta", '
        '"apikey": "<REDACTED:json.value>", '
        '"apiKey": "<REDACTED:json.value>", '
        '"x_api_key": "<REDACTED:json.value>", '
        '"xApiKey": "<REDACTED:json.value>", '
        '"api.key": "golf"}'
    )

    assert_sanitized(
        source,
        expected,
        sensitive_values=("alpha", "gamma", "delta", "echo", "foxtrot"),
        counts_by_rule={RULE_ID_JSON_VALUE: 5},
    )


def test_json_string_values_redact() -> None:
    assert_sanitized(
        '{"token": "abc"}',
        '{"token": "<REDACTED:json.value>"}',
        sensitive_values=("abc",),
    )


def test_json_non_string_direct_values_remain_unchanged() -> None:
    source = '{"token": 123, "token": true, "token": false, "token": null}'
    assert_unchanged(source)


def test_json_array_and_object_direct_values_remain_unchanged() -> None:
    source = '{"token": ["abc"], "token": {"nested": "abc"}}'
    assert_unchanged(source)


def test_json_nested_approved_string_fields_redact() -> None:
    source = '{"outer": {"token": "abc"}, "items": [{"apiKey": "def"}]}'
    expected = (
        '{"outer": {"token": "<REDACTED:json.value>"}, '
        '"items": [{"apiKey": "<REDACTED:json.value>"}]}'
    )

    assert_sanitized(
        source,
        expected,
        sensitive_values=("abc", "def"),
        counts_by_rule={RULE_ID_JSON_VALUE: 2},
    )


def test_json_empty_string_value_redacts() -> None:
    assert_sanitized(
        '{"token": ""}',
        '{"token": "<REDACTED:json.value>"}',
        sensitive_values=(),
        counts_by_rule={RULE_ID_JSON_VALUE: 1},
    )


def test_json_preserves_formatting_and_whitespace() -> None:
    source = '{\n  "token" : "abc" ,\n  "other" : "def"\n}'
    expected = '{\n  "token" : "<REDACTED:json.value>" ,\n  "other" : "def"\n}'

    assert_sanitized(
        source,
        expected,
        sensitive_values=("abc",),
    )


def test_json_escaped_quote_in_value() -> None:
    value = 'synthetic\\"quote'
    assert_sanitized(
        f'{{"token": "{value}"}}',
        '{"token": "<REDACTED:json.value>"}',
        sensitive_values=(value,),
    )


def test_json_escaped_backslash_in_value() -> None:
    value = "synthetic\\\\path"
    assert_sanitized(
        f'{{"token": "{value}"}}',
        '{"token": "<REDACTED:json.value>"}',
        sensitive_values=(value,),
    )


def test_json_valid_unicode_escape_in_value() -> None:
    value = "synthetic\\u0041value"
    assert_sanitized(
        f'{{"token": "{value}"}}',
        '{"token": "<REDACTED:json.value>"}',
        sensitive_values=(value,),
    )


def test_json_unicode_escape_not_decoded_for_matching() -> None:
    assert_unchanged('{"access\\u005Ftoken": "abc"}')


def test_json_literal_newline_in_string_is_skipped() -> None:
    assert_unchanged('{"token": "abc\ndef"}')


def test_json_invalid_escape_is_skipped() -> None:
    assert_unchanged('{"token": "abc\\xdef"}')


def test_json_unterminated_string_is_skipped() -> None:
    assert_unchanged('{"token": "abc')


def test_json_repeated_fields_counted() -> None:
    source = '{"token": "xyz", "token": "uvw", "other": "keep"}'
    expected = (
        '{"token": "<REDACTED:json.value>", '
        '"token": "<REDACTED:json.value>", "other": "keep"}'
    )

    assert_sanitized(
        source,
        expected,
        sensitive_values=("xyz", "uvw"),
        counts_by_rule={RULE_ID_JSON_VALUE: 2},
    )


def test_json_multiple_snippets_in_one_file() -> None:
    source = (
        'log: {"token": "xyz"}\nnote: {"password": "uvw"}\nbody {"apiKey": "rst"}\n'
    )
    expected = (
        'log: {"token": "<REDACTED:json.value>"}\n'
        'note: {"password": "<REDACTED:json.value>"}\n'
        'body {"apiKey": "<REDACTED:json.value>"}\n'
    )

    assert_sanitized(
        source,
        expected,
        sensitive_values=("xyz", "uvw", "rst"),
        counts_by_rule={RULE_ID_JSON_VALUE: 3},
    )


def test_json_exact_marker_is_idempotent() -> None:
    assert_unchanged(f'{{"token": "{REDACTION_MARKER_JSON_VALUE}"}}')
    assert_unchanged(
        f'{{"token": "{REDACTION_MARKER_JSON_VALUE}", '
        f'"apiKey": "{REDACTION_MARKER_JSON_VALUE}"}}'
    )


def test_json_embedded_marker_is_redacted() -> None:
    value = f"prefix{REDACTION_MARKER_JSON_VALUE}suffix"
    assert_sanitized(
        f'{{"token": "{value}"}}',
        '{"token": "<REDACTED:json.value>"}',
        sensitive_values=(value,),
    )


def test_json_unapproved_marker_like_value_is_redacted() -> None:
    value = "<REDACTED:json.token>"
    assert_sanitized(
        f'{{"token": "{value}"}}',
        '{"token": "<REDACTED:json.value>"}',
        sensitive_values=(value,),
    )


@pytest.mark.parametrize("marker", WRONG_FAMILY_MARKERS)
def test_json_wrong_family_markers_are_redacted(marker: str) -> None:
    assert_sanitized(
        f'{{"token": "{marker}"}}',
        '{"token": "<REDACTED:json.value>"}',
        sensitive_values=(marker,),
    )


def test_json_overlapping_authorization_findings_are_skipped() -> None:
    assert_sanitized(
        f'Authorization: Bearer {{"access_token":"{JSON_VALUE}"}}',
        f"Authorization: Bearer {REDACTION_MARKER}",
        sensitive_values=(JSON_VALUE,),
        counts_by_rule={RULE_ID_AUTHORIZATION_BEARER: 1},
    )


def test_json_overlapping_cookie_findings_are_skipped() -> None:
    assert_sanitized(
        f'Cookie: session={{"token":"{JSON_VALUE}"}}',
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}",
        sensitive_values=(JSON_VALUE,),
        counts_by_rule={RULE_ID_COOKIE_VALUE: 1},
    )


def test_json_overlapping_sensitive_header_findings_are_skipped() -> None:
    assert_sanitized(
        f'X-API-Key: {{"token":"{JSON_VALUE}"}}',
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}",
        sensitive_values=(JSON_VALUE,),
        counts_by_rule={RULE_ID_HEADER_SECRET: 1},
    )


def test_json_overlapping_query_findings_are_skipped() -> None:
    assert_sanitized(
        f'GET /api?token={{"access_token":"{JSON_VALUE}"}} HTTP/1.1',
        f"GET /api?token={REDACTION_MARKER_QUERY_SECRET} HTTP/1.1",
        sensitive_values=(JSON_VALUE,),
        counts_by_rule={RULE_ID_QUERY_SECRET: 1},
    )


def test_json_empty_value_inside_query_finding_is_skipped() -> None:
    assert_sanitized(
        'GET /api?token={"access_token":""} HTTP/1.1',
        f"GET /api?token={REDACTION_MARKER_QUERY_SECRET} HTTP/1.1",
        sensitive_values=(),
        counts_by_rule={RULE_ID_QUERY_SECRET: 1},
    )


def test_json_array_inside_sensitive_query_parameter_is_covered() -> None:
    assert_sanitized(
        f'GET /api?token=[{{"access_token":"{JSON_VALUE}"}}] HTTP/1.1',
        f"GET /api?token={REDACTION_MARKER_QUERY_SECRET} HTTP/1.1",
        sensitive_values=(JSON_VALUE,),
        counts_by_rule={RULE_ID_QUERY_SECRET: 1},
    )


def test_json_inside_preserved_harmless_cookie_value_is_redacted() -> None:
    assert_sanitized(
        f'Cookie: theme={{"token":"{JSON_VALUE}"}}',
        f'Cookie: theme={{"token":"{REDACTION_MARKER_JSON_VALUE}"}}',
    )


def test_json_inside_non_sensitive_query_parameter_is_redacted() -> None:
    assert_sanitized(
        f'?payload={{"access_token":"{JSON_VALUE}"}}',
        f'?payload={{"access_token":"{REDACTION_MARKER_JSON_VALUE}"}}',
    )


def test_json_idempotence() -> None:
    source = '{"token": "xyz", "apiKey": "uvw"}'
    first, first_report = sanitize_text(source)
    second, second_report = sanitize_text(first)

    assert "xyz" not in first and "xyz" not in second
    assert "uvw" not in first and "uvw" not in second
    assert first == second
    assert first_report.counts_by_rule == {RULE_ID_JSON_VALUE: 2}
    assert second_report.counts_by_rule == {}


def test_json_findings_store_no_raw_value_or_field_name() -> None:
    source = f'{{"token": "{JSON_VALUE}", "apiKey": "{SECOND_JSON_VALUE}"}}'
    findings = _find_json_field_values(source, ())

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
    for sensitive_text in (JSON_VALUE, SECOND_JSON_VALUE, "token", "apiKey"):
        if any(sensitive_text in value for value in stored_values):
            pytest.fail("finding stored synthetic json data")


def test_json_field_names_do_not_become_report_ids() -> None:
    sanitized, report = sanitize_text(
        f'{{"token": "{JSON_VALUE}", "apiKey": "{SECOND_JSON_VALUE}"}}'
    )

    assert JSON_VALUE not in sanitized
    assert SECOND_JSON_VALUE not in sanitized
    assert report.counts_by_rule == {RULE_ID_JSON_VALUE: 2}
    for name in ("token", "apiKey"):
        if any(name in rule_id for rule_id in report.counts_by_rule):
            pytest.fail("report included a json field name")


def test_json_escaped_solidus_and_common_escapes() -> None:
    value = "synthetic/path\\n"
    assert_sanitized(
        f'{{"token": "{value}"}}',
        '{"token": "<REDACTED:json.value>"}',
        sensitive_values=(value,),
    )


def test_json_mixed_rules_in_one_file() -> None:
    source = (
        f"Authorization: Bearer {JSON_VALUE}\n"
        f"Cookie: session={JSON_VALUE}; theme=dark\n"
        f"X-API-Key: {JSON_VALUE}\n"
        f"GET /api?token={JSON_VALUE} HTTP/1.1\n"
        f'{{"token": "{SECOND_JSON_VALUE}", "password": "{THIRD_JSON_VALUE}"}}\n'
    )
    expected = (
        f"Authorization: Bearer {REDACTION_MARKER}\n"
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}; theme=dark\n"
        f"X-API-Key: {REDACTION_MARKER_HEADER_SECRET}\n"
        f"GET /api?token={REDACTION_MARKER_QUERY_SECRET} HTTP/1.1\n"
        f'{{"token": "{REDACTION_MARKER_JSON_VALUE}", '
        f'"password": "{REDACTION_MARKER_JSON_VALUE}"}}\n'
    )

    assert_sanitized(
        source,
        expected,
        sensitive_values=(JSON_VALUE, SECOND_JSON_VALUE, THIRD_JSON_VALUE),
        counts_by_rule={
            RULE_ID_AUTHORIZATION_BEARER: 1,
            RULE_ID_COOKIE_VALUE: 1,
            RULE_ID_HEADER_SECRET: 1,
            RULE_ID_QUERY_SECRET: 1,
            RULE_ID_JSON_VALUE: 2,
        },
    )
