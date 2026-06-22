"""Golden fixture tests for end-to-end sanitization behavior."""

from __future__ import annotations

import re
from pathlib import Path

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
    SanitizationReport,
    sanitize_text,
)

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "golden"

FIXTURE_NAMES = (
    "http_request_mixed",
    "burp_repeater_like",
    "api_log_mixed",
    "mobile_api_trace_like",
    "report_note_mixed",
    "edge_cases_markers_and_malformed_cookie",
    "json_api_body_mixed",
    "form_urlencoded_body_mixed",
    "proxy_authorization_mixed",
)

EXPECTED_COUNTS = {
    "http_request_mixed": {
        "authorization.bearer": 1,
        "cookie.value": 3,
        "header.secret": 1,
        "query.secret": 3,
    },
    "burp_repeater_like": {
        "authorization.basic": 1,
        "cookie.header": 1,
        "header.secret": 1,
        "query.secret": 1,
    },
    "api_log_mixed": {
        "authorization.other": 1,
        "query.secret": 2,
    },
    "mobile_api_trace_like": {
        "authorization.bearer": 1,
        "cookie.value": 3,
        "header.secret": 1,
        "query.secret": 1,
    },
    "report_note_mixed": {
        "authorization.bearer": 1,
        "header.secret": 1,
        "query.secret": 2,
    },
    "edge_cases_markers_and_malformed_cookie": {
        "authorization.bearer": 1,
        "cookie.header": 1,
        "header.secret": 1,
        "query.secret": 2,
    },
    "json_api_body_mixed": {
        "authorization.bearer": 1,
        "json.value": 6,
    },
    "form_urlencoded_body_mixed": {
        "authorization.bearer": 1,
        "form.value": 10,
        "query.secret": 1,
    },
    "proxy_authorization_mixed": {
        "proxy_authorization.bearer": 1,
        "proxy_authorization.basic": 2,
        "proxy_authorization.other": 4,
        "query.secret": 1,
    },
}

RAW_SECRET_VALUES = {
    "http_request_mixed": (
        "synthetic-access-token",
        "synthetic-signature",
        "synthetic-api-key",
        "synthetic-bearer-token",
        "synthetic-session-cookie",
        "synthetic-telemetry-id",
        "synthetic-unknown-value",
    ),
    "burp_repeater_like": (
        "synthetic-signature",
        "synthetic-basic-token",
        "synthetic-csrf-token",
    ),
    "api_log_mixed": (
        "synthetic-amz-signature",
        "synthetic-key",
        "synthetic-signature",
        "synthetic-api-key",
    ),
    "mobile_api_trace_like": (
        "synthetic-access-token",
        "synthetic-bearer-token",
        "synthetic-auth-token",
        "synthetic-session-cookie",
        "synthetic-telemetry-value",
    ),
    "report_note_mixed": (
        "synthetic-query-token",
        "synthetic-bearer-token",
        "synthetic-api-key",
        "synthetic-signature",
    ),
    "edge_cases_markers_and_malformed_cookie": (
        "synthetic-bearer-token",
        "synthetic-signature",
        "synthetic-token",
    ),
    "json_api_body_mixed": (
        "synthetic-bearer-token",
        "synthetic-access-token",
        "synthetic-refresh-token",
        "synthetic-id-token",
        "synthetic-client-secret",
        "synthetic-password",
        "synthetic-api-key",
    ),
    "form_urlencoded_body_mixed": (
        "synthetic-bearer-token",
        "synthetic-access-token",
        "synthetic-refresh-token",
        "synthetic-client-secret",
        "synthetic-password",
        "synthetic-csrf-token",
        "synthetic-jwt-plus+value",
        "synthetic-api-key",
        "synthetic-nested-access-token",
        "synthetic-overlap-token",
        "synthetic-overlap-sig",
    ),
    "proxy_authorization_mixed": (
        "synthetic-proxy-bearer-token",
        "synthetic-proxy-basic-token+/=",
        'username="synthetic-proxy-user", realm="api", nonce="abc", response="def"',
        "synthetic-proxy-nested-query-token",
        "synthetic-proxy-nested-json-token",
        "synthetic-proxy-nested-form-token",
        "synthetic-normal-query-token",
    ),
}

APPROVED_RULE_IDS = (
    frozenset(EXPECTED_COUNTS["http_request_mixed"].keys())
    | frozenset(EXPECTED_COUNTS["burp_repeater_like"].keys())
    | frozenset(EXPECTED_COUNTS["api_log_mixed"].keys())
    | frozenset(EXPECTED_COUNTS["mobile_api_trace_like"].keys())
    | frozenset(EXPECTED_COUNTS["report_note_mixed"].keys())
    | frozenset(EXPECTED_COUNTS["edge_cases_markers_and_malformed_cookie"].keys())
    | frozenset(EXPECTED_COUNTS["json_api_body_mixed"].keys())
    | frozenset(EXPECTED_COUNTS["form_urlencoded_body_mixed"].keys())
    | frozenset(EXPECTED_COUNTS["proxy_authorization_mixed"].keys())
)

APPROVED_MARKERS = frozenset(
    (
        REDACTION_MARKER_AUTHORIZATION_BEARER,
        REDACTION_MARKER_AUTHORIZATION_BASIC,
        REDACTION_MARKER_AUTHORIZATION_CREDENTIALS,
        REDACTION_MARKER_COOKIE_VALUE,
        REDACTION_MARKER_COOKIE_HEADER,
        REDACTION_MARKER_HEADER_SECRET,
        REDACTION_MARKER_QUERY_SECRET,
        REDACTION_MARKER_JSON_VALUE,
        REDACTION_MARKER_FORM_VALUE,
        REDACTION_MARKER_PROXY_AUTHORIZATION_BEARER,
        REDACTION_MARKER_PROXY_AUTHORIZATION_BASIC,
        REDACTION_MARKER_PROXY_AUTHORIZATION_CREDENTIALS,
    )
)

_MARKER_PATTERN = re.compile(r"<REDACTED:[^>]+>")


@pytest.mark.parametrize("fixture_name", FIXTURE_NAMES)
def test_golden_fixture(fixture_name: str) -> None:
    input_text = (GOLDEN_DIR / f"{fixture_name}.input.txt").read_text(encoding="utf-8")
    expected_text = (GOLDEN_DIR / f"{fixture_name}.expected.txt").read_text(
        encoding="utf-8"
    )

    actual_text, report = sanitize_text(input_text)

    assert actual_text == expected_text
    assert report.counts_by_rule == EXPECTED_COUNTS[fixture_name]
    assert report.changed is True
    _assert_rule_ids_valid(report)
    _assert_no_raw_secrets_leaked(actual_text, fixture_name)
    _assert_only_approved_markers(actual_text)

    idempotent_text, idempotent_report = sanitize_text(actual_text)
    assert idempotent_text == actual_text
    assert idempotent_report.counts_by_rule == {}
    assert idempotent_report.changed is False


def _assert_rule_ids_valid(report: SanitizationReport) -> None:
    for rule_id in report.counts_by_rule:
        if rule_id not in APPROVED_RULE_IDS:
            pytest.fail(f"unexpected rule id in report: {rule_id}")


def _assert_no_raw_secrets_leaked(text: str, fixture_name: str) -> None:
    for value in RAW_SECRET_VALUES[fixture_name]:
        if value in text:
            pytest.fail(f"raw synthetic secret value leaked in {fixture_name}")


def _assert_only_approved_markers(text: str) -> None:
    for match in _MARKER_PATTERN.finditer(text):
        if match.group(0) not in APPROVED_MARKERS:
            pytest.fail(f"unexpected redaction marker in output: {match.group(0)}")
