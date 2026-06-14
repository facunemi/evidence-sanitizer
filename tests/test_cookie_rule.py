"""Unit tests for Cookie header sanitization rules."""

from __future__ import annotations

import time

import pytest

from evidence_sanitizer import sanitizer as sanitizer_module
from evidence_sanitizer.sanitizer import (
    COOKIE_CATEGORY_HARMLESS,
    COOKIE_CATEGORY_SENSITIVE,
    COOKIE_CATEGORY_TELEMETRY,
    COOKIE_CATEGORY_UNKNOWN,
    REDACTION_MARKER_COOKIE_HEADER,
    REDACTION_MARKER_COOKIE_VALUE,
    RULE_ID_AUTHORIZATION_BEARER,
    RULE_ID_COOKIE_HEADER,
    RULE_ID_COOKIE_VALUE,
    _classify_cookie_name,
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
COOKIE_EMBEDDED_HEADER_MARKER_VALUE = f"raw{REDACTION_MARKER_COOKIE_HEADER}value"
UNAPPROVED_COOKIE_MARKER_LIKE_VALUES = (
    "<REDACTED:cookie.sensitive>",
    "<REDACTED:cookie.unknown>",
    "<REDACTED:cookie.telemetry>",
    "<REDACTED:cookie.harmless>",
)
APPROVED_SENSITIVE_EXACT_COOKIE_NAMES = (
    "session",
    "sessionid",
    "session_id",
    "sid",
    "auth",
    "auth_token",
    "access_token",
    "refresh_token",
    "token",
    "jwt",
    "sso",
    "sso_state",
    "username",
    "user",
    "userid",
    "user_id",
    "email",
    "identity",
    "account",
    "account_id",
    "customer",
    "customer_id",
    "tenant",
    "tenant_id",
    "portalauth",
    "asp.net_sessionid",
    "jsessionid",
    "phpsessid",
    "connect.sid",
    "laravel_session",
)
SENSITIVE_NEAR_MISS_COOKIE_NAMES = (
    "superuser_setting",
    "sessionStorageEnabled",
    "consider",
    "tokenizer_mode",
    "author_theme",
)
APPROVED_TELEMETRY_EXACT_COOKIE_NAMES = (
    "_ga",
    "_gid",
    "_gat",
    "_fbp",
    "_fbc",
    "_hjid",
    "_clck",
    "_clsk",
    "ajs_anonymous_id",
    "ajs_user_id",
    "_mkto_trk",
    "hubspotutk",
    "__hstc",
    "__hssc",
    "__hssrc",
)
APPROVED_HARMLESS_EXACT_COOKIE_NAMES = ("theme", "color_scheme", "display_mode")
HARMLESS_NEAR_MISS_COOKIE_NAMES = (
    "user_theme",
    "theme_token",
    "display_mode_session",
    "color_scheme_auth",
)
DEFERRED_HARMLESS_CANDIDATE_NAMES = (
    "language",
    "lang",
    "locale",
    "timezone",
    "tz",
    "cookie_consent",
    "consent",
    "banner_dismissed",
    "sidebar_state",
)


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


@pytest.mark.parametrize("name", APPROVED_SENSITIVE_EXACT_COOKIE_NAMES)
def test_cookie_classifies_approved_sensitive_exact_names(name: str) -> None:
    assert _classify_cookie_name(name.upper()) == COOKIE_CATEGORY_SENSITIVE


@pytest.mark.parametrize(
    "name",
    (
        "ASPSESSIONID",
        "ASPSESSIONIDABC123",
        "remember_web_abc123",
        "remember_web_user-token",
    ),
)
def test_cookie_classifies_sensitive_families(name: str) -> None:
    assert _classify_cookie_name(name) == COOKIE_CATEGORY_SENSITIVE


@pytest.mark.parametrize(
    "name",
    (
        "ASPSESSIONID_ABC",
        "ASPSESSIONIDABC-123",
        "remember_web_",
        "remember-web_abc",
    ),
)
def test_cookie_sensitive_family_near_misses_are_unknown(name: str) -> None:
    assert _classify_cookie_name(name) == COOKIE_CATEGORY_UNKNOWN


@pytest.mark.parametrize("name", SENSITIVE_NEAR_MISS_COOKIE_NAMES)
def test_cookie_sensitive_near_misses_remain_unknown_and_redacted(
    name: str,
) -> None:
    assert _classify_cookie_name(name) == COOKIE_CATEGORY_UNKNOWN
    assert_sanitized(
        f"Cookie: {name}={COOKIE_VALUE}\n",
        f"Cookie: {name}={REDACTION_MARKER_COOKIE_VALUE}\n",
        (COOKIE_VALUE,),
        {RULE_ID_COOKIE_VALUE: 1},
    )


@pytest.mark.parametrize("name", APPROVED_TELEMETRY_EXACT_COOKIE_NAMES)
def test_cookie_classifies_approved_telemetry_exact_names(name: str) -> None:
    assert _classify_cookie_name(name.upper()) == COOKIE_CATEGORY_TELEMETRY


def test_cookie_telemetry_exact_names_are_redacted() -> None:
    pairs = tuple(
        (name, f"synthetic-telemetry-value-{index}")
        for index, name in enumerate(APPROVED_TELEMETRY_EXACT_COOKIE_NAMES)
    )
    source = "Cookie: " + "; ".join(f"{name}={value}" for name, value in pairs) + "\n"
    expected = (
        "Cookie: "
        + "; ".join(f"{name}={REDACTION_MARKER_COOKIE_VALUE}" for name, _value in pairs)
        + "\n"
    )

    assert_sanitized(
        source,
        expected,
        tuple(value for _name, value in pairs),
        {RULE_ID_COOKIE_VALUE: len(pairs)},
    )


@pytest.mark.parametrize(
    "name",
    (
        "_ga_ABC123",
        "_gat_request",
        "_hjsession_42",
        "_hjsessionuser_site",
        "amplitude_id",
        "amp_device",
        "mp_project",
    ),
)
def test_cookie_telemetry_prefix_families_are_redacted(name: str) -> None:
    assert _classify_cookie_name(name) == COOKIE_CATEGORY_TELEMETRY
    assert_sanitized(
        f"Cookie: {name}={COOKIE_VALUE}\n",
        f"Cookie: {name}={REDACTION_MARKER_COOKIE_VALUE}\n",
        (COOKIE_VALUE,),
        {RULE_ID_COOKIE_VALUE: 1},
    )


@pytest.mark.parametrize(
    "name",
    ("_ga_", "_gat_", "_hjsession_", "_hjsessionuser_", "amplitude_", "amp_", "mp_"),
)
def test_cookie_telemetry_prefix_near_misses_are_unknown_and_redacted(
    name: str,
) -> None:
    assert _classify_cookie_name(name) == COOKIE_CATEGORY_UNKNOWN
    assert_sanitized(
        f"Cookie: {name}={COOKIE_VALUE}\n",
        f"Cookie: {name}={REDACTION_MARKER_COOKIE_VALUE}\n",
        (COOKIE_VALUE,),
        {RULE_ID_COOKIE_VALUE: 1},
    )


@pytest.mark.parametrize("name", APPROVED_HARMLESS_EXACT_COOKIE_NAMES)
def test_cookie_classifies_approved_harmless_exact_names(name: str) -> None:
    assert _classify_cookie_name(name.upper()) == COOKIE_CATEGORY_HARMLESS


def test_cookie_harmless_exact_names_preserve_values_without_counts() -> None:
    source = (
        "Cookie: theme=synthetic-theme; "
        'color_scheme="synthetic-color"; '
        "display_mode=synthetic-display\n"
    )

    assert_unchanged(source)


def test_cookie_case_insensitive_harmless_duplicates_are_preserved() -> None:
    source = (
        f"Cookie: Theme=synthetic-dark; THEME=synthetic-light; SESSION={COOKIE_VALUE}\n"
    )
    expected = (
        "Cookie: Theme=synthetic-dark; THEME=synthetic-light; "
        f"SESSION={REDACTION_MARKER_COOKIE_VALUE}\n"
    )

    assert_sanitized(
        source,
        expected,
        (COOKIE_VALUE,),
        {RULE_ID_COOKIE_VALUE: 1},
    )


@pytest.mark.parametrize(
    "name", HARMLESS_NEAR_MISS_COOKIE_NAMES + DEFERRED_HARMLESS_CANDIDATE_NAMES
)
def test_cookie_unapproved_harmless_candidates_are_unknown_and_redacted(
    name: str,
) -> None:
    assert _classify_cookie_name(name) == COOKIE_CATEGORY_UNKNOWN
    assert_sanitized(
        f"Cookie: {name}={COOKIE_VALUE}\n",
        f"Cookie: {name}={REDACTION_MARKER_COOKIE_VALUE}\n",
        (COOKIE_VALUE,),
        {RULE_ID_COOKIE_VALUE: 1},
    )


def test_cookie_classification_treats_punctuation_as_distinct() -> None:
    source = (
        "Cookie: color_scheme=synthetic-color; "
        f"color-scheme={COOKIE_VALUE}; color.scheme={SECOND_COOKIE_VALUE}\n"
    )
    expected = (
        "Cookie: color_scheme=synthetic-color; "
        f"color-scheme={REDACTION_MARKER_COOKIE_VALUE}; "
        f"color.scheme={REDACTION_MARKER_COOKIE_VALUE}\n"
    )

    assert _classify_cookie_name("color_scheme") == COOKIE_CATEGORY_HARMLESS
    assert _classify_cookie_name("color-scheme") == COOKIE_CATEGORY_UNKNOWN
    assert _classify_cookie_name("color.scheme") == COOKIE_CATEGORY_UNKNOWN
    assert_sanitized(
        source,
        expected,
        (COOKIE_VALUE, SECOND_COOKIE_VALUE),
        {RULE_ID_COOKIE_VALUE: 2},
    )


def test_cookie_classification_uses_fixed_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sanitizer_module, "SENSITIVE_COOKIE_NAMES", frozenset(("theme",))
    )
    monkeypatch.setattr(
        sanitizer_module, "TELEMETRY_COOKIE_NAMES", frozenset(("theme",))
    )
    monkeypatch.setattr(
        sanitizer_module, "HARMLESS_COOKIE_NAMES", frozenset(("theme",))
    )

    assert _classify_cookie_name("theme") == COOKIE_CATEGORY_SENSITIVE

    monkeypatch.setattr(sanitizer_module, "SENSITIVE_COOKIE_NAMES", frozenset())

    assert _classify_cookie_name("theme") == COOKIE_CATEGORY_TELEMETRY


def test_cookie_classification_uses_name_not_value() -> None:
    shared_value = "synthetic-shared-cookie-value"
    source = (
        f"Cookie: theme={shared_value}; custom={shared_value}; "
        "display_mode=dark; other=dark\n"
    )
    expected = (
        f"Cookie: theme={shared_value}; custom={REDACTION_MARKER_COOKIE_VALUE}; "
        f"display_mode=dark; other={REDACTION_MARKER_COOKIE_VALUE}\n"
    )

    assert_sanitized(
        source,
        expected,
        (),
        {RULE_ID_COOKIE_VALUE: 2},
    )


def test_cookie_category_specific_marker_like_values_are_redacted() -> None:
    source = (
        f"Cookie: session={UNAPPROVED_COOKIE_MARKER_LIKE_VALUES[0]}; "
        f"custom={UNAPPROVED_COOKIE_MARKER_LIKE_VALUES[1]}; "
        f"_ga={UNAPPROVED_COOKIE_MARKER_LIKE_VALUES[2]}; "
        f"other={UNAPPROVED_COOKIE_MARKER_LIKE_VALUES[3]}\n"
    )
    expected = (
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}; "
        f"custom={REDACTION_MARKER_COOKIE_VALUE}; "
        f"_ga={REDACTION_MARKER_COOKIE_VALUE}; "
        f"other={REDACTION_MARKER_COOKIE_VALUE}\n"
    )

    assert_sanitized(
        source,
        expected,
        UNAPPROVED_COOKIE_MARKER_LIKE_VALUES,
        {RULE_ID_COOKIE_VALUE: 4},
    )


def test_cookie_embedded_approved_markers_under_harmless_names_are_redacted() -> None:
    source = (
        f"Cookie: theme={COOKIE_EMBEDDED_MARKER_VALUE}\n"
        f"Cookie: display_mode={COOKIE_EMBEDDED_HEADER_MARKER_VALUE}\n"
    )
    expected = (
        f"Cookie: theme={REDACTION_MARKER_COOKIE_VALUE}\n"
        f"Cookie: display_mode={REDACTION_MARKER_COOKIE_VALUE}\n"
    )

    first, first_report = sanitize_text(source)
    second, second_report = sanitize_text(first)

    assert first == expected
    assert first_report.counts_by_rule == {RULE_ID_COOKIE_VALUE: 2}
    assert second == first
    assert second_report.counts_by_rule == {}


def test_cookie_exact_approved_markers_under_harmless_names_are_idempotent() -> None:
    cases = (
        f"Cookie: theme={REDACTION_MARKER_COOKIE_VALUE}\n",
        f"Cookie: theme={REDACTION_MARKER_COOKIE_HEADER}\n",
        f"Cookie: color_scheme={REDACTION_MARKER_COOKIE_VALUE}\n",
        f"Cookie: display_mode={REDACTION_MARKER_COOKIE_HEADER}\n",
    )
    for source in cases:
        assert_unchanged(source)


@pytest.mark.parametrize(
    ("source", "raw_value"),
    (
        (
            "Cookie: theme=<REDACTED:cookie.harmless>\n",
            "<REDACTED:cookie.harmless>",
        ),
        (
            "Cookie: color_scheme=<REDACTED:cookie.unknown>\n",
            "<REDACTED:cookie.unknown>",
        ),
        (
            "Cookie: display_mode=<REDACTED:cookie.sensitive>\n",
            "<REDACTED:cookie.sensitive>",
        ),
        (
            "Cookie: theme=prefix<REDACTED:cookie.telemetry>suffix\n",
            "prefix<REDACTED:cookie.telemetry>suffix",
        ),
    ),
)
def test_cookie_unapproved_marker_like_values_under_harmless_names_are_redacted(
    source: str, raw_value: str
) -> None:
    name = source.split(": ", 1)[1].split("=", 1)[0]

    assert_sanitized(
        source,
        f"Cookie: {name}={REDACTION_MARKER_COOKIE_VALUE}\n",
        (raw_value,),
        {RULE_ID_COOKIE_VALUE: 1},
    )


def test_cookie_quoted_marker_payloads_under_harmless_names() -> None:
    source = (
        f'Cookie: theme="{REDACTION_MARKER_COOKIE_VALUE}"; '
        f'theme="{COOKIE_EMBEDDED_MARKER_VALUE}"; '
        'color_scheme="<REDACTED:cookie.harmless>"\n'
    )
    expected = (
        f'Cookie: theme="{REDACTION_MARKER_COOKIE_VALUE}"; '
        f'theme="{REDACTION_MARKER_COOKIE_VALUE}"; '
        f'color_scheme="{REDACTION_MARKER_COOKIE_VALUE}"\n'
    )

    assert_sanitized(
        source,
        expected,
        (COOKIE_EMBEDDED_MARKER_VALUE, "<REDACTED:cookie.harmless>"),
        {RULE_ID_COOKIE_VALUE: 2},
    )


def test_cookie_mixed_harmless_marker_and_redaction_paths() -> None:
    embedded_value = f"prefix{REDACTION_MARKER_COOKIE_VALUE}suffix"
    source = (
        "Cookie: theme=dark; "
        f"color_scheme={REDACTION_MARKER_COOKIE_HEADER}; "
        f"display_mode={embedded_value}; "
        "theme=<REDACTED:cookie.harmless>; "
        f"session={COOKIE_VALUE}; _ga={SECOND_COOKIE_VALUE}; "
        f"custom={THIRD_COOKIE_VALUE}\n"
    )
    expected = (
        "Cookie: theme=dark; "
        f"color_scheme={REDACTION_MARKER_COOKIE_HEADER}; "
        f"display_mode={REDACTION_MARKER_COOKIE_VALUE}; "
        f"theme={REDACTION_MARKER_COOKIE_VALUE}; "
        f"session={REDACTION_MARKER_COOKIE_VALUE}; "
        f"_ga={REDACTION_MARKER_COOKIE_VALUE}; "
        f"custom={REDACTION_MARKER_COOKIE_VALUE}\n"
    )
    findings = find_cookie_values(source)

    assert [finding.rule_id for finding in findings] == [RULE_ID_COOKIE_VALUE] * 5
    previous_end = 0
    for finding in findings:
        assert previous_end <= finding.start
        previous_end = finding.end
    assert_sanitized(
        source,
        expected,
        (
            embedded_value,
            "<REDACTED:cookie.harmless>",
            COOKIE_VALUE,
            SECOND_COOKIE_VALUE,
            THIRD_COOKIE_VALUE,
        ),
        {RULE_ID_COOKIE_VALUE: 5},
    )


def test_cookie_names_do_not_become_report_ids() -> None:
    sanitized, report = sanitize_text(
        f"Cookie: username={COOKIE_VALUE}; _ga={SECOND_COOKIE_VALUE}; "
        f"theme={THIRD_COOKIE_VALUE}; custom=synthetic-custom-cookie\n"
    )

    if COOKIE_VALUE in sanitized or SECOND_COOKIE_VALUE in sanitized:
        pytest.fail("sanitized text leaked synthetic cookie value")
    assert report.counts_by_rule == {RULE_ID_COOKIE_VALUE: 3}
    for name in ("username", "_ga", "theme", "custom"):
        if any(name in rule_id for rule_id in report.counts_by_rule):
            pytest.fail("report included a cookie name")


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
        f"theme={THIRD_COOKIE_VALUE}\n"
    )

    assert_sanitized(
        source,
        expected,
        (COOKIE_VALUE, SECOND_COOKIE_VALUE),
        {RULE_ID_COOKIE_VALUE: 2},
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
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}; theme=\t \n",
        (),
        {RULE_ID_COOKIE_VALUE: 1},
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
        f"Cookie: _ga={REDACTION_MARKER_COOKIE_VALUE}\n",
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
        f"custom={COOKIE_VALUE}; other={REDACTION_MARKER_COOKIE_HEADER}\n"
    )
    expected = (
        f"Cookie: session={REDACTION_MARKER_COOKIE_VALUE}; "
        f"custom={REDACTION_MARKER_COOKIE_VALUE}; "
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
        f"Cookie: theme={SECOND_COOKIE_VALUE}\n"
    )

    assert_sanitized(
        source,
        expected,
        (COOKIE_VALUE, "synthetic-malformed"),
        {RULE_ID_COOKIE_VALUE: 1, RULE_ID_COOKIE_HEADER: 1},
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

    if COOKIE_VALUE in first or COOKIE_VALUE in second:
        pytest.fail("sanitized text leaked synthetic cookie value")
    assert first == second
    assert first_report.counts_by_rule == {RULE_ID_COOKIE_VALUE: 1}
    assert second_report.counts_by_rule == {}


def test_cookie_findings_do_not_overlap_authorization_findings() -> None:
    source = (
        "Authorization: Bearer synthetic-auth-token\n"
        f"Cookie: session={COOKIE_VALUE}; custom={SECOND_COOKIE_VALUE}\n"
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
