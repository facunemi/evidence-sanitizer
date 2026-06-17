# Architecture

## Smallest Proposed Architecture

The architecture should remain file-to-file and rule-driven. The first implementation should avoid speculative layers and introduce modules only when there is implemented behavior to place in them.

Milestone 0 expected package shape, when implementation begins:

```text
src/evidence_sanitizer/
|-- __init__.py
|-- __main__.py
`-- cli.py
```

Milestone 0 must not contain sanitizer implementation. It should establish packaging, CLI entry-point shape, and verification tooling only when implementation work begins.

Milestone 1 may introduce additional modules only as responsibilities become real. Likely responsibilities are:

- CLI command handling and exit-code mapping.
- Input validation and reading.
- Output path validation and exclusive output creation.
- Deterministic sanitization for the bearer authorization rule.
- Safe reporting of counts by rule identifier.

Milestone 2 generalizes the existing Authorization-header rule but should continue to use the same small module boundary. The added responsibility is still one coherent Authorization-header sanitizer, so it does not justify a `rules/` package, plugin registry, factories, dependency injection, inheritance hierarchy, generalized precedence engine, or generalized configuration.

Milestone 3 adds one concrete Cookie-header responsibility. Keep production behavior in `src/evidence_sanitizer/sanitizer.py` with small Cookie-specific constants and private helpers. A separate `cookie.py` module is not justified unless the approved implementation responsibilities objectively exceed a cohesive helper set. Do not introduce a `rules/` package, plugin registry, parser framework, dependency injection, inheritance hierarchy, configurable rule ordering, generalized precedence engine, or generalized configuration.

Milestone 4 extends the same Cookie-header responsibility with deterministic name-only classification and very limited value preservation. Keep production behavior in `src/evidence_sanitizer/sanitizer.py` with small private classification constants and helpers. The added responsibility does not justify a `cookie.py` module, `rules/` package, configuration file, runtime-editable list, registry, plugin, dependency injection, inheritance hierarchy, generalized policy engine, regex framework, new dependency, or new public API.

Milestone 5 adds one concrete selected-sensitive-header responsibility. Keep production behavior in `src/evidence_sanitizer/sanitizer.py` with small private constants for the fixed rule ID, marker, approved header-name set, and one private line-oriented finder. The added responsibility does not justify a `headers.py` module, `rules/` package, registry, plugin, configuration file, user-editable policy, dynamic downloads, dependency injection, inheritance hierarchy, generalized parser framework, new dependency, or new public API.

Milestone 6 adds one concrete selected-sensitive-query-parameter responsibility. Keep production behavior in `src/evidence_sanitizer/sanitizer.py` with small private constants for the fixed rule ID, marker, approved parameter-name set, and one private raw query finder. The added responsibility does not justify a `query.py` module, URL parsing dependency, `rules/` package, registry, plugin, configuration file, user-editable policy, recursive parser, dependency injection, inheritance hierarchy, generalized parser framework, new dependency, or new public API.

Do not create modules such as `paths.py`, `reporting.py`, `textio.py`, `engine.py`, or `rules/` merely because they might be useful later. Their creation should be justified by concrete implemented responsibilities.

## Data Flow

Milestone 1 through milestone 6 data flow:

1. Typer parses `sanitize INPUT --output OUTPUT [--dry-run]`.
2. The command validates the input path, output path, and output parent directory.
3. The command rejects a destination that already exists.
4. The command rejects a destination that resolves to the input file.
5. The command reads the complete input file in memory, up to 10 MiB.
6. The command rejects NUL bytes.
7. The command decodes strict UTF-8 or UTF-8 with BOM.
8. The sanitizer applies the approved Authorization-header rule set, the approved Cookie-header rule set in milestone 3 and later, the approved selected-sensitive-header rule set in milestone 5, and the approved selected-sensitive-query-parameter rule set in milestone 6.
9. The sanitizer returns sanitized text plus a safe report.
10. Dry-run mode prints the safe report and writes nothing.
11. Normal mode creates the output path exclusively and writes the sanitized bytes.
12. On controlled write failure, the tool attempts to remove the incomplete output without hiding the original error.

## Rule Contract

The first rule contract should be minimal and deterministic. A rule receives decoded text and returns findings that contain offsets, replacement text, and a rule identifier. Findings must not contain the original matched value.

Conceptual shape:

```python
@dataclass(frozen=True)
class Finding:
    rule_id: str
    start: int
    end: int
    replacement: str
```

```python
@dataclass(frozen=True)
class SanitizationReport:
    counts_by_rule: dict[str, int]
    changed: bool
```

```python
class Rule(Protocol):
    rule_id: str

    def find(self, text: str) -> tuple[Finding, ...]:
        ...
```

These are public design concepts, not a requirement to create separate modules or protocols in milestone 0. Do not implement the `Rule` protocol in milestone 0. In milestone 1, implement a protocol only if it is the smallest way to keep the bearer rule independently testable.

## Finding And Report Data Structures

Findings should store:

- `rule_id`: stable identifier, such as `authorization.bearer`, `authorization.basic`, `authorization.other`, `cookie.value`, `cookie.header`, `header.secret`, or `query.secret`.
- `start`: start offset in decoded text.
- `end`: end offset in decoded text.
- `replacement`: deterministic replacement text.

Findings must not store:

- Matched secret values.
- Source line text.
- Context around the match.

Reports should store:

- Counts by rule identifier.
- Whether sanitized output differs from input.

Reports must not store:

- Detected values.
- Source excerpts.
- Replacement previews with surrounding evidence.

## Module Boundaries

Start with the fewest modules possible.

Milestone 0:

- `cli.py`: Typer application skeleton only.
- `__main__.py`: command entry point only.
- `__init__.py`: package metadata only if needed.

Milestone 1 boundaries should be introduced only when the code becomes difficult to keep safe and testable in `cli.py`. Acceptable extraction triggers include:

- Path validation needs independent tests.
- The bearer rule needs independent tests.
- Input decoding needs independent tests.
- Output writing needs independent tests.

Avoid broad names that imply future frameworks. Prefer small concrete names tied to implemented behavior.

Milestone 2 should keep Authorization-header parsing and replacement in `sanitizer.py`. A new `authorization.py` module or `rules/` package is not justified unless implementation responsibilities grow beyond one coherent Authorization-header finder.

Milestone 3 should also stay in `sanitizer.py`. The Cookie rule should add only fixed constants, a line-oriented Cookie finder, and small private parsing helpers. It should reuse `Finding`, `SanitizationReport`, `apply_findings`, existing file handling, and right-to-left replacement. No new public data structures are required.

Milestone 4 should continue to stay in `sanitizer.py`. Cookie-name classification should add only small private exact-name sets, private family helpers, and a private classifier. The Cookie parser may return transient Cookie names alongside value spans so the finder can decide whether to preserve or redact each value, but names must not be stored in `Finding`, `SanitizationReport`, CLI output, or reports.

Milestone 5 should continue to stay in `sanitizer.py`. Sensitive-header sanitization should add only small private constants and one private finder that reuses `_iter_physical_lines` to inspect decoded physical lines. It should reuse `Finding`, `SanitizationReport`, `apply_findings`, `sanitize_text`, existing file handling, right-to-left replacement, and overlap protection. No new public data structures or public APIs are required.

Milestone 6 should continue to stay in `sanitizer.py`. Query-parameter sanitization should add only small private constants and one private raw query finder. It should reuse `Finding`, `SanitizationReport`, `_iter_physical_lines` where useful for line-boundary consistency, `apply_findings`, `sanitize_text`, existing file handling, right-to-left replacement, and overlap protection. No new public data structures or public APIs are required.

## Encoding And Newline Behavior

- Read bytes first.
- Reject files larger than 10 MiB.
- Reject bytes containing `NUL`.
- Decode using strict UTF-8.
- If a UTF-8 BOM is present, preserve that fact and decode accordingly.
- Re-emit a UTF-8 BOM only when the input had one.
- Do not normalize newlines.
- Do not use text mode newline conversion for reading or writing.
- Preserve LF, CRLF, mixed newline sequences, and final-newline state by operating on decoded text without newline normalization.

## Authorization Header Rules

Milestone 1 supports only HTTP-style Bearer authorization header lines:

```text
Authorization: Bearer secret-token
```

The rule should:

- Match the header name case-insensitively.
- Match the `Bearer` scheme case-insensitively.
- Preserve the header name, colon spacing, scheme spelling, and newline sequence.
- Replace only the credential portion with `<REDACTED:authorization.bearer>`.
- Avoid matching arbitrary prose that contains the word `Bearer`.
- Be idempotent when run repeatedly.

Milestone 2 generalizes this into one coherent Authorization-header finder. The finder should produce at most one finding per Authorization line and should avoid overlapping findings by construction. If overlapping findings occur, treat that as an internal sanitization error rather than introducing a generalized overlap-resolution system.

### Milestone 2 Auth-Scheme Grammar

Milestone 2 should match only syntactically valid auth schemes using the ASCII HTTP token character set:

```text
!#$%&'*+-.^_`|~0-9A-Za-z
```

Unicode scheme names and malformed scheme names are unsupported and remain unchanged. The Authorization header name is still matched case-insensitively, and only lines that begin exactly with the header name are in scope. Folded or indented header lines remain unsupported.

### Milestone 2 Finder Structure

Use one line-oriented finder in `sanitizer.py` that parses the header name, spacing around `:`, scheme, spacing after the scheme, credential section, trailing spaces or tabs, and line ending. It should then branch by scheme:

- Bearer branch for `Bearer`, case-insensitive.
- Basic branch for `Basic`, case-insensitive.
- Generic fallback branch for all other syntactically valid schemes.

Bearer and Basic branches must run before the generic branch and must not fall through to the generic branch when their specialized validation fails. Generic fallback applies only to schemes other than Bearer and Basic.

### Milestone 2 Bearer Branch

The Bearer branch preserves all milestone 1 behavior:

- Preserve header name casing.
- Preserve spacing around `:`.
- Preserve scheme casing.
- Preserve spacing between scheme and credentials.
- Preserve trailing spaces and tabs.
- Require exactly one contiguous non-whitespace credential.
- Replace only the credential with `<REDACTED:authorization.bearer>`.
- Use rule ID `authorization.bearer`.
- Leave empty, whitespace-only, or internally spaced Bearer credentials unchanged.

### Milestone 2 Basic Branch

The Basic branch should:

- Match `Basic` case-insensitively.
- Preserve header name casing, scheme casing, and surrounding spacing.
- Preserve trailing spaces and tabs.
- Require exactly one contiguous non-whitespace credential.
- Not Base64-decode or validate the credential.
- Replace only the credential with `<REDACTED:authorization.basic>`.
- Use rule ID `authorization.basic`.
- Leave empty, whitespace-only, or internally spaced Basic credentials unchanged.

### Milestone 2 Generic Fallback Branch

The generic branch should:

- Apply only to syntactically valid schemes other than Bearer and Basic.
- Preserve header name, spacing around `:`, scheme casing, and spacing between scheme and credentials.
- Replace the complete non-empty credential section after the scheme with `<REDACTED:authorization.credentials>`.
- Use rule ID `authorization.other`.
- Allow internal spaces, commas, quotes, equals signs, colons, slashes, and other punctuation.
- Not parse individual Digest, AWS, AMX, OAuth, Signature, or custom parameters.
- Leave empty or scheme-only headers unchanged.
- Never include the custom scheme name in the report rule ID.

### Milestone 2 Idempotence And Marker Policy

Approved markers are:

```text
<REDACTED:authorization.bearer>
<REDACTED:authorization.basic>
<REDACTED:authorization.credentials>
```

If the complete credential section is exactly equal to any approved marker, the value is already sanitized and the finder should produce no finding. This applies even when the marker appears under a different scheme. The sanitizer must not correct or normalize a marker used under another scheme. A marker embedded inside a larger raw credential value is not already sanitized.

### Milestone 2 Reporting Aggregation

Reports should aggregate counts from findings by fixed rule ID only:

- `authorization.bearer`
- `authorization.basic`
- `authorization.other`

Counts represent one redacted Authorization credential section per matching header line. Reports must not include credential values, source excerpts, replacement previews, or custom scheme names.

## Cookie Header Rules

Milestone 3 supports only exact line-start HTTP request `Cookie` header lines. It preserves safely parsed cookie names and as much delimiter formatting as safely possible while replacing every cookie value. If complete deterministic parsing fails, it replaces the complete trimmed header value with a whole-header fallback marker instead of partially sanitizing the line.

### Milestone 3 Header Detection Grammar

Use one line-oriented finder in `sanitizer.py` for Cookie headers. The header detector should:

- Match `Cookie` case-insensitively.
- Match only at decoded text offset `0` or immediately after `\n`.
- Allow spaces and tabs between `Cookie` and `:`.
- Allow spaces and tabs after `:`.
- Preserve header-name casing, spacing around `:`, trailing spaces and tabs, LF, CRLF, mixed newline sequences, UTF-8 BOM state, and final-newline state.
- Not match `Set-Cookie`, `X-Cookie`, indented Cookie lines, folded continuation lines, or prose containing the word `Cookie`.

Exact header-like `Cookie:` lines inside message bodies may be sanitized because full HTTP body-boundary parsing remains deferred.

### Milestone 3 Complete-Parse Lifecycle

For each exact non-folded Cookie line:

1. Identify the header value span after the header name, colon, and allowed horizontal whitespace.
2. Preserve trailing spaces and tabs outside the replacement span.
3. If the trimmed header value is empty, produce no finding.
4. If the complete trimmed header value is exactly an approved Cookie marker, produce no finding.
5. Parse the complete header value before emitting any per-value findings.
6. If every segment parses safely, emit one `cookie.value` finding for each cookie value that is not already an exact approved Cookie marker.
7. If any segment or delimiter is malformed or uncertain, emit one `cookie.header` finding for the complete trimmed header value and emit no `cookie.value` findings for that line.

This complete-parse-before-findings lifecycle is required to avoid partial sanitization. A malformed segment mixed with valid segments must not leave raw cookie values exposed next to sanitized values.

### Milestone 3 Cookie Name Grammar

Cookie names must be non-empty and use only the ASCII HTTP token character set:

```text
!#$%&'*+-.^_`|~0-9A-Za-z
```

The `$` character is allowed because it is part of the HTTP token character set. Non-ASCII names, empty names, and names containing characters outside this grammar trigger whole-header fallback. Cookie names are preserved only when the complete header value parses safely.

### Milestone 3 Cookie Value Scanner

A safely parsed Cookie header consists of one or more non-empty `name=value` pairs separated by semicolons. The first `=` separates name from value. The scanner should allow and preserve spaces or tabs around `=`, spaces or tabs around `;`, original pair order, duplicate names, and trailing horizontal whitespace at the end of the header.

Unquoted values may be empty and may contain additional `=`, commas, colons, slashes, printable punctuation other than semicolons, and non-ASCII text. Unquoted values end at the next semicolon or at the end of the header value before trailing horizontal whitespace.

Quoted values are supported. The scanner should preserve the surrounding quote characters and replace only the quoted payload. Semicolons inside quoted values are part of the value, not delimiters. Valid escaped characters inside quoted values are supported. Missing closing quotes, dangling escapes, and non-horizontal junk after the closing quote before `;` or line end trigger whole-header fallback.

NUL remains rejected by the existing input-validation path. CR and LF remain line delimiters, not Cookie-value characters. Other unsupported control characters inside a Cookie value trigger whole-header fallback rather than a new global error.

### Milestone 3 Fallback Semantics

Whole-header fallback uses rule ID `cookie.header` and marker `<REDACTED:cookie.header>`. It replaces the complete trimmed Cookie header value, preserving the header name, spacing around `:`, leading horizontal whitespace after `:`, trailing spaces and tabs, and line ending.

Fallback triggers include:

- Missing `=`.
- Empty name.
- Leading semicolon.
- Trailing semicolon.
- Consecutive semicolons.
- Malformed segment mixed with valid segments.
- Malformed quoted syntax.
- Missing closing quote.
- Dangling escape.
- Invalid non-ASCII cookie name.
- Unsupported control character.
- Junk after a closing quote.
- Any other condition that prevents complete safe parsing.

A fallback header produces no `cookie.value` findings. Empty `Cookie:` headers and `Cookie:` headers followed only by spaces or tabs remain unchanged and produce no finding.

Folded Cookie headers are unsupported in milestone 3. If an exact `Cookie:` line is immediately followed by a physical line beginning with a space or tab, leave the entire folded form unchanged. Do not sanitize only the first physical line. Full folded-header parsing is deferred.

### Milestone 3 Idempotence And Marker Policy

Approved Cookie markers are:

```text
<REDACTED:cookie.value>
<REDACTED:cookie.header>
```

If an exact approved Cookie marker is used as a complete individual cookie value, the value is already sanitized and the finder should produce no finding. If an exact approved Cookie marker is used as the complete trimmed Cookie header value, the header is already sanitized and the finder should produce no finding. This applies even when the marker is used in an unexpected Cookie context. The sanitizer must not correct or normalize wrong-context markers. A marker embedded inside a larger raw value is not already sanitized and must be redacted. Trailing spaces and tabs after exact markers are preserved. Repeated sanitization must produce byte-identical output.

### Milestone 3 Reporting Aggregation

Reports should aggregate Cookie counts from findings by fixed rule ID only:

- `cookie.value`
- `cookie.header`

`cookie.value` counts each individual cookie value actually replaced. `cookie.header` counts each Cookie header line changed through whole-header fallback. A fallback header must not also increment `cookie.value`. Already-redacted values and empty headers produce no counts. Cookie names must never become rule IDs, and reports must not include cookie values, source excerpts, replacement previews, or cookie names as dynamic report identifiers.

### Milestone 3 Combination With Authorization Findings

Authorization and Cookie findings are independent and non-overlapping by construction because they match different exact header names. The sanitizer should collect Authorization findings and Cookie findings, then apply the combined finding set with the existing right-to-left replacement function. If an overlap is ever produced, treat it as the existing internal sanitization error rather than adding a generalized overlap-resolution system.

Existing Authorization ordering and behavior must remain unchanged. Cookie parsing must not alter Bearer, Basic, or generic Authorization matching, marker policy, counts, or idempotence.

### Milestone 4 Cookie Classification Lifecycle

Milestone 4 adds name-only classification after Milestone 3 has completely and safely parsed a non-folded exact line-start `Cookie` header. Classification must not run on malformed headers, folded Cookie forms, `Set-Cookie`, `X-Cookie`, indented Cookie lines, empty Cookie headers, or whitespace-only Cookie headers.

For each exact non-folded Cookie line in milestone 4:

1. Identify the header value span after the header name, colon, and allowed horizontal whitespace.
2. Preserve trailing spaces and tabs outside the replacement span.
3. If the trimmed header value is empty, produce no finding.
4. If the complete trimmed header value is exactly an approved Cookie marker, produce no finding.
5. Parse the complete header value before emitting findings or preserving any value.
6. If any segment or delimiter is malformed or uncertain, emit one `cookie.header` finding for the complete trimmed header value and emit no per-cookie findings.
7. If every segment parses safely, classify each parsed Cookie name using only the name.
8. Emit one `cookie.value` finding for each redacted value that is not already an exact approved Cookie marker.
9. Emit no finding for approved harmless exact names whose values are preserved.

The parser result may carry a transient tuple such as `(name, value_start, value_end)` for each parsed pair. The name is used only for classification and must not be retained in `Finding`, reports, exceptions, logs, or CLI output.

### Milestone 4 Classification Matching

Classification uses the conceptual categories `sensitive`, `telemetry`, `harmless`, and `unknown`. The category is internal policy only and is not a rule ID, marker, report field, or public API.

Classification should use small private constants and helpers:

```python
COOKIE_CATEGORY_SENSITIVE = "sensitive"
COOKIE_CATEGORY_TELEMETRY = "telemetry"
COOKIE_CATEGORY_HARMLESS = "harmless"
COOKIE_CATEGORY_UNKNOWN = "unknown"

SENSITIVE_COOKIE_NAMES = frozenset(...)
TELEMETRY_COOKIE_NAMES = frozenset(...)
HARMLESS_COOKIE_NAMES = frozenset(...)

def _classify_cookie_name(name: str) -> str:
    ...
```

The classifier must:

- Match names case-insensitively.
- Normalize only by ASCII lowercase for internal matching.
- Preserve original Cookie-name casing in output.
- Operate only on names already accepted by the Milestone 3 ASCII HTTP-token grammar.
- Treat `_`, `-`, and `.` as distinct characters.
- Perform no Unicode normalization.
- Use no suffix matching.
- Use no broad substring matching.
- Use prefix or family matching only for explicitly approved families.
- Use fixed precedence `sensitive > telemetry > harmless > unknown`.
- Avoid a generalized precedence engine.

Approved sensitive matching consists of exact case-insensitive names and two families. Exact names are the product-specified lower-case set, including `session`, `sessionid`, `session_id`, `sid`, `auth`, `auth_token`, `access_token`, `refresh_token`, `token`, `jwt`, `sso`, `sso_state`, `username`, `user`, `userid`, `user_id`, `email`, `identity`, `account`, `account_id`, `customer`, `customer_id`, `tenant`, `tenant_id`, `portalauth`, `asp.net_sessionid`, `jsessionid`, `phpsessid`, `connect.sid`, and `laravel_session`. The `aspsessionid` family matches `aspsessionid` plus an optional ASCII alphanumeric suffix only. The `remember_web_` family matches `remember_web_` plus a non-empty suffix using the existing ASCII HTTP-token grammar.

Approved telemetry matching consists of exact case-insensitive names and prefix families. Exact names are `_ga`, `_gid`, `_gat`, `_fbp`, `_fbc`, `_hjid`, `_clck`, `_clsk`, `ajs_anonymous_id`, `ajs_user_id`, `_mkto_trk`, `hubspotutk`, `__hstc`, `__hssc`, and `__hssrc`. Prefix families are `_ga_`, `_gat_`, `_hjsession_`, `_hjsessionuser_`, `amplitude_`, `amp_`, and `mp_`, each with a non-empty suffix. Telemetry values are redacted in milestone 4.

Approved harmless matching consists only of exact case-insensitive names `theme`, `color_scheme`, and `display_mode`. No harmless prefix, suffix, wildcard, or substring matching is approved.

### Milestone 4 Preservation And Findings

Milestone 4 keeps the existing Cookie markers and rule IDs:

```text
cookie.value
<REDACTED:cookie.value>

cookie.header
<REDACTED:cookie.header>
```

All redacted individual Cookie values use `cookie.value` and `<REDACTED:cookie.value>`, whether the internal category is `sensitive`, `telemetry`, or `unknown`. Preserved harmless values remain byte-for-byte unchanged and produce no finding or count. Do not add category-specific rule IDs or markers such as `cookie.sensitive`, `cookie.unknown`, `cookie.telemetry`, `cookie.harmless`, `<REDACTED:cookie.sensitive>`, or `<REDACTED:cookie.unknown>`.

Existing approved Cookie markers remain idempotent. Category-specific marker-like values are ordinary raw values and should be redacted as `cookie.value` unless the existing parser requires whole-header fallback. Previously redacted telemetry values cannot be recovered and must remain redacted.

### Milestone 4 Fallback And Combination Behavior

Whole-header fallback remains unchanged: a malformed non-empty exact non-folded Cookie header produces one `cookie.header` finding with `<REDACTED:cookie.header>` and no per-cookie classification or per-cookie findings. Folded Cookie forms remain completely unchanged. `Set-Cookie` remains out of scope. Exact line-start Cookie matching, newline preservation, BOM preservation, final-newline behavior, and formatting preservation remain unchanged.

Authorization and Cookie findings remain independent and non-overlapping by construction. Milestone 4 classification must not alter Bearer, Basic, or generic Authorization matching, marker policy, counts, idempotence, or file flow.

## Sensitive API/Auth Header Rules

Milestone 5 supports only exact line-start selected sensitive API/authentication-related HTTP-like headers. It redacts the complete non-empty trimmed header value with one generic marker and reports one generic fixed rule ID.

Use small private constants in `sanitizer.py`:

```python
RULE_ID_HEADER_SECRET = "header.secret"
REDACTION_MARKER_HEADER_SECRET = "<REDACTED:header.secret>"
APPROVED_HEADER_REDACTION_MARKERS = frozenset((REDACTION_MARKER_HEADER_SECRET,))
SENSITIVE_HEADER_NAMES = frozenset(...)
```

Use one private sensitive-header finder, conceptually:

```python
def _find_sensitive_header_values(text: str) -> tuple[Finding, ...]:
    ...
```

The finder should reuse `_iter_physical_lines` so newline detection, final-line behavior, and folded-line checks stay consistent with the Cookie finder. For each physical line, it should:

1. Check whether the line starts at column 0 with one approved header name, matched case-insensitively.
2. Require the approved name followed only by optional spaces or tabs and then `:`.
3. Allow spaces and tabs after `:` and treat them as preserved leading formatting outside the replacement span.
4. Determine the value span up to the physical line ending.
5. Trim only trailing spaces and tabs from the replacement span, preserving that trailing horizontal whitespace outside the replacement.
6. Skip empty or whitespace-only values.
7. Skip exact complete trimmed `<REDACTED:header.secret>` values.
8. Emit one `Finding` with rule ID `header.secret` and replacement `<REDACTED:header.secret>` for every other non-empty value.

The finder must not parse, decode, classify, split, or inspect the header value beyond empty-marker checks and replacement-span calculation. Quoted, comma-separated, and structured values are redacted as one complete trimmed value. A value containing embedded `<REDACTED:header.secret>`, unapproved marker-like values, or wrong-family Authorization/Cookie markers is treated as raw and redacted.

The approved header-name set is fixed and exact. No substring matching is allowed, and header names must not become dynamic rule IDs or report output. Near misses such as `monkey`, `keyboard`, `x-tokenizer-mode`, `x-author-theme`, `x-api-key-name`, `x-access-token-expires`, and `x-csrf-token-enabled` remain unchanged.

Folded sensitive headers are unsupported. If an exact sensitive header line is immediately followed by a physical line beginning with a space or tab, the finder should leave the complete folded form unchanged and emit no finding. It must not sanitize only the first physical line. Full folded-header parsing remains deferred.

The sensitive-header finder must not match `authorization`, `cookie`, `set-cookie`, or `proxy-authorization`. Existing Authorization and Cookie flows remain unchanged. In `sanitize_text`, collect Authorization findings, Cookie findings, and sensitive-header findings, then apply the combined finding set with the existing right-to-left replacement function. The rules are non-overlapping by construction because they match distinct exact header names. If an overlap is ever produced, keep treating it as an internal sanitization error instead of adding a generalized overlap-resolution system.

Reports should aggregate `header.secret` by fixed rule ID only. Reports must not include raw values, source excerpts, replacement previews, header names as dynamic identifiers, grouped header categories, or per-header identifiers.

## Sensitive Query Parameter Rules

Milestone 6 supports selected sensitive raw URL query parameter values in decoded text evidence. It uses one raw query scanner, not a full URL parser. The finder may match raw URL/query-like substrings in HTTP request lines, absolute URLs, relative paths with query strings, query-only tokens such as `?sig=...`, non-sensitive header values such as `Referer` and `Location`, and raw body or log lines. Full HTTP message parsing remains deferred, so exact URL-like text inside bodies or logs may be sanitized.

Use small private constants in `sanitizer.py`:

```python
RULE_ID_QUERY_SECRET = "query.secret"
REDACTION_MARKER_QUERY_SECRET = "<REDACTED:query.secret>"
APPROVED_QUERY_REDACTION_MARKERS = frozenset((REDACTION_MARKER_QUERY_SECRET,))
SENSITIVE_QUERY_PARAMETER_NAMES = frozenset(...)
```

Use one private raw query finder, conceptually:

```python
def _find_query_parameter_values(
    text: str, existing_findings: Sequence[Finding]
) -> tuple[Finding, ...]:
    ...
```

The approved parameter-name set is fixed and exact. Matching must be case-insensitive against the raw parameter name before `=`. It must not URL-decode, URL-re-encode, normalize Unicode, parse nested URLs, classify by value, infer from value shape, or use substring matching. Percent-encoded names such as `access%5Ftoken` do not match `access_token`. `_`, `-`, and `.` remain distinct.

The finder should scan decoded text for raw query candidates with these boundaries:

1. Treat `?` as the start of a raw query candidate.
2. Treat a repeated `?` inside the same query token as data, not as recursive query parsing.
3. Support multiple separate query tokens on one line.
4. Treat `&` and `;` as parameter separators.
5. Treat `#` as the end of the current query segment.
6. Treat spaces, tabs, CR, LF, quotes, apostrophes, and backticks as query-token terminators.
7. Treat `<` and `>` as URL wrapping delimiters, preserving outer delimiters such as the trailing `>` in `<https://x.test/?sig=abc>`.
8. Preserve every non-value byte and text segment by replacing only value spans.

For each raw query candidate, the lifecycle should be:

1. Split the candidate into raw parameter segments using `&` and `;` while preserving separators.
2. For each segment, find the first `=`.
3. If no `=` exists, skip the bare no-value parameter and produce no finding.
4. Compare the raw name before `=` to the approved case-insensitive parameter-name set.
5. If the name is not approved, produce no finding.
6. Replace the complete raw value span after `=` with `<REDACTED:query.secret>`.
7. Treat explicit empty values such as `?token=` as replaceable value spans and emit one finding.
8. Skip exact complete raw values equal to `<REDACTED:query.secret>`.
9. Redact embedded `<REDACTED:query.secret>` values, unapproved query marker-like values, and wrong-family markers such as `<REDACTED:header.secret>`, `<REDACTED:cookie.value>`, and `<REDACTED:authorization.bearer>`.

Marker handling must be marker-aware so the approved marker's `<` and `>` do not break idempotence or query boundary detection. Repeated sanitization must produce byte-identical output.

The query finder must not introduce grouped or per-parameter rule IDs such as `query.token`, `query.api_key`, `query.signature`, or `query.oauth`. Reports should aggregate counts by fixed rule ID `query.secret` only. Parameter names may remain visible in sanitized evidence for URL structure, but they must not be stored in `Finding`, `SanitizationReport`, CLI output, or reports as dynamic identifiers.

Existing findings are authoritative. In `sanitize_text`, collect Authorization findings, Cookie findings, and selected sensitive-header findings first. Query findings should run after those broader finders or otherwise receive the existing finding spans and skip any candidate value span that overlaps them. `apply_findings` remains the final overlap guard. Do not introduce a generalized overlap-resolution system.

Examples of overlap behavior:

```http
X-API-Key: https://x.test/?sig=abc
```

This should produce only `header.secret` because the sensitive-header finding covers the URL value.

```http
Cookie: theme=https://x.test/?sig=abc
```

This may produce `query.secret` because `theme` is an approved harmless Cookie name whose value is intentionally preserved, so no Cookie finding covers that span.

Milestone 6 must not add URL parsing dependencies, `query.py`, `rules/`, configuration files, user-editable policy, registries, plugins, dependency injection, inheritance, generalized parser frameworks, recursive parsers, new public APIs, or new exit codes.

## Exclusive Output Creation Strategy

Milestone 1 must require the output path not to exist. The implementation should create the output file exclusively, using a mode or flag equivalent to `x` creation so an existing destination is never overwritten.

On controlled write failure:

- Preserve the original error for reporting and exit-code mapping.
- Attempt to remove the incomplete output file.
- Do not obscure the original error if cleanup fails.
- Do not print evidence contents in either error.

The output parent directory must already exist. The tool should not create missing parent directories in milestone 1.

## Why Atomic Replacement Is Deferred

Atomic replacement is useful but not required for milestone 1 because the approved behavior rejects existing output paths and creates a new destination exclusively. Implementing temp-file plus atomic finalization correctly across Windows and Linux adds complexity around temp naming, cleanup, permissions, and same-directory guarantees.

Milestone 1 therefore documents this limitation instead of overbuilding it. An abrupt process termination may leave a partial output file. This is an accepted residual risk for the first implementation.

## Rejected Alternatives

- In-place editing: rejected because source evidence must never be modified.
- Overwrite option: rejected for MVP because output collisions should fail safely.
- Streaming sanitizer: rejected for milestone 1 because complete-file processing is approved and simpler to reason about with a 10 MiB limit.
- General plugin system: rejected because it increases attack surface and complexity.
- Configuration files: rejected until a concrete need exists.
- LLM detection: rejected because MVP detection must be deterministic and explainable.
- Comprehensive binary detection: rejected because milestone 1 only rejects NUL bytes and strict UTF-8 decoding failures.
- Generalized overlap resolution: rejected unless a concrete approved requirement exceeds simple non-overlapping findings, skip-on-overlap behavior, and the existing internal overlap guard.
- Metadata preservation: rejected because sanitized output is a new copy and cross-platform metadata preservation is not required.
- Atomic replacement guarantee: deferred because exclusive new-file creation is sufficient for milestone 1's approved safety target.
- URL parsing dependencies for milestone 6 query sanitization: rejected because standard parsers may decode, normalize, sort, or re-encode evidence, while the approved behavior is raw span replacement.
- Recursive query parsing: deferred because nested URL semantics and false-positive behavior require a separate approval.

## Rules Against Speculative Abstraction

- Do not add a module without implemented responsibility.
- Do not add protocols or base classes until more than one implementation needs the abstraction, except for narrow rule-testability needs.
- Do not add dependency injection containers.
- Do not add plugin discovery.
- Do not add async processing.
- Do not add configuration loading.
- Do not add reporting formats until there is an approved consumer.
- Do not add future directory-processing architecture until single-file semantics are proven.
- Do not add URL parser frameworks or recursive parsers for milestone 6 query sanitization.
