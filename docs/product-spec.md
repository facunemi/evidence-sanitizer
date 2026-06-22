# Product Specification

## Product Definition

`evidence-sanitizer` is a defensive, local-first Python CLI for creating sanitized copies of authorized penetration-testing evidence. It reads one text file, detects supported sensitive values with deterministic rules, and writes a separate sanitized output file without modifying the original evidence.

The product is not a general data-loss-prevention system. It is a small, explainable tool that reduces the risk of accidentally storing or sharing known classes of sensitive values.

## Intended Users

- Penetration testers preparing evidence for notes, reports, tickets, repositories, or peer review.
- Security consultants sharing artifacts with colleagues.
- Internal security engineers preserving useful evidence while reducing exposure of credentials or client identifiers.

## Use Cases

- Sanitize an HTTP request capture before committing it to a project repository.
- Run a dry run to see which supported rule identifiers would trigger, without creating output.
- Produce deterministic sanitized evidence for review.
- Refuse risky output choices rather than silently overwriting evidence or guessing intent.

## MVP Scope

The MVP supports:

- One input file per command.
- One explicit output file path per command.
- Complete-file processing in memory.
- Maximum input size of 10 MiB.
- Strict UTF-8 and UTF-8 with BOM only.
- Preservation of a UTF-8 BOM when present.
- Exact preservation of LF and CRLF sequences.
- Preservation of whether the input ends with a newline.
- Built-in deterministic sanitization rules only.
- Dry-run mode.
- Triggered rule identifiers and redaction counts, never detected values.
- Documented exit codes.
- Windows and Linux support for normal local filesystem usage.

Milestone 1 is smaller than the full MVP rule set. It implements only one rule: HTTP-style `Authorization: Bearer` header redaction.

Milestone 2 generalizes HTTP `Authorization` header sanitization. It preserves the Milestone 1 Bearer behavior, adds explicit Basic authentication sanitization, and adds a conservative fallback for syntactically valid unknown, custom, and structured authorization schemes.

Milestone 3 adds deterministic sanitization for exact line-start HTTP request `Cookie` headers. It preserves safely parsed cookie names and formatting while replacing every cookie value, and uses a whole-header fallback when complete safe parsing is not possible.

Milestone 4 adds deterministic Cookie-name classification for safely parsed request `Cookie` headers. It preserves only a very small exact set of harmless preference-cookie values, while known sensitive cookies, known telemetry cookies, and unknown cookies remain redacted.

Milestone 5 adds deterministic sanitization for selected sensitive API/authentication-related HTTP header values. It redacts whole non-empty values for an approved fixed list of exact line-start header names using one generic rule ID and marker.

Milestone 6 adds deterministic sanitization for selected sensitive raw URL query parameter values in decoded text evidence. It redacts values for an approved fixed list of exact raw parameter names using one generic rule ID and marker, without URL decoding, URL re-encoding, recursive URL parsing, or full HTTP parsing.

## Non-Goals

- In-place modification of evidence.
- Directory processing in current milestones.
- Binary file sanitization.
- Guaranteed detection of every secret.
- Heuristic binary classification beyond NUL-byte rejection and strict UTF-8 decoding failure.
- Preservation of permissions, ownership, timestamps, ACLs, extended attributes, or other metadata.
- Network features, telemetry, update checks, sync, or remote scanning.
- LLM-based detection or replacement.
- User-defined rules, configuration files, or plugins in the first version.
- Cookie or Set-Cookie sanitization in milestone 2.
- `Set-Cookie` sanitization in milestone 3.
- Cookie-name classification, sensitive/telemetry/harmless/unknown categories, telemetry allowlists, and selective cookie-value preservation in milestone 3.
- `Set-Cookie` sanitization, telemetry-cookie value preservation, user-defined classification lists, and runtime-editable policy in milestone 4.
- API-key-specific headers, email redaction, or client-identifier redaction in milestone 2.
- Full HTTP header/body parsing or folded-header parsing in milestone 2 and milestone 3.
- Query parameters, URLs, JSON bodies, XML bodies, form bodies, multipart parsing, response `Set-Cookie`, `Proxy-Authorization`, folded-header parsing, directory processing, runtime-editable allowlists, external data, network behavior, telemetry, LLM behavior, persistence, new dependencies, and new exit codes in milestone 5.
- URL decoding, URL re-encoding, recursive parsing of URL-valued query parameters, JSON parsing, XML parsing, form-body parsing as structured form data, multipart parsing, HTML parsing, JavaScript parsing, full HTTP message parsing, directory processing, configuration files, runtime-editable allowlists, plugins, registries, external data, network behavior, telemetry, LLM behavior, persistence, new dependencies, and new exit codes in milestone 6.
- Database storage.
- Web application features.
- Debug mode.
- Comprehensive defense against adversarial filesystem races, junction attacks, or hard-link attacks in milestone 1.

## User Stories

- As a tester, I can sanitize `request.txt` into `request.sanitized.txt` while leaving `request.txt` unchanged.
- As a tester, I can run dry-run mode and see that `authorization.bearer` matched once without seeing the token.
- As a tester, I can sanitize Basic and custom Authorization credentials without exposing them in output.
- As a tester, I can sanitize request Cookie values while preserving safely parsed cookie names for evidence context.
- As a tester, I can preserve only approved harmless Cookie preference values while redacting sensitive, telemetry, and unknown Cookie values.
- As a tester, I can sanitize selected API/authentication-related HTTP header values without exposing the exact secret type in reports.
- As a tester, I can sanitize selected sensitive query parameter values such as `sig`, `signature`, and `access_token` without exposing the exact secret type in reports.
- As a reviewer, I can understand which rule transformed data and how many replacements occurred.
- As a cautious user, I receive an error if the output path already exists.
- As a cautious user, I receive an error if the output path resolves to the same file as the input.
- As a maintainer, I can test each rule independently with synthetic data only.
- As a security engineer, I can rely on safe user-facing errors that do not include detected values or source excerpts.

## Functional Requirements

These are MVP functional requirements. Milestone 0 is governed by `docs/milestones.md` and must not implement sanitizer behavior.

- The CLI must provide a `sanitize` command.
- The `sanitize` command must accept one input path and one output path.
- The input path may be a symbolic link if it resolves to a regular file.
- The input path must not be a directory.
- The output path must not exist.
- The output parent directory must already exist.
- The output must be created with exclusive creation so an existing destination is never overwritten.
- The tool must reject input larger than 10 MiB.
- The tool must reject input containing NUL bytes.
- The tool must reject input that cannot be decoded as strict UTF-8 or UTF-8 with BOM.
- The tool must preserve a UTF-8 BOM when the input had one.
- The tool must not normalize newlines.
- The tool must not add or remove a final newline except as a direct consequence of replacing matched text.
- The tool must report only rule identifiers and counts.
- The tool must never display detected values.
- Dry-run mode must perform detection and reporting but must not create output.
- Detected findings are successful execution and must return exit code `0`.
- Typer handles CLI usage errors.

## Milestone 2 Authorization Sanitization

Milestone 2 supports HTTP-style `Authorization` header lines that begin exactly at the start of a decoded line. Indented or folded header lines remain unsupported and unchanged. Exact header-like `Authorization` lines inside message bodies may still be sanitized because full HTTP body-boundary parsing is deferred.

Supported examples:

```http
Authorization: Bearer eyJhbGciOi...
Authorization: Bearer <REDACTED:authorization.bearer>
```

```http
Authorization: Basic dXNlcjpwYXNz
Authorization: Basic <REDACTED:authorization.basic>
```

```http
Authorization: AMX appId:signature:nonce:timestamp
Authorization: AMX <REDACTED:authorization.credentials>
```

```http
Authorization: Digest username="user", realm="api", nonce="abc", response="def"
Authorization: Digest <REDACTED:authorization.credentials>
```

```http
Authorization: CustomScheme opaque value with parameters
Authorization: CustomScheme <REDACTED:authorization.credentials>
```

Milestone 2 uses these rule IDs and markers:

| Rule ID | Marker | Applies to |
| --- | --- | --- |
| `authorization.bearer` | `<REDACTED:authorization.bearer>` | `Bearer` scheme credentials |
| `authorization.basic` | `<REDACTED:authorization.basic>` | `Basic` scheme credentials |
| `authorization.other` | `<REDACTED:authorization.credentials>` | Other syntactically valid schemes |

The auth scheme must use the ASCII HTTP token character set:

```text
!#$%&'*+-.^_`|~0-9A-Za-z
```

Unicode scheme names and malformed schemes are unsupported and remain unchanged.

Bearer requirements:

- Match the header name case-insensitively.
- Match the `Bearer` scheme case-insensitively.
- Preserve header name casing, spacing around `:`, scheme casing, spacing between scheme and credentials, and trailing spaces or tabs.
- Require exactly one contiguous non-whitespace credential value.
- Replace only the credential with `<REDACTED:authorization.bearer>`.
- Leave empty, whitespace-only, or internally spaced Bearer credentials unchanged.
- Never fall through to the generic rule when Bearer-specific validation fails.

Basic requirements:

- Match the `Basic` scheme case-insensitively.
- Preserve header name casing, spacing around `:`, scheme casing, spacing between scheme and credentials, and trailing spaces or tabs.
- Require exactly one contiguous non-whitespace credential value.
- Do not Base64-decode or validate the credential.
- Replace only the credential with `<REDACTED:authorization.basic>`.
- Leave empty, whitespace-only, or internally spaced Basic credentials unchanged.
- Never fall through to the generic rule when Basic-specific validation fails.

Generic fallback requirements:

- Apply only to syntactically valid schemes other than Bearer and Basic.
- Preserve header name, spacing around `:`, scheme casing, and spacing between scheme and credentials.
- Replace the complete non-empty credential section after the scheme with `<REDACTED:authorization.credentials>`.
- Allow internal spaces, commas, quotes, equals signs, colons, slashes, and other punctuation in the credential section.
- Do not parse individual Digest, AWS, AMX, OAuth, Signature, or custom parameters.
- Leave empty or scheme-only headers unchanged.
- Never include custom scheme names in report rule IDs.

Unsupported forms remain unchanged:

- `Authorization:`
- `Authorization:` followed only by spaces or tabs
- `Authorization: Bearer`
- `Authorization: Bearer` followed only by spaces or tabs
- `Authorization: Basic`
- `Authorization: Basic` followed only by spaces or tabs
- `Authorization Bearer abc123`
- `X-Authorization: Bearer abc123`
- ` Authorization: Bearer abc123`

Already-redacted marker policy:

- The approved markers are `<REDACTED:authorization.bearer>`, `<REDACTED:authorization.basic>`, and `<REDACTED:authorization.credentials>`.
- If the complete credential section is exactly one approved marker, the value is already sanitized and produces no finding or count.
- This applies even when the marker appears under a different scheme.
- The sanitizer must not correct or normalize a marker used under another scheme.
- A marker embedded inside a larger raw credential value is not considered already sanitized.

## Milestone 3 Cookie Sanitization

Milestone 3 supports HTTP request `Cookie` header lines that begin exactly at the start of a decoded line. Indented `Cookie` lines, folded continuation lines, `Set-Cookie`, `X-Cookie`, and prose containing the word `Cookie` remain unsupported and unchanged. Exact header-like `Cookie:` lines inside message bodies may still be sanitized because full HTTP body-boundary parsing is deferred.

Milestone 3 preserves all existing Authorization behavior and all existing file safety, encoding, newline, dry-run, overwrite, reporting, and exit-code behavior. It adds no new dependencies and no new exit codes.

Supported per-value examples:

```http
Cookie: ASP.NET_SessionId=abc123; username=facu; _ga=GA1.2.123; theme=dark
Cookie: ASP.NET_SessionId=<REDACTED:cookie.value>; username=<REDACTED:cookie.value>; _ga=<REDACTED:cookie.value>; theme=<REDACTED:cookie.value>
```

```http
Cookie: preference="dark;compact"
Cookie: preference="<REDACTED:cookie.value>"
```

```http
Cookie: session=
Cookie: session=<REDACTED:cookie.value>
```

Fallback example:

```http
Cookie: session=abc; malformed-segment; theme=dark
Cookie: <REDACTED:cookie.header>
```

Milestone 3 uses these rule IDs and markers:

| Rule ID | Marker | Applies to |
| --- | --- | --- |
| `cookie.value` | `<REDACTED:cookie.value>` | Individual cookie values in completely and safely parsed `Cookie` headers |
| `cookie.header` | `<REDACTED:cookie.header>` | Whole-header fallback for non-empty `Cookie` header values that cannot be parsed safely and completely |

Header detection requirements:

- Match the `Cookie` header name case-insensitively.
- Match only exact decoded line-start `Cookie` headers.
- Allow spaces and tabs between `Cookie` and `:`.
- Allow spaces and tabs after `:`.
- Preserve header-name casing, spacing around `:`, trailing spaces and tabs, LF, CRLF, mixed newline sequences, UTF-8 BOM state, and final-newline state.
- Do not match `Set-Cookie`, `X-Cookie`, indented Cookie lines, folded continuation lines, or prose containing the word `Cookie`.

Safe per-value parsing requirements:

- Per-value redaction is allowed only when the complete `Cookie` header value parses safely.
- A safely parsed header consists of one or more non-empty `name=value` pairs separated by semicolons.
- Cookie names must be non-empty and use only ASCII HTTP token characters. `$` is allowed because it is an HTTP token character.
- Non-ASCII or malformed cookie names trigger whole-header fallback.
- Preserve spaces or tabs around `=`, spaces or tabs around `;`, original pair order, duplicate names, and trailing horizontal whitespace at the end of the header.
- The first `=` separates name from value.
- Values may be empty. Unquoted values may contain additional `=`, commas, colons, slashes, printable punctuation other than semicolons, and non-ASCII text.
- Quoted values are supported. Preserve the surrounding quote characters and replace only the quoted payload.
- Semicolons inside quoted values are part of the value, not pair delimiters.
- Valid escaped characters inside quoted values are supported.
- Missing closing quotes, dangling escapes, and non-horizontal junk after a closing quote before `;` or line end trigger fallback.

Empty behavior:

- `Cookie:` remains unchanged and produces no finding.
- `Cookie:` followed only by spaces or tabs remains unchanged and produces no finding.
- Explicit empty cookie values such as `Cookie: session=` are valid and must be redacted with `<REDACTED:cookie.value>`.

Whole-header fallback requirements:

- For any non-empty, non-marker, exact non-folded `Cookie` header that cannot be completely and deterministically parsed, replace the complete trimmed header value with `<REDACTED:cookie.header>`.
- Fallback triggers include missing `=`, empty name, leading semicolon, trailing semicolon, consecutive semicolons, malformed segments mixed with valid segments, malformed quoted syntax, missing closing quote, dangling escape, invalid non-ASCII cookie names, unsupported control characters, junk after a closing quote, or any other condition that prevents complete safe parsing.
- Do not partially sanitize a malformed header.
- A fallback header produces no `cookie.value` findings.

Folded Cookie headers are unsupported in milestone 3. If an exact `Cookie:` line is immediately followed by a physical line beginning with a space or tab, leave the entire folded form unchanged. Do not sanitize only the first physical line. Full folded-header parsing is deferred.

Approved Cookie markers are `<REDACTED:cookie.value>` and `<REDACTED:cookie.header>`.

Cookie marker policy:

- An exact approved marker used as a complete individual cookie value is already sanitized and produces no finding.
- An exact approved marker used as the complete trimmed `Cookie` header value is already sanitized and produces no finding.
- This applies even when the marker is used in an unexpected Cookie context.
- The sanitizer must not correct or normalize wrong-context markers.
- A marker embedded inside a larger raw value is not already sanitized and must be redacted.
- Trailing spaces and tabs after exact markers are preserved.
- Repeated sanitization must produce byte-identical output.

Examples remaining unchanged:

```http
Cookie: session=<REDACTED:cookie.value>
Cookie: session=<REDACTED:cookie.header>
Cookie: <REDACTED:cookie.header>
Cookie: <REDACTED:cookie.value>
```

Example requiring redaction:

```http
Cookie: session=prefix<REDACTED:cookie.value>suffix
Cookie: session=<REDACTED:cookie.value>
```

Reporting semantics:

- `cookie.value` counts each individual cookie value actually replaced.
- `cookie.header` counts each `Cookie` header line changed through fallback.
- A fallback header must not also increment `cookie.value`.
- Already-redacted values produce no count.
- Empty headers produce no count.
- Cookie names must never become rule IDs.
- Reports, CLI output, errors, logs, and snapshots must never include cookie values or source excerpts.

Cookie-name disclosure limitation:

- Milestone 3 intentionally preserves safely parsed cookie names.
- Preserved names may reveal framework details, authentication mechanisms, identity concepts, tenancy concepts, or application internals.
- Examples include `ASP.NET_SessionId`, `JSESSIONID`, `username`, `email`, `customerId`, `tenant`, and `portalAuth`.
- Preserving names is approved because it provides useful penetration-testing evidence context while values are removed.
- Cookie-name classification and selective hiding are deferred to milestone 4, which will define deterministic categories such as sensitive, telemetry, harmless, and unknown.

Control-character behavior:

- NUL remains rejected by the existing input-validation path.
- CR and LF remain line delimiters, not Cookie-value characters.
- Other unsupported control characters inside a `Cookie` value trigger whole-header fallback rather than a new global error.

## Milestone 4 Cookie-Name Classification

Milestone 4 preserves all Milestone 3 Cookie parsing, fallback, formatting, marker, report, file safety, encoding, newline, dry-run, overwrite, and exit-code behavior. It adds deterministic Cookie-name classification only after a complete `Cookie` header value parses safely.

Milestone 4 uses these conceptual categories internally:

```text
sensitive
telemetry
harmless
unknown
```

Milestone 4 uses this output policy:

| Category | Output behavior |
| --- | --- |
| `sensitive` | Redact the cookie value |
| `telemetry` | Redact the cookie value |
| `harmless` | Preserve the original value only for approved exact harmless names |
| `unknown` | Redact the cookie value |

Classification must depend only on the cookie name. The sanitizer must not inspect, decode, parse, infer from, or classify using cookie values. Unknown cookies remain redacted by default.

Classification matching requirements:

- Match Cookie names case-insensitively.
- Normalize only by ASCII lowercase for internal matching.
- Preserve original Cookie-name casing in output.
- Classify only names already accepted by the Milestone 3 ASCII HTTP-token Cookie-name grammar.
- Treat `_`, `-`, and `.` as distinct characters.
- Perform no Unicode normalization.
- Use no suffix matching.
- Use no broad substring matching.
- Use prefix or family matching only where explicitly approved below.
- Use fixed precedence `sensitive > telemetry > harmless > unknown`.
- Do not introduce a generalized precedence engine.

Approved sensitive exact names, matched case-insensitively:

```text
session
sessionid
session_id
sid
auth
auth_token
access_token
refresh_token
token
jwt
sso
sso_state
username
user
userid
user_id
email
identity
account
account_id
customer
customer_id
tenant
tenant_id
portalauth
asp.net_sessionid
jsessionid
phpsessid
connect.sid
laravel_session
```

These sensitive names are exact matches only. Names such as `superuser_setting`, `sessionStorageEnabled`, `consider`, `tokenizer_mode`, and `author_theme` must not match through substring behavior and remain unknown unless another approved exact or family rule applies.

Approved sensitive families:

```text
aspsessionid
aspsessionid + optional ASCII alphanumeric suffix
remember_web_ + non-empty suffix using the existing ASCII HTTP-token grammar
```

The `aspsessionid` family is case-insensitive and allows examples such as `ASPSESSIONID` and `ASPSESSIONIDABC123`. It must not accept punctuation or arbitrary suffix characters. The `remember_web_` family is case-insensitive, requires a non-empty suffix, allows examples such as `remember_web_abc123` and `remember_web_user-token`, and must not match plain `remember_web_`.

Approved telemetry exact names, matched case-insensitively:

```text
_ga
_gid
_gat
_fbp
_fbc
_hjid
_clck
_clsk
ajs_anonymous_id
ajs_user_id
_mkto_trk
hubspotutk
__hstc
__hssc
__hssrc
```

Approved telemetry prefix families, matched case-insensitively with a non-empty suffix:

```text
_ga_
_gat_
_hjsession_
_hjsessionuser_
amplitude_
amp_
mp_
```

Telemetry values remain redacted in Milestone 4 because they can be persistent browser, user, or device identifiers that enable correlation. Telemetry classification generates no special marker, rule ID, finding type, or report entry.

Approved harmless exact names, matched case-insensitively and preserved byte-for-byte:

```text
theme
color_scheme
display_mode
```

No prefix, suffix, wildcard, or substring matching is allowed for harmless names. Names such as `user_theme`, `theme_token`, `display_mode_session`, and `color_scheme_auth` remain unknown and redacted. Names such as `language`, `lang`, `locale`, `timezone`, `tz`, `cookie_consent`, `consent`, `banner_dismissed`, and `sidebar_state` are not approved harmless names and remain unknown and redacted in Milestone 4.

Milestone 4 keeps the existing Milestone 3 Cookie rule IDs and markers:

| Rule ID | Marker | Applies to |
| --- | --- | --- |
| `cookie.value` | `<REDACTED:cookie.value>` | Individual Cookie values actually redacted |
| `cookie.header` | `<REDACTED:cookie.header>` | Whole-header fallback for non-empty `Cookie` header values that cannot be parsed safely and completely |

Milestone 4 must not add `cookie.sensitive`, `cookie.unknown`, `cookie.telemetry`, `cookie.harmless`, `<REDACTED:cookie.sensitive>`, or `<REDACTED:cookie.unknown>`. All redacted individual values use `<REDACTED:cookie.value>`. Preserved harmless values generate no finding and no count. Reports reflect actual transformations, not classification decisions, and Cookie names must never appear in report IDs or report output.

Example:

```http
Cookie: ASP.NET_SessionId=abc123; username=facu; _ga=GA1.2.123; theme=dark; portalAuth=secret; custom=value
Cookie: ASP.NET_SessionId=<REDACTED:cookie.value>; username=<REDACTED:cookie.value>; _ga=<REDACTED:cookie.value>; theme=dark; portalAuth=<REDACTED:cookie.value>; custom=<REDACTED:cookie.value>
```

Compatibility and idempotence requirements:

- Existing `<REDACTED:cookie.value>` values remain unchanged as complete individual Cookie values.
- Existing `<REDACTED:cookie.header>` values remain unchanged as complete trimmed Cookie header values.
- Previously redacted telemetry values cannot be recovered and remain redacted.
- Existing sanitized evidence remains byte-identical when repeated sanitization runs.
- Embedded approved markers inside larger raw values remain raw and are redacted.
- Wrong-context existing approved Cookie markers remain unchanged according to the current marker policy.
- Category-specific markers such as `<REDACTED:cookie.sensitive>` and `<REDACTED:cookie.unknown>` are not approved markers and are treated as ordinary raw values unless existing parser behavior requires whole-header fallback.
- Repeated sanitization must produce byte-identical output.

Parser and fallback compatibility requirements:

- Classification applies only after the complete Cookie header parses safely.
- Complete parse before findings remains required.
- No malformed Cookie header may be partially sanitized or partially classified.
- Whole-header fallback remains `cookie.header` with `<REDACTED:cookie.header>`.
- Folded Cookie forms remain completely unchanged.
- `Set-Cookie` remains out of scope.
- Exact line-start `Cookie` matching remains unchanged.
- Existing formatting, BOM, newline, and final-newline behavior remains unchanged.

Milestone 4 privacy and security limitations:

- Preserving even approved harmless values carries residual risk because custom applications can overload apparently harmless names with sensitive content.
- Only the exact names `theme`, `color_scheme`, and `display_mode` are preserved.
- Telemetry values remain redacted because they may enable persistent correlation.
- Unknown cookies remain redacted.
- Name-only classification cannot guarantee that a preserved value is actually harmless.
- Cookie names themselves remain visible for safely parsed headers.
- Folded Cookie headers remain unsupported and may retain secrets.
- Exact header-like Cookie lines inside bodies may still be sanitized because full HTTP parsing is deferred.
- `Set-Cookie` remains out of scope.

## Milestone 5 Sensitive API/Auth Header Sanitization

Milestone 5 supports selected sensitive API/authentication-related HTTP-like header lines that begin exactly at the start of a decoded physical line. It preserves all existing Authorization, Cookie, file safety, encoding, newline, dry-run, overwrite, reporting, and exit-code behavior. It adds no new dependencies and no new exit codes.

Milestone 5 uses one generic fixed rule ID and marker:

| Rule ID | Marker | Applies to |
| --- | --- | --- |
| `header.secret` | `<REDACTED:header.secret>` | Whole trimmed values for approved sensitive header names |

The generic marker keeps the marker surface small, avoids revealing the exact secret type in reports, avoids marker proliferation, and remains simple and deterministic. Header names remain visible in sanitized evidence for context. Milestone 5 must not introduce grouped or per-header rule IDs or markers such as `header.api_key`, `header.auth_token`, `header.csrf_token`, `header.signature`, `<REDACTED:header.api_key>`, or dynamic report IDs derived from header names.

Approved header names are exact case-insensitive matches only.

API key headers:

```text
x-api-key
api-key
apikey
x-apikey
api_key
x-api_key
```

Auth token headers:

```text
x-auth-token
auth-token
x-access-token
access-token
x-session-token
session-token
x-id-token
id-token
x-refresh-token
refresh-token
```

CSRF/XSRF headers:

```text
x-csrf-token
csrf-token
x-xsrf-token
xsrf-token
x-csrftoken
csrftoken
x-xsrftoken
x-csrf
csrf
```

CSRF/XSRF tokens are treated as sensitive in penetration-testing evidence because they may be session-bound and abuse-enabling, even when they are not equivalent to authentication tokens.

Cloud/vendor signature headers:

```text
x-amz-security-token
x-amz-credential
x-amz-signature
x-goog-api-key
x-goog-signature
x-ms-token-aad-access-token
```

Explicit secret headers:

```text
x-secret
x-client-secret
client-secret
```

Deferred privacy/client identity headers:

```text
x-forwarded-for
x-real-ip
cf-connecting-ip
true-client-ip
x-client-ip
```

These are privacy identifiers, not authentication secrets, and belong in a future privacy/identifier milestone.

Deferred identifier headers:

```text
x-client-id
client-id
x-tenant-id
tenant-id
x-user-id
user-id
```

These are identifiers, not always secrets, and must not be folded into the milestone 5 auth-secret scope.

Deferred authorization-like header:

```text
proxy-authorization
```

`Proxy-Authorization` is semantically close to `Authorization` and is deferred for a separate decision on scheme-preserving behavior, markers, and rule IDs.

Non-approved variants intentionally remain unchanged:

```text
x-token
token
x-jwt
jwt
x-api-secret
authorization-token
x-api-key-name
x-access-token-expires
x-csrf-token-enabled
```

No substring matching is approved. Near misses such as `monkey`, `keyboard`, `x-tokenizer-mode`, `x-author-theme`, `x-api-key-name`, `x-access-token-expires`, and `x-csrf-token-enabled` remain unchanged.

Header detection requirements:

- Match only physical decoded lines starting at column 0.
- Match approved header names case-insensitively.
- Require the approved name followed only by optional spaces or tabs and then `:`.
- Allow spaces and tabs before `:`.
- Allow spaces and tabs after `:`.
- Replace only the complete trimmed value after `:`.
- Preserve header name casing, colon spacing, leading spaces or tabs after `:`, trailing spaces or tabs after the value, line ending, UTF-8 BOM state, LF, CRLF, mixed newline sequences, and final-newline state.
- Support a final line without a newline.
- Do not match indented lines.
- Do not match folded sensitive-header forms.
- Do not match `authorization`, `cookie`, `set-cookie`, or `proxy-authorization`.

Folded sensitive headers are unsupported in milestone 5. If an exact sensitive header line is immediately followed by a physical line beginning with a space or tab, leave the complete folded form unchanged, emit no `header.secret` finding, and do not sanitize only the first physical line. Full folded-header parsing is deferred, so folded sensitive headers may retain secrets.

Empty and whitespace-only values remain unchanged and produce no finding:

```http
X-API-Key:
X-API-Key: [spaces only]
```

This is approved because no secret value is present, it is consistent with empty or whitespace-only Cookie behavior, and it avoids findings for absence of data.

For non-empty values, milestone 5 replaces the whole trimmed value:

```http
X-API-Key: abc123[spaces]
X-API-Key: <REDACTED:header.secret>[spaces]
```

Quoted, comma-separated, and structured values are redacted as one complete trimmed value. Milestone 5 must not parse quoted values, comma-separated values, structured values, or quote payloads.

Examples:

```http
X-API-Key: "abc123"
X-API-Key: key=value; sig=abc123
X-API-Key: one,two,three
```

All become, while preserving surrounding header formatting and trailing horizontal whitespace:

```http
X-API-Key: <REDACTED:header.secret>
```

Approved milestone 5 marker:

```text
<REDACTED:header.secret>
```

Marker policy:

- An exact complete trimmed value equal to `<REDACTED:header.secret>` is unchanged and produces no finding.
- Trailing spaces and tabs after the exact marker are preserved.
- An embedded approved marker is treated as raw and redacted.
- Unapproved header marker-like values are treated as raw and redacted.
- Wrong-family Authorization and Cookie markers inside sensitive headers are treated as raw and redacted.
- Do not create a generalized marker framework.

Examples remaining unchanged:

```http
X-API-Key: <REDACTED:header.secret>
X-API-Key: <REDACTED:header.secret>[spaces]
```

Examples requiring redaction:

```http
X-API-Key: prefix<REDACTED:header.secret>suffix
X-API-Key: <REDACTED:header.api_key>
X-Auth-Token: <REDACTED:authorization.bearer>
X-CSRF-Token: <REDACTED:cookie.value>
```

Expected output:

```http
X-API-Key: <REDACTED:header.secret>
X-API-Key: <REDACTED:header.secret>
X-Auth-Token: <REDACTED:header.secret>
X-CSRF-Token: <REDACTED:header.secret>
```

Reporting semantics:

- `header.secret` counts one finding per sensitive header line whose non-empty value is actually replaced.
- Empty or whitespace-only values produce no count.
- Exact approved marker values produce no count.
- Folded sensitive headers produce no count because they remain unchanged.
- Repeated sensitive headers count once per changed physical line.
- Reports contain only fixed rule ID `header.secret` and counts.
- Reports never contain raw values, source excerpts, header names as dynamic IDs, or replacement previews.

Milestone 5 compatibility requirements:

- Existing `Authorization: Bearer`, `Authorization: Basic`, generic `Authorization` schemes, Authorization markers, Authorization counts, and Authorization idempotence remain unchanged.
- Existing Cookie parser, Cookie fallback, Cookie harmless preservation, Cookie marker policy, Cookie counts, folded Cookie behavior, and `Set-Cookie` scope remain unchanged.
- Query parameters, URLs, JSON bodies, XML bodies, form bodies, multipart parsing, response `Set-Cookie`, `Proxy-Authorization`, full HTTP parsing, and folded-header parsing remain out of scope.

Milestone 5 security and privacy limitations:

- Selected sensitive headers may contain API keys, auth/session/access/refresh/id tokens, CSRF/XSRF tokens, cloud temporary tokens, cloud signatures, or client secrets.
- Cloud signature headers can be highly sensitive.
- Preserving header names may reveal cloud providers, authentication architecture, frameworks, or API design.
- Exact header-like lines inside bodies may be redacted because full HTTP parsing remains deferred.
- Non-approved custom secret headers may remain raw.
- Folded sensitive headers remain unchanged and may retain secrets.
- IP/client identity headers are deferred to a privacy/identifier milestone.
- `Proxy-Authorization` is deferred.
- `Set-Cookie`, URLs, query strings, and bodies remain out of scope.
- The tool does not guarantee detection or removal of every secret.

## Milestone 6 Sensitive Query Parameter Sanitization

Milestone 6 supports selected sensitive raw URL query parameter values in decoded text evidence. It preserves all existing Authorization, Cookie, selected sensitive-header, file safety, encoding, newline, dry-run, overwrite, reporting, and exit-code behavior. It adds no new dependencies and no new exit codes.

The rule may operate on raw URL/query-like substrings appearing in HTTP request lines, absolute URLs, relative paths with query strings, query-only tokens such as `?sig=...`, non-sensitive header values such as `Referer` and `Location`, and raw body or log lines when matching is syntactic and deterministic. This is not full HTTP parsing, so exact URL-like text inside bodies or logs may be sanitized as an accepted limitation.

Milestone 6 uses one generic fixed rule ID and marker:

| Rule ID | Marker | Applies to |
| --- | --- | --- |
| `query.secret` | `<REDACTED:query.secret>` | Values for approved sensitive raw URL query parameter names |

The generic marker keeps the marker surface small, avoids revealing the exact secret type in reports, avoids marker proliferation, preserves simple idempotence, and remains consistent with `header.secret`. Parameter names remain visible in sanitized evidence for URL structure. Milestone 6 must not introduce grouped or per-parameter rule IDs or markers such as `query.token`, `query.api_key`, `query.signature`, `query.oauth`, or dynamic report IDs derived from parameter names.

Approved auth/session/token parameter names, matched case-insensitively as exact raw names:

```text
access_token
auth_token
id_token
jwt
refresh_token
session
session_id
sid
token
```

Approved API key parameter names, matched case-insensitively as exact raw names:

```text
api-key
api_key
apikey
```

Approved OAuth/client secret parameter name, matched case-insensitively as an exact raw name:

```text
client_secret
```

Approved signature and signed URL parameter names, matched case-insensitively as exact raw names:

```text
sig
signature
x-amz-credential
x-amz-security-token
x-amz-signature
x-goog-credential
x-goog-signature
```

`sig` and `signature` are explicitly approved because real penetration-testing evidence may include signed URL or callback query parameters using those names.

Deferred parameter names:

```text
key
code
state
nonce
secret
sign
signed
se
sp
sv
sr
st
expires
expiry
timestamp
redirect_uri
url
email
user
user_id
bearer
sessionid
app_key
subscription-key
ocp-apim-subscription-key
client_assertion
assertion
samlresponse
saml_response
idp_token
password
passwd
pwd
shared_secret
private_key
csrf
csrf_token
xsrf
xsrf_token
utm_source
utm_medium
utm_campaign
gclid
fbclid
msclkid
_ga
```

Deferred-name rationale:

- `key`, `code`, `state`, `nonce`, `secret`, `sign`, and `signed` are useful but too broad for the initial milestone.
- Short cloud/SAS names such as `se`, `sp`, `sv`, `sr`, and `st` are too broad without a dedicated signed-URL context.
- Tracking parameters are privacy identifiers and belong in a separate privacy/telemetry milestone.
- Password and SAML/form-like parameters are deferred until body/form parsing scope is addressed or explicitly approved.

Matching requirements:

- Parameter-name matching is exact, raw, and case-insensitive.
- Matching applies only to the raw parameter name before `=`.
- No URL decoding is performed.
- Percent-encoded names are not matched; `access%5Ftoken` does not match `access_token`.
- `_`, `-`, and `.` remain distinct.
- No substring matching is approved.
- No value-based classification is approved.
- Do not infer sensitivity from parameter position, value shape, length, UUID-like format, apparent encoding, or surrounding URL text.

Near misses remain unchanged:

```text
keyboard
monkey
tokenizer
access_token_expires
signature_algorithm
design
signal
signed_in
code_verifier
postcode
state_name
nonces
api_key_name
```

Query boundary and parsing behavior:

- Use a small raw query scanner, not a full URL parser.
- `?` starts a raw query candidate when encountered in decoded text.
- Repeated `?` inside the same query token is treated as data, not a recursive query start.
- Multiple separate query tokens on one line are supported.
- `&` separates parameters.
- `;` also separates parameters.
- `#` ends the current query segment.
- Spaces, tabs, CR, LF, quotes, apostrophes, and backticks terminate the query token.
- `<` and `>` are URL wrapping delimiters.
- Angle-bracket wrapped URLs such as `<https://x.test/?sig=abc>` preserve the outer `>`.
- Query parsing preserves all non-value bytes and text.
- Parameter order, repeated parameters, and separators are preserved.
- No sorting, normalization, decoding, or re-encoding occurs.
- `&amp;` is not decoded to `&` in Milestone 6.

Value span behavior:

- For a matched parameter with `=`, replace only the complete raw value span.
- Preserve parameter name casing.
- Preserve `=`.
- Preserve separators.
- Preserve parameter order and repeated parameters.
- Preserve percent-encoding outside the replaced value.
- Do not parse nested URLs inside values.
- Do not redact non-approved parameters.

Example:

```text
https://example.test/a?token=abc&theme=dark
https://example.test/a?token=<REDACTED:query.secret>&theme=dark
```

Empty and no-value behavior:

```text
?token=value
?token=<REDACTED:query.secret>
```

```text
?token=
?token=<REDACTED:query.secret>
```

Explicit empty sensitive parameter values are still intentional sensitive fields and are normalized to the marker. They count once.

```text
?token
?token&foo=bar
```

Bare no-value parameters remain unchanged and produce no count because there is no value span to replace without changing structure.

Marker policy:

- The approved Milestone 6 marker is `<REDACTED:query.secret>`.
- An exact complete raw parameter value equal to `<REDACTED:query.secret>` is unchanged and produces no finding.
- Marker handling must be marker-aware so the approved marker's `<` and `>` do not break idempotence or query boundary detection.
- Embedded `<REDACTED:query.secret>` inside a larger raw value is treated as raw and redacted.
- Unapproved query marker-like values are treated as raw and redacted.
- Wrong-family markers such as `<REDACTED:header.secret>`, `<REDACTED:cookie.value>`, or `<REDACTED:authorization.bearer>` are treated as raw query values and redacted.
- Repeated sanitization must produce byte-identical output.

Examples:

```text
?token=<REDACTED:query.secret>
?token=prefix<REDACTED:query.secret>suffix
?token=<REDACTED:header.secret>
?token=<REDACTED:cookie.value>
```

Expected output:

```text
?token=<REDACTED:query.secret>
?token=<REDACTED:query.secret>
?token=<REDACTED:query.secret>
?token=<REDACTED:query.secret>
```

Interaction with existing rules:

- Existing Authorization findings are authoritative and remain unchanged.
- Existing Cookie findings are authoritative and remain unchanged.
- Existing `header.secret` findings are authoritative and remain unchanged.
- Query findings that overlap existing findings are skipped and produce no `query.secret` count.
- `apply_findings` remains the final overlap guard.

Example:

```http
X-API-Key: https://x.test/?sig=abc
```

This reports only `header.secret` because the sensitive-header finding covers the URL value.

A preserved harmless Cookie value may still receive a `query.secret` finding if no Cookie finding covers that span:

```http
Cookie: theme=https://x.test/?sig=abc
Cookie: theme=https://x.test/?sig=<REDACTED:query.secret>
```

This is approved because `theme` is intentionally preserved by the Cookie rule and there is no overlapping Cookie finding.

Reporting semantics:

- `query.secret` counts one finding per approved query parameter value actually replaced.
- Already-redacted exact query marker values produce no count.
- Bare no-value parameters produce no count.
- Non-approved parameters produce no count.
- Query findings skipped because they overlap existing findings produce no count.
- Reports contain only fixed rule ID `query.secret` and counts for query findings.
- Reports never contain raw values, source excerpts, parameter names as dynamic IDs, or replacement previews.

Milestone 6 security and privacy limitations:

- `sig` and `signature` are often highly sensitive in signed URLs and callback flows.
- OAuth/OIDC-style token parameters can grant access or represent session-bound state.
- API key parameters can authenticate requests.
- Cloud signature parameters can authorize temporary access.
- `code`, `state`, `nonce`, `key`, short SAS parameters, and tracking identifiers are deferred to avoid broad false positives.
- Exact raw URL-like text inside bodies or logs may be sanitized because Milestone 6 is not full HTTP parsing.
- Malformed or unusual query strings may be partially missed.
- Percent-encoded parameter names are not decoded and may be missed.
- Recursive URL-in-value parsing is deferred.
- Existing Authorization, Proxy-Authorization, Cookie, and sensitive-header rules remain authoritative for overlapping spans after Milestone 11.
- The tool does not guarantee complete detection or removal of every secret.

## Milestone 9 Sensitive JSON-Like Field Sanitization

Milestone 9 adds deterministic sanitization for approved sensitive JSON-like string fields in decoded text evidence. It preserves all existing Authorization, Cookie, selected sensitive-header, selected sensitive-query-parameter, file-processing, safety, encoding, newline, reporting, CLI, and exit-code behavior.

Milestone 9 uses one generic fixed rule ID and marker:

| Rule ID | Marker | Applies to |
| --- | --- | --- |
| `json.value` | `<REDACTED:json.value>` | String values for approved JSON-like field names |

The generic marker keeps the marker surface small, avoids revealing the exact secret type in reports, avoids marker proliferation, preserves simple idempotence, and remains consistent with `header.secret` and `query.secret`. Field names remain visible in sanitized evidence for structure.

Milestone 9 scope:

- Scan decoded text for JSON-like string-key/string-value pairs only.
- Preserve original formatting by replacing only the raw string value payload between the value's opening and closing quotes.
- Preserve key casing, spacing around `:`, commas, braces, brackets, line endings, UTF-8 BOM state, and final-newline state.
- Operate in full JSON documents, HTTP bodies, logs, and report snippets where JSON-like string-key/string-value pairs appear.
- Keep one input file, one explicit output file, and complete-file in-memory processing.
- Keep deterministic built-in behavior only.

Milestone 9 must not include:

- Full JSON parsing or validation.
- JSON reserialization.
- JSON schema support.
- JSON object/array direct-value redaction.
- Number, boolean, or null value redaction.
- Recursive parsing of URLs inside JSON values.
- Form-urlencoded parsing.
- Multipart parsing.
- XML parsing.
- HTML/JavaScript parsing.
- YAML/TOML parsing.
- Entropy-based detection.
- Arbitrary regex or user-defined rules.
- Configurable rules.
- Plugins, registries, or parser frameworks.
- External dependencies.
- Network behavior.
- Telemetry.
- LLM behavior.
- Persistence.
- Directory scanning.
- New CLI options.
- New exit codes.

### Parsing Strategy

Milestone 9 uses a conservative raw JSON-like scanner, not `json.loads()` or a full JSON parser. The scanner looks for patterns equivalent to:

```json
"approved_field": "string value"
```

The scanner must:

- Recognize a double-quoted string key.
- Skip optional whitespace between the closing key quote and `:`.
- Require `:` after the key.
- Skip optional whitespace between `:` and the opening value quote.
- Recognize a double-quoted string value.
- Replace only the raw string payload between the value's opening and closing quotes.
- Preserve the surrounding quotes and all other text.

The scanner should respect valid JSON string escapes such as `\"`, `\\`, `\/`, `\n`, `\t`, and `\u1234` when locating the closing value quote. It must not decode escape sequences. It must treat literal CR or LF inside a string, invalid escapes, or unterminated strings as malformed and skip that candidate rather than redacting a larger span.

### Approved Field Names

Approved field names are matched exactly after ASCII-only lowercase normalization. The approved set is fixed and exact. No substring, prefix, suffix, or wildcard matching is allowed. No Unicode normalization is performed. Field names are not decoded from JSON unicode escapes for matching purposes. `_`, `-`, and `.` remain distinct characters.

Approved names:

```text
token
access_token
accessToken
refresh_token
refreshToken
id_token
idToken
auth_token
authToken
jwt
session
session_id
sessionId
sid
api_key
apiKey
apikey
x_api_key
xApiKey
password
passwd
pwd
client_secret
clientSecret
shared_secret
sharedSecret
private_key
privateKey
sig
signature
x_amz_signature
xAmzSignature
x_goog_signature
xGoogSignature
client_assertion
clientAssertion
saml_response
samlResponse
samlresponse
```

Names such as `token`, `session`, `sig`, and `signature` have known false-positive risk but are approved because they are common in API evidence and matching is exact only. Names such as `tokenizer`, `access_token_expires`, `password_policy`, `secret_name`, `signature_algorithm`, `code_verifier`, `state_name`, and `private_key_id` are near misses and must remain unchanged.

### Deferred Field Names

The following names are intentionally deferred to future milestones or explicit approvals:

```text
key
secret
code
state
nonce
assertion
sign
signed
expires
expiry
timestamp
redirect_uri
url
email
user
user_id
client_id
tenant_id
account_id
customer_id
csrf
csrf_token
xsrf
xsrf_token
code_verifier
state_name
tokenizer
access_token_expires
password_policy
secret_name
signature_algorithm
private_key_id
```

`secret`, `code`, `state`, `nonce`, `assertion`, and `key` are context-dependent or too broad for this milestone. CSRF/XSRF fields are deferred for JSON until explicitly approved. Identifier-like fields such as `email`, `user`, `user_id`, `client_id`, `tenant_id`, `account_id`, and `customer_id` are deferred to avoid expanding scope into privacy/identifier redaction.

### Matching Semantics

- Field-name matching is exact and raw after ASCII-only lowercase normalization.
- No substring, prefix, or suffix matching is approved.
- No Unicode normalization is performed.
- No URL decoding is performed.
- No JSON unicode-escape decoding is performed for matching; `"access\u005Ftoken"` does not match `access_token`.
- `_`, `-`, and `.` remain distinct.
- No value-based classification is approved.
- Field names must never become rule IDs or report identifiers.

### Value-Type Behavior

Milestone 9 redacts only JSON-like string values.

Examples for a field named `token`:

```json
{
  "token": "abc",
  "token": 123,
  "token": true,
  "token": false,
  "token": null,
  "token": ["abc"],
  "token": {"nested": "abc"}
}
```

Behavior:

- `"token": "abc"` is redacted.
- `"token": 123` remains unchanged.
- `"token": true` remains unchanged.
- `"token": false` remains unchanged.
- `"token": null` remains unchanged.
- `"token": ["abc"]` remains unchanged as the direct value.
- `"token": {"nested": "abc"}` remains unchanged as the direct value.
- Nested approved string fields inside arrays or objects are still redacted when they appear as their own JSON-like string-key/string-value pairs.

### Empty String Behavior

Explicit empty JSON string values are redacted and counted once.

Example:

```json
{"token": ""}
```

Expected output:

```json
{"token": "<REDACTED:json.value>"}
```

Rationale:

- An empty string is an explicit value span.
- This aligns with explicit empty query parameter values and explicit empty Cookie values.

### Marker And Idempotence Policy

Approved milestone 9 marker:

```text
<REDACTED:json.value>
```

Policy:

- An exact JSON string value equal to `<REDACTED:json.value>` is unchanged and produces no finding.
- An embedded `<REDACTED:json.value>` inside a larger string is treated as raw and redacted.
- Unapproved JSON marker-like values such as `<REDACTED:json.token>` are treated as raw and redacted.
- Wrong-family markers such as `<REDACTED:query.secret>`, `<REDACTED:header.secret>`, `<REDACTED:cookie.value>`, and `<REDACTED:authorization.bearer>` are treated as raw and redacted.
- Repeated sanitization must produce byte-identical output.
- The marker remains inside the existing JSON string quotes.

Examples:

```json
{"token": "<REDACTED:json.value>"}
{"token": "prefix<REDACTED:json.value>suffix"}
{"token": "<REDACTED:query.secret>"}
{"token": "<REDACTED:json.token>"}
```

Expected output:

```json
{"token": "<REDACTED:json.value>"}
{"token": "<REDACTED:json.value>"}
{"token": "<REDACTED:json.value>"}
{"token": "<REDACTED:json.value>"}
```

### Escaping And Replacement Policy

The marker contains only safe ASCII characters and no quotes or backslashes, so it can be inserted as raw string content between the existing value quotes without JSON escaping.

Example:

```json
"token": "abc"
```

becomes:

```json
"token": "<REDACTED:json.value>"
```

The surrounding formatting, including whitespace and punctuation, must be preserved.

### Overlap Behavior

Existing Authorization, Proxy-Authorization, Cookie, selected sensitive-header, selected form-urlencoded, and selected sensitive-query-parameter findings remain authoritative after Milestone 11. JSON findings must run after those broader finders and skip any candidate value span that overlaps an existing finding.

Example:

```http
Authorization: Bearer {"access_token":"abc"}
X-API-Key: {"token":"abc"}
Cookie: session={"token":"abc"}
GET /api?token={"access_token":"abc"} HTTP/1.1
```

In all of these cases, the broader existing finding covers the span and no `json.value` finding is emitted.

A preserved harmless Cookie value may still receive a `json.value` finding when no Cookie finding covers that span:

```http
Cookie: theme={"token":"abc"}
```

This is approved because `theme` is an approved harmless Cookie name whose value is intentionally preserved, so no Cookie finding covers that value.

A non-sensitive query or header value may also receive a `json.value` finding when no broader finding covers it:

```text
?payload={"access_token":"abc"}
```

### Reporting Semantics

- `json.value` counts one finding per approved JSON-like string field value actually replaced.
- Exact approved marker values produce no count.
- Deferred or non-approved field names produce no count.
- Non-string values produce no count.
- Malformed candidates produce no count.
- JSON findings skipped because they overlap existing findings produce no count.
- Reports contain only fixed rule ID `json.value` and counts.
- Reports never contain raw values, field names, JSON snippets, or replacement previews.

### Milestone 9 Acceptance Criteria

- Existing Authorization behavior remains unchanged.
- Existing Cookie behavior remains unchanged.
- Existing selected sensitive-header behavior remains unchanged.
- Existing selected sensitive-query-parameter behavior remains unchanged.
- Approved field names redact only JSON-like string values.
- Deferred and near-miss field names remain unchanged.
- Matching is exact and ASCII-lowercase based.
- No substring, prefix, or suffix matching is approved.
- No Unicode escape decoding for field names is performed.
- No value-based classification is approved.
- Empty string values are redacted with `<REDACTED:json.value>` and counted once.
- Non-string direct values remain unchanged.
- Formatting is preserved by replacing only the value payload between quotes.
- Escaped strings are parsed safely enough to locate the closing quote without decoding escapes.
- Malformed candidates are skipped rather than fallback-redacted.
- Exact `<REDACTED:json.value>` values are idempotent.
- Embedded `<REDACTED:json.value>` values are redacted.
- Unapproved JSON marker-like values are redacted.
- Wrong-family markers are redacted.
- JSON findings overlapping Authorization, Proxy-Authorization, Cookie, `header.secret`, `form.value`, or `query.secret` findings are skipped after Milestone 11.
- JSON may redact inside preserved harmless Cookie values and non-sensitive query/header text when no broader finding overlaps.
- Reports use only fixed rule ID `json.value`.
- Reports contain no raw values, field names, JSON snippets, or replacement previews.
- No new dependency, configuration file, module, plugin, registry, network behavior, telemetry collection, LLM behavior, persistence, full JSON parsing, JSON reserialization, directory processing, overwrite mode, or exit code is introduced.
- Existing source immutability, output collision, dry-run, UTF-8, UTF-8 BOM, LF, CRLF, mixed-newline, final-newline, 10 MiB, NUL-byte, safe-error, and exit-code behavior remains unchanged.
- Tests use only synthetic data.

## Milestone 10 Sensitive Form-URL-Encoded Field Sanitization

Milestone 10 adds deterministic sanitization for approved sensitive `application/x-www-form-urlencoded` field values in HTTP-like evidence. It preserves all existing Authorization, Cookie, selected sensitive-header, selected sensitive-query-parameter, selected sensitive JSON-like field, file-processing, safety, encoding, newline, reporting, CLI, and exit-code behavior.

Milestone 10 uses one generic fixed rule ID and marker:

| Rule ID | Marker | Applies to |
| --- | --- | --- |
| `form.value` | `<REDACTED:form.value>` | Raw values for approved sensitive form-urlencoded field names |

The generic marker keeps the marker surface small, avoids revealing the exact secret type in reports, avoids marker proliferation, preserves simple idempotence, and remains consistent with `header.secret`, `query.secret`, and `json.value`. Field names remain visible in sanitized evidence for structure.

Milestone 10 scope:

- Scan decoded text for HTTP-like `Content-Type: application/x-www-form-urlencoded` header lines.
- Support optional media-type parameters such as `; charset=utf-8`.
- Scan only the immediate first physical line after the blank header/body separator.
- Replace only the raw value span after `=` for approved field names.
- Preserve field name casing, spacing around `=`, `&` separators, field order, repeated fields, line endings, UTF-8 BOM state, and final-newline state.
- Operate in HTTP request bodies and raw evidence snippets where a supported Content-Type line precedes a supported body line.
- Keep one input file, one explicit output file, and complete-file in-memory processing.
- Keep deterministic built-in behavior only.

Milestone 10 must not include:

- Full HTTP message parsing.
- Request/response boundary parsing.
- `Content-Length`-based body parsing.
- Chunked-transfer decoding.
- Multi-line or wrapped form body parsing.
- Raw form-urlencoded scanning without a supported Content-Type line.
- Form data in arbitrary prose.
- Multipart parsing.
- JSON parsing changes.
- XML parsing.
- HTML/JavaScript parsing.
- YAML/TOML parsing.
- Recursive URL parsing inside form values.
- URL decoding or re-encoding.
- Percent-decoding of names or values.
- Plus-decoding of names or values.
- Semantic OAuth flow validation.
- Entropy-based detection.
- Arbitrary regex or user-defined rules.
- Configurable rules.
- Plugins, registries, or parser frameworks.
- External dependencies.
- Network behavior.
- Telemetry.
- LLM behavior.
- Persistence.
- Directory scanning.
- New CLI options.
- New exit codes.

### Parsing Strategy

Milestone 10 uses a conservative Content-Type-gated form-urlencoded scanner, not a full HTTP parser.

The scanner must:

- Match `Content-Type` case-insensitively at the start of a decoded physical line.
- Allow spaces and tabs between `Content-Type` and `:`.
- Allow spaces and tabs after `:`.
- Require the media type `application/x-www-form-urlencoded` after optional whitespace.
- Allow optional media-type parameters such as `; charset=utf-8` after the media type.
- Locate the immediate first physical line after the blank header/body separator line following the matched Content-Type line.
- Treat that single physical line as the form body candidate, even if it is blank.
- Split the candidate into raw `name=value` segments using `&` as the only separator.
- Preserve every non-value byte.

A blank header/body separator line is a physical line whose content is empty after removing its line ending. The form body candidate is the immediate first physical line after the separator. If that line is blank, no form body is scanned. If no separator line exists after the Content-Type line, no form body is scanned.

### Approved Field Names

Approved field names are matched exactly after ASCII-only lowercase normalization. The approved set is fixed and exact. No substring, prefix, suffix, or wildcard matching is allowed. No Unicode normalization is performed. Field names are not decoded from percent escapes or plus signs for matching purposes. `_`, `-`, and `.` remain distinct characters.

Approved names:

```text
access_token
accessToken
auth_token
authToken
id_token
idToken
jwt
refresh_token
refreshToken
session
session_id
sessionId
sid
token
api-key
api_key
apiKey
apikey
x_api_key
xApiKey
client_secret
clientSecret
shared_secret
sharedSecret
private_key
privateKey
password
passwd
pwd
client_assertion
clientAssertion
saml_response
samlResponse
samlresponse
sig
signature
x-amz-credential
x-amz-security-token
x-amz-signature
x-goog-credential
x-goog-signature
x_amz_signature
xAmzSignature
x_goog_signature
xGoogSignature
csrf
csrf_token
xsrf
xsrf_token
```

CSRF/XSRF fields are approved for form-urlencoded bodies because anti-CSRF tokens commonly appear as form field values. Names such as `token`, `session`, `sig`, and `signature` have known false-positive risk but are approved because matching is Content-Type-gated and exact-name-only. Names such as `password_policy`, `access_token_expires`, `client_secret_name`, `tokenizer`, `state_name`, `code_challenge`, and `code_challenge_method` are near misses and must remain unchanged.

### Deferred Field Names

The following names are intentionally deferred to future milestones or explicit approvals:

```text
key
secret
code
state
nonce
assertion
sign
signed
expires
expiry
timestamp
redirect_uri
url
email
user
user_id
username
client_id
tenant_id
account_id
customer_id
grant_type
scope
otp
mfa_code
se
sp
sv
sr
st
utm_source
gclid
fbclid
```

`code`, `state`, and `nonce` are context-dependent OAuth fields and are deferred. `username`, `email`, `user`, and identifier-like fields are deferred to avoid expanding privacy/PII scope. `grant_type` and `scope` are OAuth metadata rather than secrets by default and are deferred. `otp` and `mfa_code` can be sensitive but require explicit future approval. `secret` and `key` are too broad for this milestone. Short SAS-style names such as `se`, `sp`, `sv`, `sr`, and `st` are deferred.

### Matching Semantics

- Field-name matching is exact and raw after ASCII-only lowercase normalization.
- No substring, prefix, or suffix matching is approved.
- No Unicode normalization is performed.
- No URL decoding is performed.
- No percent-decoding is performed; `access%5Ftoken` does not match `access_token`.
- No plus-decoding is performed.
- `_`, `-`, and `.` remain distinct.
- No value-based classification is approved.
- Field names must never become rule IDs or report identifiers.

### Value Behavior

Milestone 10 redacts only raw form field values for approved names.

- For a matched field with `=`, replace only the complete raw value span after `=`.
- Preserve field name casing.
- Preserve `=`.
- Preserve `&` separators.
- Preserve field order and repeated fields.
- Preserve percent-encoding and plus signs in non-redacted values.
- Do not redact non-approved fields.
- Do not decode nested URLs inside values.

Examples:

```text
access_token=abc
access_token=
access_token
access_token=a=b=c
access_token=abc&theme=dark
```

Expected output:

```text
access_token=<REDACTED:form.value>
access_token=<REDACTED:form.value>
access_token
access_token=<REDACTED:form.value>
access_token=<REDACTED:form.value>&theme=dark
```

Explicit empty values are intentional sensitive fields and are normalized to the marker. They count once.

Bare no-value parameters such as `access_token` remain unchanged and produce no count because there is no value span to replace without changing structure.

### Separator Behavior

Milestone 10 supports `&` as the only form field separator. Semicolon-separated form fields are deferred.

```text
access_token=abc;theme=dark
```

For M10, if this appears in a supported form body line, it is treated as one raw value for `access_token` ending at the line boundary, because `;` is not a recognized form separator. Otherwise it follows the scanner's documented raw value boundary behavior.

### Encoding Policy

Milestone 10 preserves raw decoded text.

- Do not percent-decode names.
- Do not percent-decode values.
- Do not plus-decode names.
- Do not plus-decode values.
- Match raw names only.
- Redact raw value spans without decoding.
- Preserve `%XX` and `+` in non-redacted values.
- Do not re-encode anything.

Examples:

```text
access_token=synthetic%2Dtoken
access%5Ftoken=synthetic-token
password=hello+world
```

Expected policy:

- `access_token=synthetic%2Dtoken` redacts because the raw name matches.
- `access%5Ftoken=synthetic-token` does not match `access_token` because the name is not percent-decoded.
- `password=hello+world` redacts the raw value `hello+world` without decoding the plus signs.

### Marker And Idempotence Policy

Approved milestone 10 marker:

```text
<REDACTED:form.value>
```

Policy:

- An exact complete form field value equal to `<REDACTED:form.value>` is unchanged and produces no finding.
- An embedded `<REDACTED:form.value>` inside a larger value is treated as raw and redacted.
- Unapproved form marker-like values such as `<REDACTED:form.token>` are treated as raw and redacted.
- Wrong-family markers such as `<REDACTED:query.secret>`, `<REDACTED:header.secret>`, `<REDACTED:cookie.value>`, `<REDACTED:authorization.bearer>`, and `<REDACTED:json.value>` are treated as raw and redacted.
- Repeated sanitization must produce byte-identical output.

Examples:

```text
access_token=<REDACTED:form.value>
access_token=prefix<REDACTED:form.value>suffix
access_token=<REDACTED:query.secret>
access_token=<REDACTED:form.token>
```

Expected output:

```text
access_token=<REDACTED:form.value>
access_token=<REDACTED:form.value>
access_token=<REDACTED:form.value>
access_token=<REDACTED:form.value>
```

### Overlap Behavior And Ordering

After Milestone 11, the final sanitizer ordering is:

1. Authorization findings.
2. Proxy-Authorization findings.
3. Cookie findings.
4. Sensitive-header findings.
5. Form-urlencoded findings.
6. Query findings.
7. JSON findings.

Rationale:

- Authorization, Proxy-Authorization, Cookie, and sensitive headers are broader line/header findings and remain authoritative.
- Form-urlencoded body values are broader than nested query or JSON-like content inside the same form value.
- Query and JSON may still run inside non-sensitive form fields when no form finding overlaps.

Examples:

```http
GET /api?access_token=abc HTTP/1.1
```

This produces only `query.secret`, not `form.value`, because M10 is Content-Type-gated and query scanning remains responsible for URL query parameters.

```http
Content-Type: application/x-www-form-urlencoded

redirect_uri=https://callback.example.test/cb?access_token=synthetic-token&client_secret=synthetic-client-secret
```

Form does not redact `redirect_uri` because it is deferred. Query may redact nested `access_token` and `client_secret` if current query rules support those raw query names and no form finding overlaps.

```http
Content-Type: application/x-www-form-urlencoded

access_token=https://api.example.test/cb?token=synthetic-token
```

`form.value` redacts the whole `access_token` value, and query or JSON findings inside that value are skipped due to overlap.

```http
Authorization: Bearer access_token=abc
X-API-Key: access_token=abc
```

Authorization and sensitive-header rules remain authoritative where they match.

After Milestone 11, `Proxy-Authorization` is also authoritative where it matches:

```http
Proxy-Authorization: Basic access_token=abc
```

This produces only a proxy authorization finding, not `form.value`, `query.secret`, or `json.value` for nested form-like text inside the proxy credential.

```json
{"body":"access_token=abc&client_secret=secret"}
```

No `form.value` applies unless there is a supported Content-Type-gated form body line. JSON behavior remains governed by `json.value` only for approved JSON field names.

### Reporting Semantics

- `form.value` counts one finding per approved form field value actually replaced.
- Already-redacted exact form marker values produce no count.
- Deferred or non-approved field names produce no count.
- Bare no-value fields produce no count.
- Unsupported bodies produce no count.
- Form findings skipped because they overlap existing findings produce no count.
- Reports contain only fixed rule ID `form.value` and counts.
- Reports never contain raw form values, form field names, body snippets, or replacement previews.

### Milestone 10 Acceptance Criteria

- Existing Authorization behavior remains unchanged.
- Existing Cookie behavior remains unchanged.
- Existing selected sensitive-header behavior remains unchanged.
- Existing selected sensitive-query-parameter behavior remains unchanged.
- Existing selected sensitive JSON-like field behavior remains unchanged.
- `form.value` rule and `<REDACTED:form.value>` marker are the only form report identifiers and markers.
- Form scanning is Content-Type-gated to `application/x-www-form-urlencoded`.
- Optional media-type parameters after the media type are supported.
- Only the immediate first physical line after the blank header/body separator is scanned.
- Approved field names redact only raw values after `=`.
- Deferred and near-miss field names remain unchanged.
- Matching is exact and ASCII-lowercase based.
- No percent-decoding or plus-decoding is performed.
- No substring, prefix, or suffix matching is approved.
- Explicit empty values redact with `<REDACTED:form.value>` and count once.
- Bare no-value fields remain unchanged and produce no count.
- Additional `=` characters are preserved as part of the value.
- `&` is the only supported separator.
- Semicolon form separation is deferred.
- Exact `<REDACTED:form.value>` values are idempotent.
- Embedded `<REDACTED:form.value>` values are redacted.
- Unapproved form marker-like values are redacted.
- Wrong-family markers are redacted.
- Form findings overlapping Authorization, Proxy-Authorization, Cookie, or `header.secret` findings are skipped after Milestone 11.
- Query and JSON findings overlapping proxy or form findings are skipped after Milestone 11.
- Query/JSON may still run in non-sensitive form fields when no form finding overlaps.
- Reports use only fixed rule ID `form.value`.
- Reports contain no raw values, form field names, snippets, or replacement previews.
- No new dependency, configuration file, module, plugin, registry, network behavior, telemetry collection, LLM behavior, persistence, full HTTP parsing, directory processing, overwrite mode, or exit code is introduced.
- Existing source immutability, output collision, dry-run, UTF-8, UTF-8 BOM, LF, CRLF, mixed-newline, final-newline, 10 MiB, NUL-byte, safe-error, and exit-code behavior remains unchanged.
- Tests use only synthetic data.

## Milestone 11 Proxy-Authorization Sanitization

Milestone 11 adds deterministic sanitization for exact line-start HTTP request `Proxy-Authorization` header credentials. It preserves all existing Authorization, Cookie, selected sensitive-header, selected sensitive-query-parameter, selected JSON-like field, selected form-urlencoded field, file-processing, safety, encoding, newline, reporting, CLI, and exit-code behavior.

Milestone 11 covers only this HTTP request header:

```text
Proxy-Authorization
```

Milestone 11 must not add broader additional header coverage, generic header matching, substring matching, full HTTP parsing, runtime configuration, plugins, external dependencies, CLI options, output formats, or network behavior.

Milestone 11 uses dedicated proxy-specific rule IDs and markers. It must not reuse `authorization.*` rule IDs for `Proxy-Authorization`, because reports should distinguish application/API Authorization credentials from proxy credentials.

| Rule ID | Marker | Applies to |
| --- | --- | --- |
| `proxy_authorization.bearer` | `<REDACTED:proxy_authorization.bearer>` | `Bearer` proxy credentials |
| `proxy_authorization.basic` | `<REDACTED:proxy_authorization.basic>` | `Basic` proxy credentials |
| `proxy_authorization.other` | `<REDACTED:proxy_authorization.credentials>` | Other syntactically valid proxy auth schemes |

### M11 Matching Behavior

Milestone 11 supports `Proxy-Authorization` header lines that begin exactly at the start of a decoded physical line. Matching is case-insensitive for the header name. Indented or folded forms remain unsupported and unchanged.

The finder must preserve:

- Header-name casing.
- Spaces and tabs around `:`.
- Scheme casing.
- Spaces and tabs before credentials.
- Trailing spaces and tabs.
- LF, CRLF, and mixed line endings.
- UTF-8 BOM and final-newline state through existing file handling.

The proxy auth scheme must use the same ASCII HTTP token character set as Authorization:

```text
!#$%&'*+-.^_`|~0-9A-Za-z
```

Unicode scheme names and malformed schemes are unsupported and remain unchanged.

`Bearer` requirements:

- Match the `Bearer` scheme case-insensitively.
- Require exactly one contiguous non-whitespace credential value.
- Replace only the credential with `<REDACTED:proxy_authorization.bearer>`.
- Leave empty, whitespace-only, or internally spaced Bearer credentials unchanged.
- Never fall through to `proxy_authorization.other` when Bearer-specific validation fails.

`Basic` requirements:

- Match the `Basic` scheme case-insensitively.
- Require exactly one contiguous non-whitespace credential value.
- Do not Base64-decode or validate the credential.
- Replace only the credential with `<REDACTED:proxy_authorization.basic>`.
- Leave empty, whitespace-only, or internally spaced Basic credentials unchanged.
- Never fall through to `proxy_authorization.other` when Basic-specific validation fails.

Generic proxy fallback requirements:

- Apply only to syntactically valid schemes other than Bearer and Basic.
- Preserve header name, spacing around `:`, scheme casing, and spacing between scheme and credentials.
- Replace the complete non-empty credential section after the scheme with `<REDACTED:proxy_authorization.credentials>`.
- Allow internal spaces, commas, quotes, equals signs, colons, slashes, and other punctuation.
- Do not parse individual Digest, Negotiate, NTLM, OAuth, Signature, or custom parameters.
- Leave empty or scheme-only headers unchanged.
- Never include custom proxy scheme names in report rule IDs.

Folded `Proxy-Authorization` headers are unsupported. If an exact `Proxy-Authorization:` line is immediately followed by a physical line beginning with a space or tab, leave the complete folded form unchanged, emit no proxy finding, and do not sanitize only the first physical line. Full folded-header parsing remains deferred.

Unsupported or unchanged examples include:

```http
Proxy-Authorization:
Proxy-Authorization: [spaces only]
Proxy-Authorization: Bearer
Proxy-Authorization: Bearer one two
Proxy-Authorization: Basic first second
Proxy-Authorization: Münch token
 Proxy-Authorization: Basic token
Proxy-Authorization: Basic token
 continued
Proxy-Authenticate: Basic realm="proxy"
WWW-Authenticate: Basic realm="origin"
X-Proxy-Authorization: Basic token
The Proxy-Authorization header was present.
```

### M11 Explicit Non-Goals And Deferred Behavior

The following remain out of scope for Milestone 11:

- `Proxy-Authenticate`.
- `WWW-Authenticate`.
- `X-Proxy-Authorization`.
- `Forwarded`.
- `X-Forwarded-*`.
- `X-Original-*`.
- `Via`.
- `X-API-Key` variants beyond existing `header.secret` behavior.
- Additional signature headers.
- Full HTTP parsing.
- Folded-header parsing.
- Value decoding.
- Recursive parsing.
- Configuration files, runtime configuration, or plugins.

### M11 Marker And Idempotence Policy

Approved proxy markers are:

```text
<REDACTED:proxy_authorization.bearer>
<REDACTED:proxy_authorization.basic>
<REDACTED:proxy_authorization.credentials>
```

Policy:

- An exact complete proxy credential section equal to any approved proxy marker is already sanitized and produces no finding.
- Proxy markers are accepted under the wrong proxy auth scheme without normalization.
- The sanitizer must not correct or normalize a proxy marker used under another proxy scheme.
- An embedded approved proxy marker inside a larger raw proxy credential is treated as raw and redacted.
- Existing non-proxy markers inside `Proxy-Authorization` are treated as raw and re-redacted to the appropriate proxy marker, including Authorization markers, `<REDACTED:header.secret>`, `<REDACTED:query.secret>`, `<REDACTED:json.value>`, `<REDACTED:form.value>`, and Cookie markers.
- Re-redacting non-proxy markers is intentional to preserve precise report semantics for proxy credentials.
- Repeated sanitization must produce byte-identical output.

### M11 Ordering And Overlap Behavior

The final sanitizer ordering is:

1. Authorization findings.
2. Proxy-Authorization findings.
3. Cookie findings.
4. Sensitive-header findings.
5. Form-urlencoded findings.
6. Query findings.
7. JSON findings.

Proxy findings participate in overlap checks for later form, query, and JSON rules. Nested URLs, JSON-like strings, or form-like content inside proxy credentials must not create secondary `form.value`, `query.secret`, or `json.value` findings.

Example:

```http
Proxy-Authorization: Digest token=https://proxy.example.test/?access_token=synthetic-token
```

This reports only `proxy_authorization.other`. Normal URL query strings outside proxy credentials still use `query.secret` when they match existing query rules.

### M11 Reporting Semantics

- `proxy_authorization.bearer`, `proxy_authorization.basic`, and `proxy_authorization.other` count one finding per proxy credential section actually replaced.
- Empty, whitespace-only, unsupported, folded, malformed, or already-redacted proxy credentials produce no count.
- Findings store only fixed rule ID, offsets, and replacement.
- Reports contain only fixed proxy rule IDs and counts.
- Reports, CLI output, exceptions, logs, tests, and snapshots must not include raw proxy credential values, proxy credential snippets, source excerpts, dynamic header names, or custom proxy scheme names as report IDs.

### M11 Acceptance Criteria

- Existing Authorization behavior remains unchanged.
- Existing Cookie behavior remains unchanged.
- Existing selected sensitive-header behavior remains unchanged, and the sensitive-header finder still does not match `proxy-authorization`.
- Existing selected sensitive-query-parameter behavior remains unchanged outside overlapping proxy credentials.
- Existing selected JSON-like field behavior remains unchanged outside overlapping proxy credentials.
- Existing selected form-urlencoded field behavior remains unchanged outside overlapping proxy credentials.
- Exact line-start `Proxy-Authorization` headers are matched case-insensitively.
- Header-name casing, spaces and tabs around `:`, scheme casing, spaces and tabs before credentials, trailing spaces and tabs, line endings, UTF-8 BOM state, and final-newline state are preserved.
- Bearer proxy credentials redact only one contiguous non-whitespace credential with `proxy_authorization.bearer` and `<REDACTED:proxy_authorization.bearer>`.
- Basic proxy credentials redact only one contiguous non-whitespace credential with `proxy_authorization.basic` and `<REDACTED:proxy_authorization.basic>`.
- Other valid proxy schemes such as Digest, Negotiate, NTLM, and custom valid auth-schemes redact the complete non-empty credential section with `proxy_authorization.other` and `<REDACTED:proxy_authorization.credentials>`.
- Invalid Bearer and Basic values remain unchanged and do not fall through to `proxy_authorization.other`.
- Empty, whitespace-only, malformed, Unicode-scheme, indented, and folded forms remain unchanged.
- Folded `Proxy-Authorization` forms produce no finding.
- `Proxy-Authenticate`, `WWW-Authenticate`, `X-Proxy-Authorization`, and prose remain unchanged.
- Exact approved proxy markers are idempotent.
- Wrong proxy markers under another proxy scheme are accepted without normalization.
- Embedded proxy markers are redacted.
- Wrong-family non-proxy markers inside `Proxy-Authorization` are re-redacted to the appropriate proxy marker.
- Proxy findings suppress nested form, query, and JSON findings inside proxy credential spans.
- Normal URL query strings outside proxy credentials still use `query.secret`.
- Reports contain only fixed proxy rule IDs and counts.
- Reports, CLI output, exceptions, logs, tests, and snapshots do not include raw proxy credential values, proxy credential snippets, source excerpts, dynamic header names, or custom proxy scheme names as report IDs.
- Findings do not store raw proxy credentials or custom proxy scheme names.
- No broader additional header coverage, generic header matching, substring matching, full HTTP parsing, folded-header parsing, value decoding, recursive parsing, runtime configuration, plugins, external dependencies, CLI options, output formats, network behavior, overwrite mode, or exit code is introduced.
- Existing source immutability, output collision, dry-run, UTF-8, UTF-8 BOM, LF, CRLF, mixed-newline, final-newline, 10 MiB, NUL-byte, safe-error, and exit-code behavior remains unchanged.
- Tests use only synthetic data.

## CLI Behavior

Recommended command shape:

```bash
evidence-sanitizer sanitize INPUT --output OUTPUT
evidence-sanitizer sanitize INPUT --output OUTPUT --dry-run
```

Successful sanitization:

```text
Sanitized: evidence.txt -> evidence.sanitized.txt
Rules triggered:
authorization.bearer: 1
```

Dry run:

```text
Dry run: no output written
Rules triggered:
authorization.bearer: 1
```

Milestone 2 example with multiple Authorization scheme types:

```text
Sanitized: evidence.txt -> evidence.sanitized.txt
Rules triggered:
authorization.basic: 1
authorization.bearer: 1
authorization.other: 1
```

Milestone 3 example with Authorization and Cookie findings:

```text
Sanitized: evidence.txt -> evidence.sanitized.txt
Rules triggered:
authorization.basic: 1
authorization.bearer: 1
authorization.other: 1
cookie.header: 1
cookie.value: 4
```

Milestone 4 example with one harmless Cookie value preserved:

```text
Sanitized: evidence.txt -> evidence.sanitized.txt
Rules triggered:
cookie.value: 5
```

Milestone 5 example with selected sensitive headers:

```text
Sanitized: evidence.txt -> evidence.sanitized.txt
Rules triggered:
authorization.bearer: 1
cookie.value: 1
header.secret: 2
```

Milestone 6 example with selected sensitive query parameters:

```text
Sanitized: evidence.txt -> evidence.sanitized.txt
Rules triggered:
authorization.bearer: 1
cookie.value: 1
header.secret: 1
query.secret: 2
```

Milestone 11 example with Proxy-Authorization credentials:

```text
Sanitized: evidence.txt -> evidence.sanitized.txt
Rules triggered:
authorization.bearer: 1
proxy_authorization.basic: 1
proxy_authorization.other: 1
query.secret: 1
```

No findings:

```text
Sanitized: evidence.txt -> evidence.sanitized.txt
Rules triggered: none
```

Output collision:

```text
Error: output file already exists
```

Same source and destination:

```text
Error: output path must not resolve to the input file
```

Normal CLI output may show the user-provided paths exactly as supplied. It must not convert paths to absolute resolved paths for display unless a later decision explicitly changes this.

## Exit Codes

- `0`: Success, including success with findings and success with no findings.
- `1`: Unexpected internal error or internal sanitization error. The displayed message must be safe and must not include evidence contents.
- `2`: CLI usage error handled by Typer.
- `3`: Unsafe path, output collision, missing output parent directory, or source/destination conflict.
- `4`: Input read error, input too large, NUL byte rejection, unsupported input type, or UTF-8 decoding failure.
- `5`: Output write failure.

## Supported Input Assumptions

- The user is authorized to process the evidence.
- The input is a local text file, not a directory or remote resource.
- The input is at most 10 MiB.
- The input is strict UTF-8, optionally with a UTF-8 BOM.
- The input does not contain NUL bytes.
- The input may contain LF, CRLF, or mixed newline sequences, which must be preserved exactly.
- The input may omit or include a final newline; that state must be preserved.

## Known Limitations

- The tool does not guarantee that every secret is removed.
- The tool only detects supported patterns.
- Milestone 1 detects only HTTP-style `Authorization: Bearer` header values.
- Milestone 2 detects HTTP-style `Authorization` header credentials for Bearer, Basic, and syntactically valid other schemes only.
- Milestone 2 does not parse Cookie, Set-Cookie, API-key-specific headers, email addresses, or client identifiers.
- Milestone 3 detects exact line-start HTTP request `Cookie` headers only.
- Milestone 3 does not sanitize `Set-Cookie`, classify cookie names, preserve selected cookie values, or use telemetry allowlists.
- Milestone 4 classifies safely parsed Cookie names only with fixed built-in rules and preserves values only for exact harmless names `theme`, `color_scheme`, and `display_mode`.
- Milestone 4 redacts known telemetry values because they may be persistent identifiers, and redacts unknown Cookie values by default.
- Milestone 5 detects only exact line-start selected sensitive API/authentication-related header names from the approved list and redacts only whole non-empty trimmed values.
- Milestone 5 does not use substring header matching, value parsing, value decoding, value classification, grouped rule IDs, per-header rule IDs, or dynamic report IDs.
- Milestone 5 leaves indented and folded sensitive-header forms unchanged, which may leave sensitive values intact.
- Milestone 5 does not sanitize non-approved secret headers, `Proxy-Authorization`, `Set-Cookie`, query parameters, URLs, JSON bodies, XML bodies, form bodies, or multipart bodies.
- Milestone 6 detects only approved exact raw URL query parameter names from the approved list and redacts only raw values after `=`.
- Milestone 6 does not use substring parameter matching, URL decoding, URL re-encoding, value parsing, value classification, grouped rule IDs, per-parameter rule IDs, or dynamic report IDs.
- Milestone 6 does not decode percent-encoded parameter names, so names such as `access%5Ftoken` remain unsupported and may retain sensitive values.
- Milestone 6 does not recursively parse URL-valued query parameters and may miss nested sensitive query values.
- Milestone 6 may sanitize exact URL-like text inside bodies or logs because full HTTP parsing remains deferred.
- Full HTTP header/body boundary parsing is deferred; exact header-like `Authorization`, `Cookie`, and selected sensitive-header lines inside bodies may be sanitized.
- Folded or indented Authorization header lines remain unsupported.
- Folded, continued, or indented Cookie header lines remain unsupported and unchanged, which may leave sensitive cookie values intact.
- Unicode auth-scheme names and malformed schemes remain unsupported.
- Non-ASCII or malformed cookie names trigger whole-header fallback instead of name preservation.
- Basic credentials are not decoded or validated.
- Generic structured credentials are redacted as one whole credential section.
- Milestone 6 does not sanitize deferred query parameter names, JSON bodies, XML bodies, form bodies as structured form data, multipart bodies, HTML, JavaScript, or nested URLs inside query values.
- Milestone 10 detects only approved sensitive field names in `application/x-www-form-urlencoded` bodies that follow a supported `Content-Type` line and a blank header/body separator.
- Milestone 10 scans only the immediate first physical line after the separator and does not support multi-line or wrapped form bodies.
- Milestone 10 does not scan raw form-urlencoded strings without a supported Content-Type line.
- Milestone 10 does not decode percent-encoded or plus-encoded names or values.
- Milestone 10 supports only `&` as a form field separator; semicolon-separated form fields are deferred.
- Deferred form field names such as `code`, `state`, `nonce`, `secret`, `key`, `username`, `email`, `otp`, and `mfa_code` may retain secrets.
- Broad approved exact form names such as `token`, `session`, `sig`, and `signature` may produce false positives.
- Milestone 11 detects only exact line-start `Proxy-Authorization` header credentials for Bearer, Basic, and syntactically valid other schemes.
- Milestone 11 does not sanitize `Proxy-Authenticate`, `WWW-Authenticate`, `X-Proxy-Authorization`, `Forwarded`, `X-Forwarded-*`, `X-Original-*`, `Via`, additional signature headers, or `X-API-Key` variants beyond existing `header.secret` behavior.
- Folded or indented `Proxy-Authorization` header lines remain unsupported and unchanged, which may leave proxy credentials intact.
- Unicode proxy auth-scheme names and malformed proxy schemes remain unsupported.
- Basic proxy credentials are not decoded or validated.
- Generic structured proxy credentials are redacted as one whole credential section.
- Replacement marker collisions are accepted and handled deterministically.
- Binary detection is intentionally limited and cannot reliably identify every binary file.
- Output creation is exclusive, but atomic replacement is not guaranteed in milestone 1.
- Abrupt process termination may leave a partial output file.
- The tool does not preserve source file metadata.
- Directory processing is deferred, so partial-success behavior for multiple files is not yet defined.
- Comprehensive adversarial filesystem handling is deferred.

## Acceptance Criteria

MVP acceptance criteria:

- A single supported text file can be sanitized into a distinct output file.
- The source file is not modified.
- Existing output paths are rejected.
- Source and output paths resolving to the same file are rejected.
- Dry-run mode creates no output file.
- Rule identifiers and counts are reported without detected values.
- Detected findings return exit code `0`.
- Input larger than 10 MiB is rejected.
- NUL bytes and UTF-8 decoding failures are rejected.
- UTF-8 BOM presence, newline sequences, and final-newline state are preserved.
- No network, telemetry, plugin, or LLM behavior exists.
- Tests use only synthetic data.

Milestone 2 acceptance criteria:

- Existing Bearer behavior remains unchanged, including marker, rule ID, spacing preservation, token-only credential matching, and idempotence.
- Basic Authorization credentials are sanitized with rule ID `authorization.basic` and marker `<REDACTED:authorization.basic>`.
- Basic credentials are not decoded or validated.
- Bearer and Basic lines with empty, whitespace-only, or internally spaced credentials remain unchanged and do not fall through to the generic rule.
- Unknown, custom, and structured Authorization schemes using the approved ASCII token grammar are sanitized with rule ID `authorization.other` and marker `<REDACTED:authorization.credentials>`.
- Generic structured credentials may contain internal spaces and punctuation and are redacted as one whole credential section.
- Any complete credential section that exactly equals an approved marker is unchanged and does not increment counts, even when the marker appears under a different scheme.
- Reports contain only `authorization.bearer`, `authorization.basic`, and `authorization.other` rule IDs and counts.
- Reports never contain credential values, source excerpts, or custom scheme names.
- One Authorization line produces at most one finding.
- Cookie, Set-Cookie, API-key-specific headers, email redaction, and client-identifier redaction are not implemented.
- Existing file safety, dry-run, UTF-8, BOM, newline, size-limit, NUL-byte, safe-error, and exit-code behavior remains unchanged.

Milestone 3 acceptance criteria:

- Existing Authorization behavior remains unchanged and all existing Authorization regression tests remain valid.
- Exact line-start `Cookie` headers are matched case-insensitively.
- Spaces and tabs between `Cookie` and `:`, spaces and tabs after `:`, header-name casing, trailing spaces and tabs, LF, CRLF, mixed newline sequences, UTF-8 BOM state, and final-newline state are preserved.
- `Set-Cookie`, `X-Cookie`, indented Cookie lines, folded continuation lines, and prose containing the word `Cookie` remain unchanged.
- Exact header-like `Cookie:` lines inside bodies may be sanitized because full HTTP body-boundary parsing remains deferred.
- Safely parsed Cookie headers preserve cookie names, pair order, duplicate names, and delimiter formatting while replacing every individual value with `<REDACTED:cookie.value>`.
- Empty Cookie headers and whitespace-only Cookie headers remain unchanged and produce no counts.
- Explicit empty cookie values are redacted with `<REDACTED:cookie.value>`.
- Unquoted values containing additional `=`, commas, colons, slashes, printable punctuation other than semicolons, or non-ASCII text are redacted.
- Quoted values, semicolons inside quoted values, and valid escaped characters inside quoted values are supported; only the quoted payload is replaced.
- Missing `=`, empty names, leading semicolons, trailing semicolons, consecutive semicolons, malformed mixed segments, malformed quoted syntax, missing closing quotes, dangling escapes, non-ASCII cookie names, unsupported control characters, and junk after closing quotes trigger whole-header fallback.
- Whole-header fallback replaces the complete trimmed header value with `<REDACTED:cookie.header>` and produces no `cookie.value` counts.
- No malformed Cookie header is partially sanitized.
- Approved Cookie markers are idempotent as individual values and as complete trimmed header values.
- Embedded Cookie markers inside larger raw values are redacted.
- Rule counts use only `cookie.value` and `cookie.header` for Cookie findings.
- `cookie.value` counts each individual cookie value actually replaced, and `cookie.header` counts each Cookie header line changed through fallback.
- Cookie names never become rule IDs and are not included in reports as dynamic identifiers.
- Reports, CLI output, exceptions, logs, tests, and snapshots do not include cookie values or source excerpts.
- Cookie-name classification, sensitive/telemetry/harmless/unknown categories, telemetry allowlists, selective value preservation, and `Set-Cookie` sanitization are not implemented.
- No new dependency, configuration file, plugin, network behavior, telemetry, LLM behavior, persistence, full HTTP parsing, folded-header parsing, directory processing, overwrite mode, or exit code is introduced.
- Existing file safety, dry-run, UTF-8, BOM, newline, size-limit, NUL-byte, safe-error, and exit-code behavior remains unchanged.

Milestone 4 acceptance criteria:

- Existing Authorization behavior remains unchanged and all existing Authorization regression tests remain valid.
- Existing Cookie parser, complete-parse-before-findings behavior, whole-header fallback, folded-header handling, `Set-Cookie` non-match, formatting preservation, marker policy, report behavior, and file safety behavior remain valid except for approved harmless value preservation.
- Cookie-name classification depends only on names and never on values.
- Classification is case-insensitive, uses only ASCII lowercase for matching, preserves original Cookie-name casing in output, treats `_`, `-`, and `.` as distinct, performs no Unicode normalization, uses no suffix matching, and uses no broad substring matching.
- Sensitive precedence overrides telemetry, harmless, and unknown.
- Approved sensitive exact names and approved sensitive families redact values with `<REDACTED:cookie.value>`.
- Sensitive substring near misses such as `superuser_setting`, `sessionStorageEnabled`, `consider`, `tokenizer_mode`, and `author_theme` remain unknown and redacted.
- Approved telemetry exact names and approved telemetry prefix families redact values with `<REDACTED:cookie.value>`.
- Unknown Cookie values remain redacted with `<REDACTED:cookie.value>`.
- Only exact harmless names `theme`, `color_scheme`, and `display_mode` preserve values.
- Harmless matching is exact and case-insensitive, and harmless near misses such as `user_theme`, `theme_token`, `display_mode_session`, and `color_scheme_auth` remain redacted.
- `language`, `lang`, `locale`, `timezone`, `tz`, `cookie_consent`, `consent`, `banner_dismissed`, and `sidebar_state` remain unknown and redacted.
- Existing `cookie.value` and `cookie.header` rule IDs and markers remain the only Cookie report IDs and markers.
- No category-specific marker or report ID is introduced.
- Preserved harmless values produce no finding and no count.
- Existing `<REDACTED:cookie.value>` and `<REDACTED:cookie.header>` markers remain idempotent.
- Category-specific raw marker-like values such as `<REDACTED:cookie.sensitive>` and `<REDACTED:cookie.unknown>` are not approved markers and are redacted as ordinary values unless fallback applies.
- Reports, CLI output, exceptions, logs, tests, and snapshots do not include redacted Cookie values or source excerpts.
- Cookie names never become report IDs and are not included in reports as dynamic identifiers.
- No new dependency, configuration file, runtime-editable list, plugin, registry, policy engine, network behavior, telemetry collection, LLM behavior, persistence, full HTTP parsing, folded-header parsing, directory processing, overwrite mode, or exit code is introduced.
- Existing source immutability, output collision, dry-run, UTF-8, UTF-8 BOM, LF, CRLF, mixed-newline, final-newline, 10 MiB, NUL-byte, safe-error, and exit-code behavior remains unchanged.

Milestone 5 acceptance criteria:

- Existing Authorization behavior remains unchanged, including Bearer, Basic, generic schemes, markers, counts, and idempotence.
- Existing Cookie behavior remains unchanged, including parser, fallback, harmless preservation, marker policy, counts, folded Cookie behavior, and `Set-Cookie` scope.
- Every approved sensitive header name redacts when it appears as an exact decoded line-start physical header with a non-empty value.
- Header-name matching is exact and case-insensitive.
- No substring header matching is approved.
- Near-miss header names such as `monkey`, `keyboard`, `x-tokenizer-mode`, `x-author-theme`, `x-api-key-name`, `x-access-token-expires`, and `x-csrf-token-enabled` remain unchanged.
- Indented sensitive-header lines remain unchanged.
- Folded sensitive-header forms remain completely unchanged and produce no count.
- Empty and whitespace-only sensitive-header values remain unchanged and produce no count.
- Non-empty sensitive-header values are replaced with `<REDACTED:header.secret>`.
- Header name casing, spaces and tabs around `:`, leading spaces and tabs after `:`, trailing spaces and tabs after the value, line endings, UTF-8 BOM state, and final-newline state are preserved.
- Quoted, structured, and comma-separated values are redacted as whole trimmed values without parsing.
- Exact `<REDACTED:header.secret>` values are idempotent.
- Embedded `<REDACTED:header.secret>` values are redacted.
- Unapproved marker-like values such as `<REDACTED:header.api_key>` are redacted.
- Wrong-family Authorization and Cookie markers inside sensitive headers are redacted.
- Reports contain only fixed rule ID `header.secret` and counts for sensitive-header findings.
- Header names never become report IDs and are not included in reports as dynamic identifiers.
- Reports, CLI output, exceptions, logs, tests, and snapshots do not include redacted sensitive-header values or source excerpts.
- `authorization`, `cookie`, `set-cookie`, and `proxy-authorization` are not matched by the sensitive-header finder.
- No new dependency, configuration file, runtime-editable allowlist, plugin, registry, network behavior, telemetry collection, LLM behavior, persistence, full HTTP parsing, folded-header parsing, directory processing, overwrite mode, or exit code is introduced.
- Existing source immutability, output collision, dry-run, UTF-8, UTF-8 BOM, LF, CRLF, mixed-newline, final-newline, 10 MiB, NUL-byte, safe-error, and exit-code behavior remains unchanged.

Milestone 6 acceptance criteria:

- Existing Authorization behavior remains unchanged, including Bearer, Basic, generic schemes, markers, counts, and idempotence.
- Existing Cookie behavior remains unchanged, including parser, fallback, harmless preservation, marker policy, counts, folded Cookie behavior, and `Set-Cookie` scope.
- Existing selected sensitive-header behavior remains unchanged, including approved names, marker policy, counts, folded-header behavior, and `header.secret` overlap authority.
- Every approved query parameter name redacts when it appears as an exact raw query parameter name with `=`.
- `sig` and `signature` redact.
- Parameter-name matching is exact, raw, and case-insensitive.
- No substring parameter matching is approved.
- Deferred names such as `code`, `state`, `nonce`, `key`, `secret`, `sign`, `signed`, `se`, `sp`, `sv`, `sr`, and `st` remain unchanged.
- Percent-encoded names are not decoded; `access%5Ftoken` remains unchanged.
- `&` and `;` separate parameters.
- `#` ends the current query segment.
- Whitespace, quotes, apostrophes, backticks, and angle delimiters bound query tokens.
- Repeated parameters are supported.
- Multiple query tokens per line are supported.
- Explicit empty values such as `?token=` are redacted with `<REDACTED:query.secret>` and counted once.
- Bare no-value parameters such as `?token` remain unchanged and produce no count.
- Exact `<REDACTED:query.secret>` values are idempotent.
- Embedded `<REDACTED:query.secret>` values are redacted.
- Wrong-family markers such as `<REDACTED:header.secret>`, `<REDACTED:cookie.value>`, and `<REDACTED:authorization.bearer>` are redacted in approved query parameter values.
- Query findings overlapping Authorization, Proxy-Authorization, Cookie, or `header.secret` findings are skipped and produce no `query.secret` count after Milestone 11.
- Preserved harmless Cookie values may receive query redaction when no Cookie finding overlaps.
- Reports contain only fixed rule ID `query.secret` and counts for query findings.
- Query parameter names never become report IDs and are not included in reports as dynamic identifiers.
- Reports, CLI output, exceptions, logs, tests, and snapshots do not include redacted query values or source excerpts.
- No URL decoding, URL re-encoding, recursive URL parsing, JSON parsing, XML parsing, form-body parsing, multipart parsing, HTML parsing, JavaScript parsing, full HTTP parsing, directory processing, configuration file, runtime-editable allowlist, plugin, registry, network behavior, telemetry collection, LLM behavior, persistence, dependency, module, overwrite mode, or exit code is introduced.
- Existing source immutability, output collision, dry-run, UTF-8, UTF-8 BOM, LF, CRLF, mixed-newline, final-newline, 10 MiB, NUL-byte, safe-error, and exit-code behavior remains unchanged.

Milestone 11 acceptance criteria:

- Exact line-start `Proxy-Authorization` headers redact supported Bearer, Basic, and valid other proxy auth schemes with dedicated `proxy_authorization.*` rule IDs and markers.
- `authorization.*` rule IDs and markers are not reused for `Proxy-Authorization`.
- Header-name casing, spaces and tabs around `:`, scheme casing, spaces and tabs before credentials, trailing spaces and tabs, LF, CRLF, UTF-8 BOM state, and final-newline state are preserved.
- Bearer and Basic proxy credentials redact only one contiguous non-whitespace credential and do not fall through to `proxy_authorization.other` when invalid.
- Other valid proxy schemes redact the complete non-empty credential section after the scheme.
- Empty, whitespace-only, malformed, Unicode-scheme, indented, and folded `Proxy-Authorization` forms remain unchanged.
- `Proxy-Authenticate`, `WWW-Authenticate`, `X-Proxy-Authorization`, and prose remain unchanged.
- Exact approved proxy markers are idempotent, including when used under another proxy scheme without normalization.
- Embedded proxy markers are redacted.
- Non-proxy markers inside `Proxy-Authorization` are treated as raw and re-redacted to the appropriate proxy marker.
- Proxy findings run after Authorization and before Cookie, `header.secret`, `form.value`, `query.secret`, and `json.value` findings.
- Proxy findings participate in overlap checks for later form, query, and JSON rules, so nested form-like, query-like, or JSON-like content inside proxy credentials creates no secondary findings.
- Normal URL query strings outside proxy credentials still use `query.secret`.
- Reports contain only fixed proxy rule IDs and counts, never raw proxy credential values, snippets, dynamic header names, or custom proxy scheme names as report IDs.
- Findings do not store raw proxy credentials or custom proxy scheme names.
- No broader additional header coverage, generic header matching, substring matching, full HTTP parsing, folded-header parsing, value decoding, recursive parsing, runtime configuration, plugin system, dependency, CLI option, output format, network behavior, overwrite mode, or exit code is introduced.
- Existing Authorization, Proxy-Authorization, Cookie, selected sensitive-header, query, JSON-like, form-urlencoded, source immutability, output collision, dry-run, UTF-8, UTF-8 BOM, LF, CRLF, mixed-newline, final-newline, 10 MiB, NUL-byte, safe-error, and exit-code behavior remains unchanged.
