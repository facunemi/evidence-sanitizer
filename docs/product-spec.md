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
- API-key-specific headers, email redaction, or client-identifier redaction in milestone 2.
- Full HTTP header/body parsing or folded-header parsing in milestone 2 and milestone 3.
- Database storage.
- Web application features.
- Debug mode.
- Comprehensive defense against adversarial filesystem races, junction attacks, or hard-link attacks in milestone 1.

## User Stories

- As a tester, I can sanitize `request.txt` into `request.sanitized.txt` while leaving `request.txt` unchanged.
- As a tester, I can run dry-run mode and see that `authorization.bearer` matched once without seeing the token.
- As a tester, I can sanitize Basic and custom Authorization credentials without exposing them in output.
- As a tester, I can sanitize request Cookie values while preserving safely parsed cookie names for evidence context.
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
- Full HTTP header/body boundary parsing is deferred; exact header-like `Authorization` and `Cookie` lines inside bodies may be sanitized.
- Folded or indented Authorization header lines remain unsupported.
- Folded, continued, or indented Cookie header lines remain unsupported and unchanged, which may leave sensitive cookie values intact.
- Unicode auth-scheme names and malformed schemes remain unsupported.
- Non-ASCII or malformed cookie names trigger whole-header fallback instead of name preservation.
- Basic credentials are not decoded or validated.
- Generic structured credentials are redacted as one whole credential section.
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
