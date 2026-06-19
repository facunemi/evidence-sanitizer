# Security Model

## Protected Assets

- Original evidence files.
- Detected sensitive values, including Bearer tokens, Basic credentials, custom or structured Authorization credentials, Cookie values, selected sensitive API/authentication-related header values, selected sensitive URL query parameter values, selected sensitive JSON-like string field values, and future supported secret types.
- Sanitized output integrity.
- User trust that reported findings do not leak secret contents.
- Local filesystem state at source and destination paths.

## Trust Boundaries

- The CLI receives untrusted file contents from a user-selected local path.
- The CLI receives user-provided paths through command-line arguments.
- The local filesystem may contain symbolic links or race-prone paths.
- The terminal receives only sanitized status output.
- No network boundary exists because the tool must not send evidence over the network.

## Threats

- Accidental modification of original evidence.
- Accidental overwrite of an existing output file.
- Secret leakage through logs, reports, exceptions, tracebacks, tests, or debug output.
- False negatives that leave unsupported or malformed secrets intact.
- False positives that reduce evidence usefulness.
- Regex patterns that are slow on adversarial input.
- Partial output after an interrupted or failed write.
- User confusion about the scope of supported sanitization.
- Filesystem races or link behavior causing validation results to become stale.

## Security Invariants

- The source file is opened for reading only and must never be written by the tool.
- The output path must not exist before writing.
- Existing output files must never be overwritten.
- Dry-run mode must not create output or temporary files.
- Detected values must never appear in terminal output, reports, exceptions, tracebacks, test snapshots, or logs.
- Findings and reports must not store matched secret values.
- Reports for generic Authorization schemes must not include custom scheme names as rule identifiers.
- Reports for Cookie findings must use only fixed rule identifiers and must not derive rule identifiers from cookie names.
- Milestone 4 Cookie classification must use only deterministic Cookie-name rules and must not inspect, decode, parse, infer from, or classify using Cookie values.
- Reports for selected sensitive-header findings must use only fixed rule identifier `header.secret` and must not derive rule identifiers from header names, header groups, or detected values.
- Reports for selected query-parameter findings must use only fixed rule identifier `query.secret` and must not derive rule identifiers from parameter names, parameter groups, or detected values.
- Reports for selected JSON-like field findings must use only fixed rule identifier `json.value` and must not derive rule identifiers from field names, field groups, or detected values.
- The tool must not perform network calls or telemetry.
- The first implementation must not use LLM detection.
- Tests must use synthetic data only.

## Secret-Leakage Prevention

Milestone 1 should use safe, user-facing error messages. It should not expose Python tracebacks for expected errors. It should not implement debug mode.

Safe output may include:

- User-provided input and output paths.
- Rule identifiers.
- Redaction counts.
- High-level error categories.

Safe output must not include:

- Matched token values.
- Source lines.
- Context around a match.
- Raw input bytes.
- Decoded input snippets.
- Replacement previews with surrounding evidence.
- Custom Authorization scheme names in report rule identifiers.
- Cookie values or Cookie source excerpts.
- Cookie names as dynamic report identifiers.
- Cookie classification categories derived into dynamic report identifiers.
- Selected sensitive-header values or source excerpts.
- Selected sensitive-header names as dynamic report identifiers.
- Selected query parameter values or source excerpts.
- Selected query parameter names as dynamic report identifiers.
- Selected JSON-like field values or source excerpts.
- Selected JSON-like field names as dynamic report identifiers.

Sensitive values must not be accepted as command-line arguments. CLI arguments should be limited to paths and flags so secrets are not encouraged to appear in shell history or process listings.

## Filesystem Risks

### Source-File Immutability

The source path must be treated as read-only. The implementation must not use in-place editing, backup-overwrite behavior, or write handles on the input file.

### Destination Resolving To Source

The tool must reject an output path that resolves to the input file. The input path may be a symbolic link to a regular file, but the output must not target the same resolved file.

### Output Collision Handling

The output path must not exist. The implementation must use exclusive creation so an existing destination is never overwritten, including if the destination appears between validation and creation.

### Symbolic Links, Junctions, And Hard Links

Milestone 1 allows the input path to be a symbolic link to a regular file. It rejects existing output paths, which also avoids writing through an existing destination symlink.

Milestone 1 does not attempt comprehensive protection against junction, mount-point, or hard-link attacks. These scenarios are explicitly unsupported adversarial filesystem cases.

### Path Traversal

The tool does not extract archives or enforce a sandbox root, so classic archive path traversal is not in scope. User-provided paths should still be resolved for safety checks, while normal output should display paths as supplied by the user.

### TOCTOU

The implementation should avoid relying solely on check-then-write logic. Exclusive output creation is required so a destination that appears after validation is not overwritten.

Milestone 1 does not claim complete time-of-check/time-of-use safety against adversarial local filesystem changes.

### Partial Writes

Atomic replacement is not guaranteed in milestone 1. An abrupt process termination may leave a partial output file. On controlled write failure, the tool should attempt to remove the incomplete output without obscuring the original error.

### Temporary Files

Milestone 1 should not require temporary output files because atomic replacement is deferred. If temporary files are introduced later, they must be created in the output directory, avoid evidence leakage in names, and be cleaned up on controlled failures.

### Permissions And Metadata

The tool does not preserve permissions, ownership, timestamps, ACLs, extended attributes, or other metadata. Sanitized output is a new file created with normal platform defaults.

### Windows And Linux Path Behavior

Use standard library path handling. Account for normal case-insensitive behavior on Windows when checking whether source and destination resolve to the same file. Do not claim comprehensive equivalence across all filesystems, junctions, network mounts, or adversarial races.

## Input And Parsing Risks

### UTF-8, BOM, And Decoding

Only strict UTF-8 and UTF-8 with BOM are supported. Decode failures are rejected. If the input has a UTF-8 BOM, the output must preserve it.

### LF And CRLF Newlines

The implementation must not normalize newlines. Read and write bytes in a way that preserves LF, CRLF, mixed newline sequences, and final-newline state.

### Binary-File Detection

Milestone 1 binary detection is intentionally limited to rejecting NUL bytes and rejecting strict UTF-8 decoding failures. The tool must not claim to reliably detect all binary files.

### Very Large Files

The MVP processes complete files in memory. Inputs larger than 10 MiB must be rejected before sanitization.

### Structured HTTP Syntax

Milestone 1 is limited to HTTP-style `Authorization: Bearer` header lines. It should not redact arbitrary prose containing the word `Bearer`.

Milestone 2 expands only within HTTP-style `Authorization` header lines. It supports Bearer, Basic, and syntactically valid unknown, custom, or structured authorization schemes. It does not add Cookie, Set-Cookie, API-key-specific header, email, or client-identifier sanitization.

Milestone 2 uses the ASCII HTTP token character set for auth-scheme names:

```text
!#$%&'*+-.^_`|~0-9A-Za-z
```

Unicode scheme names, malformed schemes, folded headers, and indented headers remain unsupported and unchanged.

Full HTTP header/body boundary parsing is deferred. As a result, an exact header-like `Authorization:` line inside a message body may be sanitized. This is an accepted false-positive risk for milestone 2.

Basic credentials are sensitive but are not decoded or validated. Generic structured credentials, such as Digest, AWS, AMX, OAuth, Signature, or custom parameters, are sensitive and are redacted as one whole credential section without parsing individual parameters.

Milestone 3 expands only to exact line-start HTTP request `Cookie` header lines. It does not add `Set-Cookie`, API-key-specific header, email, or client-identifier sanitization. It does not add cookie-name classification, sensitive/telemetry/harmless/unknown categories, telemetry allowlists, or selective cookie-value preservation.

Cookie values are sensitive and must be redacted when a supported Cookie line is sanitized. Safely parsed cookie names are intentionally preserved for evidence usefulness, but preserved names may disclose framework details, authentication mechanisms, identity concepts, tenancy concepts, and application internals. Examples include `ASP.NET_SessionId`, `JSESSIONID`, `username`, `email`, `customerId`, `tenant`, and `portalAuth`. Cookie-name classification is deferred to milestone 4.

Milestone 4 adds deterministic Cookie-name classification for safely parsed request Cookie headers. The approved internal categories are sensitive, telemetry, harmless, and unknown. Sensitive, telemetry, and unknown Cookie values remain redacted. Only exact harmless names `theme`, `color_scheme`, and `display_mode` preserve their original values. Classification is case-insensitive, uses only ASCII lowercase name matching, treats `_`, `-`, and `.` as distinct, performs no Unicode normalization, uses no suffix matching, and uses no broad substring matching.

Milestone 4 telemetry values remain redacted because telemetry cookies can contain persistent browser, user, or device identifiers. Preserving telemetry values could enable cross-report, cross-site, or long-term correlation. Telemetry classification exists only to make the deterministic policy explicit; it does not create a special report entry, marker, or preservation behavior.

Preserving even approved harmless values carries residual risk because custom applications can overload apparently harmless names with sensitive content. Name-only classification cannot guarantee that a preserved `theme`, `color_scheme`, or `display_mode` value is actually harmless. Unknown cookies remain redacted by default, and names such as `language`, `lang`, `locale`, `timezone`, `tz`, `cookie_consent`, `consent`, `banner_dismissed`, and `sidebar_state` remain unknown and redacted in milestone 4.

Milestone 3 Cookie headers are parsed only when complete deterministic parsing succeeds. If parsing a non-empty exact non-folded Cookie header is uncertain, the sanitizer must use whole-header fallback instead of partially sanitizing valid-looking pairs and leaving possible secrets exposed. Empty `Cookie:` headers and whitespace-only `Cookie:` headers remain unchanged and produce no finding.

Milestone 4 classification applies only after the complete Cookie header parses safely. Malformed Cookie headers must continue to use whole-header fallback, and individual Cookie names in malformed headers must not be classified or reported.

Milestone 5 expands only to selected sensitive API/authentication-related HTTP-like headers. It supports an approved fixed list of exact line-start header names and replaces whole non-empty trimmed values with `<REDACTED:header.secret>`. It does not parse, decode, classify, split, or infer from values. It does not use substring header matching, grouped rule IDs, per-header rule IDs, dynamic report IDs, user configuration, plugins, new dependencies, or new exit codes.

Milestone 5 selected headers may contain API keys, auth/session/access/refresh/id tokens, CSRF/XSRF tokens, cloud temporary tokens, cloud signatures, or client secrets. CSRF/XSRF sensitivity varies by application, but redaction is appropriate for penetration-testing evidence because these tokens may be session-bound and abuse-enabling. Cloud signature headers and client-secret headers can be highly sensitive.

Milestone 5 intentionally preserves header names for evidence context. Preserved names may reveal cloud providers, authentication architecture, frameworks, API design, or vendor integrations. Reports must still contain only `header.secret` and counts, never header names as dynamic identifiers or detected values.

Milestone 5 intentionally defers IP and client identity headers such as `x-forwarded-for`, `x-real-ip`, `cf-connecting-ip`, `true-client-ip`, and `x-client-ip` because they are privacy identifiers rather than authentication secrets. Identifier headers such as `x-client-id`, `client-id`, `x-tenant-id`, `tenant-id`, `x-user-id`, and `user-id` are also deferred because they are not always secrets. `Proxy-Authorization` is deferred because it is semantically close to `Authorization` and requires a separate decision on scheme-preserving behavior, markers, and rule IDs.

Milestone 6 expands only to selected sensitive raw URL query parameter values in decoded text evidence. It supports an approved fixed list of exact raw parameter names and replaces raw values after `=` with `<REDACTED:query.secret>`. It does not URL-decode, URL-re-encode, recursively parse URL-valued parameters, parse JSON, parse XML, parse structured form bodies, parse multipart bodies, parse HTML, parse JavaScript, use value-based classification, use substring parameter matching, use grouped rule IDs, use per-parameter rule IDs, use dynamic report IDs, add user configuration, add plugins, add registries, add new dependencies, or add new exit codes.

Milestone 9 expands only to selected sensitive JSON-like string fields in decoded text evidence. It supports an approved fixed list of exact JSON-like field names and replaces only the raw string value payload between quotes with `<REDACTED:json.value>`. It does not perform full JSON parsing, JSON validation, JSON reserialization, JSON schema checking, unicode-escape decoding for field names, recursive parsing of nested values, value-based classification, substring field-name matching, grouped rule IDs, per-field rule IDs, dynamic report IDs, user configuration, plugins, registries, new dependencies, or new exit codes.

Milestone 9 selected JSON-like fields may contain OAuth/OIDC-style access, refresh, ID, and auth tokens; session identifiers; JWTs; API keys; client secrets; shared secrets; private keys; signatures; SAML responses; and client assertions. Broad approved exact names such as `token`, `session`, `sig`, and `signature` may produce false positives, but they are explicitly approved because they are common in API evidence. `sig` and `signature` are often highly sensitive in signed URLs and callback flows. Cloud signature parameters such as `x-amz-signature`, `x-amz-security-token`, and `x-amz-credential` can authorize temporary access. API key parameters can authenticate requests.

Milestone 6 intentionally defers broad names such as `key`, `code`, `state`, `nonce`, `secret`, `sign`, and `signed` to avoid broad false positives. Short cloud/SAS names such as `se`, `sp`, `sv`, `sr`, and `st` are deferred until a dedicated signed-URL context is approved. Tracking identifiers such as `utm_source`, `gclid`, `fbclid`, `msclkid`, and `_ga` are privacy or telemetry identifiers and belong in a separate milestone. Password and SAML/form-like parameter names are deferred until body/form parsing scope is addressed or explicitly approved.

Folded Cookie headers are unsupported in milestone 3. If an exact `Cookie:` line is immediately followed by a physical line beginning with a space or tab, the folded form remains completely unchanged. This is a residual false-negative risk because folded Cookie values may remain in output. Full folded-header parsing is deferred.

Folded selected sensitive headers are unsupported in milestone 5. If an exact sensitive header line is immediately followed by a physical line beginning with a space or tab, the complete folded form remains unchanged and produces no `header.secret` finding. This is a residual false-negative risk because folded sensitive-header values may remain in output. Full folded-header parsing remains deferred.

Full HTTP header/body boundary parsing remains deferred in milestone 3, milestone 5, and milestone 6. As a result, exact header-like `Cookie:` or selected sensitive-header lines inside message bodies may be sanitized, and exact raw URL-like text inside bodies or logs may be sanitized. This is an accepted false-positive risk for deterministic line-oriented and query-scanning rules.

Percent-encoded query parameter names are not decoded in milestone 6. For example, `access%5Ftoken` does not match `access_token` and may retain a sensitive value. Recursive URL-in-value parsing is deferred, so nested URL query strings may retain sensitive values. Malformed or unusual query strings may be partially missed. The milestone does not claim complete secret-removal coverage.

`Set-Cookie`, JSON bodies, XML bodies, form bodies as structured form data, multipart bodies, HTML, JavaScript, non-approved custom secret headers, deferred query parameter names, and nested URL-in-value parsing remain out of scope in milestone 6 and may retain secrets.

NUL remains rejected by the existing input-validation path. CR and LF are line delimiters, not Cookie-value characters. Other unsupported control characters inside a Cookie value trigger whole-header fallback rather than a new global error or a new exit code.

## Regex Risks

Regex can be appropriate for the milestone 1 bearer rule and milestone 2 Authorization-header finder if patterns are line-oriented, bounded, and avoid nested quantifiers. Tests should include long non-matching lines and malformed header-like lines to reduce catastrophic-backtracking risk.

Milestone 3 Cookie parsing should use a bounded line detector plus a deterministic scanner for the header value. The scanner should parse complete Cookie values before emitting per-value findings. Performance tests are required only if the chosen implementation creates realistic risk, such as catastrophic backtracking or unbounded parsing behavior.

Milestone 5 selected sensitive-header detection should use the existing physical-line iteration plus exact header-name checks. A broad regex or substring search is not required. Performance tests are required only if the chosen implementation creates realistic risk.

Milestone 6 selected query-parameter detection should use a small deterministic raw query scanner. A full URL parser, recursive parser, broad regex, substring search, URL-decoding pass, or URL-re-encoding pass is not required. Performance tests are required only if the chosen implementation creates realistic risk, such as unbounded scanning or catastrophic backtracking.

Milestone 9 selected JSON-like field detection should use a small deterministic raw JSON-like scanner. A full JSON parser, JSON reserialization, JSON schema validation, broad regex, substring search, or unicode-escape decoding pass is not required. Performance tests are required only if the chosen implementation creates realistic risk, such as unbounded scanning or catastrophic backtracking.

Regex is not the only approved parsing mechanism. Future structured formats may require parsers or purpose-built scanners instead of broad regular expressions.

## Rule Ordering, Overlap, And Idempotence

Milestone 1 has one rule, so generalized rule ordering is not needed. The bearer rule must produce non-overlapping findings. Any overlap in milestone 1 is an internal sanitization error.

Repeated sanitization must be idempotent for the bearer rule. The fixed marker `<REDACTED:authorization.bearer>` must not be treated as a new bearer credential on subsequent runs.

Replacement-token collisions are possible if the original evidence already contains the marker. This is acceptable for milestone 1 because reports only count actual replacements and the marker is deterministic. More advanced collision handling is deferred.

Milestone 2 should use one coherent Authorization-header finder that produces at most one finding per Authorization line. Bearer and Basic branches must not fall through to the generic branch when their specialized validation fails. Generic fallback applies only to schemes other than Bearer and Basic.

Milestone 2 approved markers are `<REDACTED:authorization.bearer>`, `<REDACTED:authorization.basic>`, and `<REDACTED:authorization.credentials>`. If the complete credential section is exactly any approved marker, the value is already sanitized and produces no finding or count, even when the marker appears under a different scheme. The sanitizer must not correct or normalize wrong-scheme markers. A marker embedded inside a larger raw credential value is not considered already sanitized.

Milestone 3 should add independent Cookie findings that do not overlap with Authorization findings by construction. The combined finding set should continue to use right-to-left replacement, and any overlap should remain an internal sanitization error rather than introducing a generalized overlap-resolution system.

Milestone 3 approved Cookie markers are `<REDACTED:cookie.value>` and `<REDACTED:cookie.header>`. If an exact approved Cookie marker is used as a complete individual cookie value, the value is already sanitized and produces no finding or count. If an exact approved Cookie marker is used as the complete trimmed Cookie header value, the header is already sanitized and produces no finding or count. The sanitizer must not correct or normalize wrong-context markers. A marker embedded inside a larger raw value is not considered already sanitized and must be redacted. Repeated sanitization must be byte-identical.

Milestone 4 keeps the same Cookie markers and rule IDs. It does not approve category-specific markers or report IDs. Values such as `<REDACTED:cookie.sensitive>` and `<REDACTED:cookie.unknown>` are ordinary raw values and should be redacted as `cookie.value` unless existing parser behavior requires whole-header fallback. Existing `<REDACTED:cookie.value>` and `<REDACTED:cookie.header>` markers remain idempotent, and previously redacted telemetry values cannot be recovered.

Milestone 5 uses only rule ID `header.secret` and marker `<REDACTED:header.secret>`. If the complete trimmed selected sensitive-header value is exactly `<REDACTED:header.secret>`, the value is already sanitized and produces no finding or count. A marker embedded inside a larger raw value is not already sanitized and must be redacted. Unapproved header marker-like values and wrong-family Authorization or Cookie markers inside selected sensitive headers are treated as raw and redacted. Replacement-marker collisions are accepted and handled deterministically. Do not introduce a generalized marker framework.

Milestone 6 uses only rule ID `query.secret` and marker `<REDACTED:query.secret>`. If the complete raw selected query parameter value is exactly `<REDACTED:query.secret>`, the value is already sanitized and produces no finding or count. Marker handling must be marker-aware so the approved marker's `<` and `>` do not break idempotence or query boundary detection. A marker embedded inside a larger raw query value is not already sanitized and must be redacted. Unapproved query marker-like values and wrong-family Authorization, Cookie, or sensitive-header markers inside selected query parameter values are treated as raw and redacted. Replacement-marker collisions are accepted and handled deterministically. Do not introduce a generalized marker framework.

Existing Authorization, Cookie, and selected sensitive-header findings are authoritative in milestone 6. Query findings that overlap existing findings must be skipped and produce no `query.secret` count. `apply_findings` remains the final overlap guard. A preserved harmless Cookie value may still receive a `query.secret` finding when no Cookie finding overlaps because harmless Cookie values are intentionally preserved.

Milestone 9 uses only rule ID `json.value` and marker `<REDACTED:json.value>`. If the complete raw JSON-like string value payload is exactly `<REDACTED:json.value>`, the value is already sanitized and produces no finding or count. A marker embedded inside a larger raw string value is not already sanitized and must be redacted. Unapproved JSON marker-like values and wrong-family Authorization, Cookie, sensitive-header, or query markers inside selected JSON-like field values are treated as raw and redacted. Replacement-marker collisions are accepted and handled deterministically. Do not introduce a generalized marker framework.

Existing Authorization, Cookie, selected sensitive-header, and selected sensitive-query-parameter findings are authoritative in milestone 9. JSON findings that overlap existing findings must be skipped and produce no `json.value` count. `apply_findings` remains the final overlap guard. A preserved harmless Cookie value may still receive a `json.value` finding when no Cookie finding overlaps because harmless Cookie values are intentionally preserved. A non-sensitive query or header value may also receive a `json.value` finding when no broader finding overlaps.

## Dry-Run Behavior

Dry-run mode performs validation, reading, decoding, and detection. It must not create the output file and must not create temporary files. It reports only safe rule identifiers and counts.

## Future Directory Inputs

Directory processing is deferred. Future directory mode must define partial-failure semantics before implementation, including whether any output is written after one file fails and how per-file statuses are reported without leaking evidence.

## Assumptions And Residual Risks

- Users supply authorized evidence only.
- Users understand that unsupported secrets may remain.
- Paths displayed in normal output may themselves reveal project or client names; this is accepted for usability in milestone 1.
- Exclusive output creation prevents overwrites but does not prevent every filesystem race.
- Partial output can remain after abrupt termination.
- Metadata is intentionally not preserved.
- Binary detection is limited and incomplete by design.
- Milestone 2 does not guarantee detection of every Authorization-like credential or every possible secret.
- Milestone 2 marker collisions are accepted and handled deterministically.
- Milestone 3 does not guarantee detection of every Cookie-like value or every possible secret.
- Milestone 3 intentionally preserves safely parsed Cookie names, which may disclose application structure.
- Milestone 3 leaves folded Cookie headers unchanged, which may leave sensitive values intact.
- Milestone 3 may sanitize exact header-like `Cookie:` lines inside message bodies because full HTTP parsing is deferred.
- Milestone 3 marker collisions are accepted and handled deterministically.
- Milestone 4 does not guarantee that preserved harmless values are actually harmless.
- Milestone 4 intentionally redacts telemetry values because they may be persistent identifiers.
- Milestone 4 unknown Cookie values remain redacted by default, which may reduce evidence usefulness.
- Milestone 4 Cookie classification is name-only and can be wrong when an application uses a misleading Cookie name.
- `Set-Cookie` sanitization remains deferred.
- Milestone 5 does not guarantee detection of every sensitive API/authentication header or every possible secret.
- Milestone 5 preserves selected sensitive-header names, which may disclose system architecture or vendor details.
- Milestone 5 leaves folded selected sensitive headers unchanged, which may leave sensitive values intact.
- Milestone 5 may sanitize exact selected sensitive-header-like lines inside message bodies because full HTTP parsing is deferred.
- Milestone 5 marker collisions are accepted and handled deterministically.
- IP/client identity headers and identifier headers remain deferred to a privacy/identifier milestone.
- Milestone 6 does not guarantee detection of every sensitive query parameter or every possible secret.
- Milestone 6 may sanitize exact raw URL-like text inside bodies or logs because full HTTP parsing is deferred.
- Milestone 6 percent-encoded query parameter names remain unsupported and may retain sensitive values.
- Milestone 6 does not recursively parse URL-valued query parameters, so nested query values may remain raw.
- Milestone 6 marker collisions are accepted and handled deterministically.
- Existing Authorization, Cookie, and selected sensitive-header findings remain authoritative for overlapping spans.
- IP/client identity headers, identifier headers, broad query names, short SAS names, tracking parameters, password-like query names, and SAML/form-like query names remain deferred to future milestones or approvals.
- `Proxy-Authorization`, `Set-Cookie`, XML bodies, form bodies as structured form data, multipart bodies, HTML, JavaScript, and unsupported body parsing remain out of scope.
- Milestone 9 does not guarantee detection of every sensitive JSON-like field or every possible secret.
- Milestone 9 may sanitize JSON-like string-key/string-value pairs inside prose, logs, or snippets because full JSON parsing remains deferred.
- Milestone 9 does not decode JSON unicode-escape field names, so names such as `"access\u005Ftoken"` remain unsupported and may retain sensitive values.
- Milestone 9 does not recursively parse URL-valued JSON string values, so nested sensitive values may remain raw.
- Milestone 9 does not redact non-string direct values such as numbers, booleans, null, arrays, or objects.
- Deferred JSON field names such as `key`, `secret`, `code`, `state`, `nonce`, `assertion`, CSRF/XSRF fields, and identifier-like fields may retain secrets.
- Broad approved exact names such as `token`, `session`, `sig`, and `signature` may produce false positives.
- Malformed JSON-like candidates may be skipped and may retain secrets.
- Existing Authorization, Cookie, selected sensitive-header, and selected sensitive-query-parameter findings remain authoritative for overlapping spans.

## Explicitly Unsupported Adversarial Filesystem Scenarios

Milestone 1 does not attempt comprehensive handling of:

- Malicious junction or mount-point replacement during execution.
- Hard-link attacks designed to confuse source/destination identity.
- Network filesystem inconsistency.
- Privileged local attackers changing paths between validation and writing.
- Filesystems with unusual case-folding or path-equivalence semantics.
- Race conditions beyond the protection provided by exclusive output creation.
