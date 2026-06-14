# Security Model

## Protected Assets

- Original evidence files.
- Detected sensitive values, including Bearer tokens, Basic credentials, custom or structured Authorization credentials, Cookie values, and future supported secret types.
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

Milestone 3 Cookie headers are parsed only when complete deterministic parsing succeeds. If parsing a non-empty exact non-folded Cookie header is uncertain, the sanitizer must use whole-header fallback instead of partially sanitizing valid-looking pairs and leaving possible secrets exposed. Empty `Cookie:` headers and whitespace-only `Cookie:` headers remain unchanged and produce no finding.

Folded Cookie headers are unsupported in milestone 3. If an exact `Cookie:` line is immediately followed by a physical line beginning with a space or tab, the folded form remains completely unchanged. This is a residual false-negative risk because folded Cookie values may remain in output. Full folded-header parsing is deferred.

Full HTTP header/body boundary parsing remains deferred in milestone 3. As a result, an exact header-like `Cookie:` line inside a message body may be sanitized. This is an accepted false-positive risk for milestone 3.

NUL remains rejected by the existing input-validation path. CR and LF are line delimiters, not Cookie-value characters. Other unsupported control characters inside a Cookie value trigger whole-header fallback rather than a new global error or a new exit code.

## Regex Risks

Regex can be appropriate for the milestone 1 bearer rule and milestone 2 Authorization-header finder if patterns are line-oriented, bounded, and avoid nested quantifiers. Tests should include long non-matching lines and malformed header-like lines to reduce catastrophic-backtracking risk.

Milestone 3 Cookie parsing should use a bounded line detector plus a deterministic scanner for the header value. The scanner should parse complete Cookie values before emitting per-value findings. Performance tests are required only if the chosen implementation creates realistic risk, such as catastrophic backtracking or unbounded parsing behavior.

Regex is not the only approved parsing mechanism. Future structured formats may require parsers or purpose-built scanners instead of broad regular expressions.

## Rule Ordering, Overlap, And Idempotence

Milestone 1 has one rule, so generalized rule ordering is not needed. The bearer rule must produce non-overlapping findings. Any overlap in milestone 1 is an internal sanitization error.

Repeated sanitization must be idempotent for the bearer rule. The fixed marker `<REDACTED:authorization.bearer>` must not be treated as a new bearer credential on subsequent runs.

Replacement-token collisions are possible if the original evidence already contains the marker. This is acceptable for milestone 1 because reports only count actual replacements and the marker is deterministic. More advanced collision handling is deferred.

Milestone 2 should use one coherent Authorization-header finder that produces at most one finding per Authorization line. Bearer and Basic branches must not fall through to the generic branch when their specialized validation fails. Generic fallback applies only to schemes other than Bearer and Basic.

Milestone 2 approved markers are `<REDACTED:authorization.bearer>`, `<REDACTED:authorization.basic>`, and `<REDACTED:authorization.credentials>`. If the complete credential section is exactly any approved marker, the value is already sanitized and produces no finding or count, even when the marker appears under a different scheme. The sanitizer must not correct or normalize wrong-scheme markers. A marker embedded inside a larger raw credential value is not considered already sanitized.

Milestone 3 should add independent Cookie findings that do not overlap with Authorization findings by construction. The combined finding set should continue to use right-to-left replacement, and any overlap should remain an internal sanitization error rather than introducing a generalized overlap-resolution system.

Milestone 3 approved Cookie markers are `<REDACTED:cookie.value>` and `<REDACTED:cookie.header>`. If an exact approved Cookie marker is used as a complete individual cookie value, the value is already sanitized and produces no finding or count. If an exact approved Cookie marker is used as the complete trimmed Cookie header value, the header is already sanitized and produces no finding or count. The sanitizer must not correct or normalize wrong-context markers. A marker embedded inside a larger raw value is not considered already sanitized and must be redacted. Repeated sanitization must be byte-identical.

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
- `Set-Cookie` sanitization remains deferred.

## Explicitly Unsupported Adversarial Filesystem Scenarios

Milestone 1 does not attempt comprehensive handling of:

- Malicious junction or mount-point replacement during execution.
- Hard-link attacks designed to confuse source/destination identity.
- Network filesystem inconsistency.
- Privileged local attackers changing paths between validation and writing.
- Filesystems with unusual case-folding or path-equivalence semantics.
- Race conditions beyond the protection provided by exclusive output creation.
