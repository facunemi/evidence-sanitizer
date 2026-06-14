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

Do not create modules such as `paths.py`, `reporting.py`, `textio.py`, `engine.py`, or `rules/` merely because they might be useful later. Their creation should be justified by concrete implemented responsibilities.

## Data Flow

Milestone 1 through milestone 3 data flow:

1. Typer parses `sanitize INPUT --output OUTPUT [--dry-run]`.
2. The command validates the input path, output path, and output parent directory.
3. The command rejects a destination that already exists.
4. The command rejects a destination that resolves to the input file.
5. The command reads the complete input file in memory, up to 10 MiB.
6. The command rejects NUL bytes.
7. The command decodes strict UTF-8 or UTF-8 with BOM.
8. The sanitizer applies the approved Authorization-header rule set and, in milestone 3, the approved Cookie-header rule set.
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

- `rule_id`: stable identifier, such as `authorization.bearer`, `authorization.basic`, `authorization.other`, `cookie.value`, or `cookie.header`.
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
- Generalized overlap resolution: rejected until more than one rule exists.
- Metadata preservation: rejected because sanitized output is a new copy and cross-platform metadata preservation is not required.
- Atomic replacement guarantee: deferred because exclusive new-file creation is sufficient for milestone 1's approved safety target.

## Rules Against Speculative Abstraction

- Do not add a module without implemented responsibility.
- Do not add protocols or base classes until more than one implementation needs the abstraction, except for narrow rule-testability needs.
- Do not add dependency injection containers.
- Do not add plugin discovery.
- Do not add async processing.
- Do not add configuration loading.
- Do not add reporting formats until there is an approved consumer.
- Do not add future directory-processing architecture until single-file semantics are proven.
