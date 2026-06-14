# Milestones

## Milestone 0: Project Foundation

Milestone 0 establishes the Python project foundation only. It must not implement sanitizer behavior.

Expected package shape when implementation begins:

```text
src/evidence_sanitizer/
|-- __init__.py
|-- __main__.py
`-- cli.py
```

Expected milestone 0 work:

- Create packaging and tooling configuration.
- Establish Python 3.12 or newer support.
- Configure Typer for the CLI.
- Configure pytest, ruff, and mypy.
- Add a CLI entry point with root help output.
- Add minimal tests for root command availability and expected no-implementation behavior.
- Document development commands.

Milestone 0 CLI scope:

- Expose root CLI help only.
- Do not register a `sanitize` command in milestone 0.
- Add the `sanitize` command in milestone 1.

Milestone 0 packaging decisions:

- Use `pyproject.toml` with PEP 621 project metadata.
- Use `hatchling` as the build backend.
- Start at version `0.1.0`.
- Use `typer` as the only runtime dependency.
- Use dependency groups or equivalent `uv`-compatible metadata for `pytest`, `ruff`, and `mypy`.
- Define the `evidence-sanitizer` console script so `uv run evidence-sanitizer --help` invokes the Typer root app.
- Keep production package code limited to the expected package shape for milestone 0.

Milestone 0 must not include:

- File reading for sanitization.
- File writing for sanitized output.
- The `sanitize` command, including a non-functional stub.
- Bearer-token detection.
- Replacement logic.
- Rule abstractions beyond what the CLI skeleton requires.
- Network features, telemetry, plugins, LLM detection, or configuration files.

### Milestone 0 Acceptance Criteria

- `uv` can create and use the project environment.
- The root CLI help command works.
- The CLI exposes root help only; `sanitize` is not registered until milestone 1.
- The production package code shape is limited to `__init__.py`, `__main__.py`, and `cli.py`.
- No sanitizer implementation exists.
- No production code reads evidence files.
- No production code writes sanitized output files.
- No network, telemetry, plugin, or LLM code exists.
- Tests use synthetic data only.
- Verification commands are documented and run successfully for the skeleton.

### Milestone 0 Verification Requirements

Expected commands after milestone 0 exists:

```bash
uv sync
uv run evidence-sanitizer --help
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```

## Milestone 1: Single-Rule End-To-End Sanitizer

Milestone 1 implements the smallest useful sanitizer. It processes one file in memory and supports only HTTP-style `Authorization: Bearer` header redaction.

Expected milestone 1 behavior:

- Provide the `sanitize INPUT --output OUTPUT [--dry-run]` command.
- Accept one input path and one output path.
- Support `--dry-run`.
- Allow the input path to be a symbolic link to a regular file.
- Reject directories as input.
- Reject input larger than 10 MiB.
- Reject input containing NUL bytes.
- Reject strict UTF-8 decoding failures.
- Accept strict UTF-8 and UTF-8 with BOM only.
- Preserve input BOM presence in output.
- Preserve LF, CRLF, mixed newline sequences, and final-newline state.
- Detect HTTP-style `Authorization: Bearer` header values.
- Replace the credential portion with `<REDACTED:authorization.bearer>`.
- Report `authorization.bearer` counts without detected values.
- Treat detected findings as success with exit code `0`.
- Reject existing output paths.
- Require the output parent directory to already exist.
- Reject output paths resolving to the source file.
- Create output exclusively so existing destinations are not overwritten.
- On controlled write failure, attempt to remove incomplete output without hiding the original error.

Milestone 1 must not include:

- Additional rules.
- Directory processing.
- Overwrite mode.
- Atomic output replacement guarantee.
- Metadata preservation.
- Configuration files.
- Plugin APIs.
- Debug mode.
- Network features.
- Telemetry.
- LLM detection.
- Comprehensive adversarial filesystem-race handling.
- Generalized overlap-resolution architecture.

### Milestone 1 Acceptance Criteria

- A supported input file can be sanitized into a new output file.
- The original input file remains byte-for-byte unchanged.
- Existing output paths are rejected before writing.
- Destinations resolving to the source file are rejected.
- Missing output parent directories are rejected.
- Dry-run mode creates no output file and no temporary file.
- Output is created using exclusive creation.
- Controlled write failure attempts cleanup of incomplete output.
- Documentation states that abrupt termination may leave partial output.
- UTF-8 BOM presence is preserved.
- LF and CRLF sequences are preserved exactly.
- Final-newline presence is preserved.
- Inputs larger than 10 MiB are rejected.
- Inputs containing NUL bytes are rejected.
- UTF-8 decoding failures are rejected.
- The only implemented rule is `authorization.bearer`.
- The bearer rule is restricted to HTTP-style header lines.
- The replacement marker is exactly `<REDACTED:authorization.bearer>`.
- The bearer rule is idempotent.
- Bearer findings do not overlap; overlap is treated as an internal sanitization error.
- CLI output includes rule IDs and counts only.
- CLI output, safe errors, reports, tests, and snapshots do not include detected values.
- Findings return exit code `0`.
- Typer handles usage errors.
- Tests use only synthetic data.

### Milestone 1 Verification Requirements

Expected commands:

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```

Required test coverage:

- CLI success with finding.
- CLI success with no finding.
- Dry-run creates no output.
- Source file immutability.
- Existing output rejection.
- Same source/destination rejection.
- Missing output parent rejection.
- 10 MiB size-limit rejection.
- NUL-byte rejection.
- UTF-8 decoding failure.
- UTF-8 BOM preservation.
- LF and CRLF preservation.
- Final-newline preservation.
- Case-insensitive authorization header and bearer scheme matching.
- Non-HTTP prose containing `Bearer` is not redacted.
- Idempotence of repeated sanitization.
- No secret leakage in CLI output or exceptions.
- Bearer detection over a synthetic 1 MiB malformed non-matching line completes in less than 2 seconds during the normal `uv run pytest` test run.

## Milestone 2: Generalized Authorization Header Sanitizer

Milestone 2 generalizes HTTP `Authorization` header sanitization while preserving all milestone 1 file-processing, safety, encoding, newline, reporting, and CLI behavior.

Milestone 2 scope:

- Preserve existing HTTP-style `Authorization: Bearer` behavior unchanged.
- Add explicit HTTP-style `Authorization: Basic` credential sanitization.
- Add a conservative generic fallback for syntactically valid unknown, custom, and structured Authorization schemes.
- Keep one input file, one explicit output file, and complete-file in-memory processing.
- Keep deterministic built-in behavior only.

Milestone 2 must not include:

- Cookie or Set-Cookie sanitization.
- API-key-specific headers.
- Email or client-identifier redaction.
- Directory processing or multiple input files.
- Overwrite mode.
- Atomic output replacement guarantee.
- Metadata preservation.
- Configuration files.
- Plugin APIs or plugin registries.
- Factories, inheritance hierarchies, dependency injection, or generalized precedence engines.
- Debug mode.
- Network features.
- Telemetry.
- LLM detection.
- Persistence.
- Full HTTP header/body parsing.
- Folded-header parsing.

Expected milestone 2 behavior:

- Use one coherent Authorization-header finder in `src/evidence_sanitizer/sanitizer.py`.
- The finder produces at most one finding per Authorization line.
- Match only exact line-start `Authorization` headers; indented or folded lines remain unchanged.
- Match the header name case-insensitively.
- Allow spaces and tabs around `:`.
- Require an auth scheme using the ASCII HTTP token character set:

```text
!#$%&'*+-.^_`|~0-9A-Za-z
```

- Leave Unicode scheme names and malformed schemes unchanged.
- Preserve header name casing, spacing around `:`, scheme casing, spacing between scheme and credentials, trailing spaces and tabs, newline sequences, and final-newline state.
- Keep Bearer rule ID `authorization.bearer` and marker `<REDACTED:authorization.bearer>`.
- Bearer credentials must be exactly one contiguous non-whitespace value.
- Empty, whitespace-only, or internally spaced Bearer credentials remain unchanged.
- Bearer lines that fail specialized validation must not fall through to the generic rule.
- Use Basic rule ID `authorization.basic` and marker `<REDACTED:authorization.basic>`.
- Basic credentials must be exactly one contiguous non-whitespace value.
- Basic credentials must not be Base64-decoded or validated.
- Empty, whitespace-only, or internally spaced Basic credentials remain unchanged.
- Basic lines that fail specialized validation must not fall through to the generic rule.
- Use generic rule ID `authorization.other` and marker `<REDACTED:authorization.credentials>` for schemes other than Bearer and Basic.
- Generic fallback replaces the complete non-empty credential section after the scheme.
- Generic fallback allows internal spaces, commas, quotes, equals signs, colons, slashes, and other punctuation.
- Generic fallback must not parse individual Digest, AWS, AMX, OAuth, Signature, or custom parameters.
- Empty or scheme-only generic headers remain unchanged.
- Custom scheme names must never appear in report rule IDs.
- Counts represent one redacted Authorization credential section per matching header line.
- Already-redacted values do not increment counts.
- Reports contain only fixed rule IDs and counts, never credential values, source excerpts, or custom scheme names.

Approved milestone 2 markers:

```text
<REDACTED:authorization.bearer>
<REDACTED:authorization.basic>
<REDACTED:authorization.credentials>
```

Marker policy:

- If the complete credential section is exactly any approved marker, the value is already sanitized and produces no finding.
- This applies even when the marker appears under a different scheme.
- The sanitizer must not correct or normalize a marker used under another scheme.
- A marker embedded inside a larger raw credential value is not considered already sanitized.

Accepted milestone 2 limitations:

- Exact header-like Authorization lines inside message bodies may be sanitized.
- Full HTTP body-boundary parsing remains deferred.
- Folded or indented header lines remain unsupported.
- Unicode auth-scheme names remain unsupported.
- Basic credentials are not decoded or validated.
- Generic structured credentials are redacted as a whole.
- The tool does not guarantee detection of every possible secret.
- Marker collisions are accepted and handled deterministically.

### Milestone 2 Acceptance Criteria

- Existing Bearer behavior remains unchanged and all existing Bearer regression tests remain valid, except milestone 1 tests that expected Basic to be unsupported must be updated for the approved Basic behavior.
- Bearer credentials are sanitized only when they are one contiguous non-whitespace value.
- Bearer lines with empty, whitespace-only, or internally spaced credentials remain unchanged and do not fall through to generic fallback.
- Basic credentials are sanitized only when they are one contiguous non-whitespace value.
- Basic credentials are not decoded or validated.
- Basic lines with empty, whitespace-only, or internally spaced credentials remain unchanged and do not fall through to generic fallback.
- Unknown, custom, and structured schemes using the approved ASCII token grammar are sanitized by generic fallback.
- Generic fallback preserves scheme name and formatting while replacing the full non-empty credential section.
- Generic fallback supports structured values containing internal spaces and punctuation.
- Malformed schemes, Unicode scheme names, folded lines, indented lines, and unrelated prose remain unchanged.
- Any exact approved marker is treated as already sanitized, even under a different scheme.
- Repeated sanitization is idempotent.
- One Authorization line creates at most one finding.
- Rule counts use only `authorization.bearer`, `authorization.basic`, and `authorization.other`.
- Reports, CLI output, exceptions, logs, tests, and snapshots do not include detected values or source excerpts.
- Reports do not include custom scheme names.
- Source files remain byte-for-byte unchanged.
- Existing output paths are not overwritten.
- Dry-run creates no output file and no temporary file.
- Existing UTF-8, UTF-8 BOM, LF, CRLF, mixed-newline, final-newline, 10 MiB, NUL-byte, safe-error, and exit-code behavior remains unchanged.
- Cookie, Set-Cookie, API-key-specific headers, email redaction, client-identifier redaction, directory processing, configuration files, plugins, network behavior, telemetry, LLM behavior, persistence, full HTTP parsing, and folded-header parsing are not implemented.
- Tests use only synthetic data.

### Milestone 2 Verification Requirements

Expected commands:

```bash
uv sync
uv run evidence-sanitizer --help
uv run python -m evidence_sanitizer --help
uv run evidence-sanitizer sanitize --help
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```

Required test coverage:

- Existing Bearer regression coverage remains passing.
- Bearer already-redacted marker remains idempotent.
- Generic fallback does not capture Bearer lines.
- Basic standard header redaction.
- Basic case-insensitive scheme matching.
- Basic preserved spacing and casing.
- Basic tabs around separators.
- Basic punctuation in one-token credentials.
- Basic empty, whitespace-only, and internally spaced credentials remain unchanged.
- Basic already-redacted marker remains unchanged.
- Multiple Basic headers are counted correctly.
- Basic idempotence.
- AMX-like generic credential redaction.
- Digest-like structured credential redaction.
- AWS-style structured credential redaction.
- Custom one-token credential redaction.
- Custom credential redaction with internal spaces.
- Generic credentials containing quotes, commas, equals signs, colons, and slashes.
- Generic scheme and surrounding syntax preservation.
- Generic empty or scheme-only headers remain unchanged.
- Malformed schemes remain unchanged.
- Indented lines remain unchanged.
- Unrelated prose remains unchanged.
- Generic already-redacted marker remains unchanged.
- Wrong-scheme markers remain unchanged.
- Generic idempotence.
- No overlap between Bearer, Basic, and generic fallback.
- Source remains byte-for-byte unchanged.
- Dry-run creates no output.
- Existing output is not overwritten.
- BOM and newline preservation remain unchanged.
- Mixed line endings remain unchanged.
- Reports contain correct counts for Bearer, Basic, and other scheme types in one file.
- Safe output contains only rule IDs and counts.
- Credential values do not appear in CLI output or errors.
- Existing exit-code behavior remains unchanged.
- Console-script and module entry points remain consistent.

## Milestone 3: HTTP Request Cookie Header Sanitizer

Milestone 3 adds deterministic sanitization for exact line-start HTTP request `Cookie` headers while preserving all milestone 1 and milestone 2 file-processing, safety, encoding, newline, reporting, CLI, and Authorization behavior.

Milestone 3 scope:

- Support only exact decoded line-start HTTP request `Cookie` headers.
- Preserve cookie names when the complete header value parses safely.
- Replace every safely parsed cookie value with `<REDACTED:cookie.value>`.
- Preserve original pair order and formatting around names, `=`, `;`, and trailing spaces or tabs as safely as possible.
- Use whole-header fallback with `<REDACTED:cookie.header>` when complete safe parsing fails.
- Keep one input file, one explicit output file, and complete-file in-memory processing.
- Keep deterministic built-in behavior only.

Milestone 3 must not include:

- `Set-Cookie` sanitization.
- Cookie-name classification.
- Sensitive, telemetry, harmless, or unknown cookie categories.
- Telemetry allowlists.
- Cookie-name allowlists or denylists.
- Selective cookie-value preservation.
- API-key-specific headers.
- Email or client-identifier redaction.
- Directory processing or multiple input files.
- Overwrite mode.
- Atomic output replacement guarantee.
- Metadata preservation.
- Configuration files.
- User-defined rules.
- Plugin APIs or plugin registries.
- Factories, inheritance hierarchies, dependency injection, configurable rule ordering, parser frameworks, or generalized precedence engines.
- Debug mode.
- Network features.
- Telemetry.
- LLM detection.
- Persistence.
- New dependencies.
- New exit codes.
- Full HTTP message parsing.
- Folded-header parsing.

Expected milestone 3 behavior:

- Keep Cookie behavior in `src/evidence_sanitizer/sanitizer.py` using small Cookie-specific constants and private helpers.
- Reuse `Finding`, `SanitizationReport`, `apply_findings`, existing file handling, and right-to-left replacement.
- Add no new public data structures.
- Authorization and Cookie findings are independent and non-overlapping by construction.
- Match `Cookie` case-insensitively.
- Match only exact decoded line-start `Cookie` headers.
- Allow spaces and tabs between `Cookie` and `:`.
- Allow spaces and tabs after `:`.
- Preserve header-name casing, spacing around `:`, trailing spaces and tabs, LF, CRLF, mixed newline sequences, UTF-8 BOM state, and final-newline state.
- Do not match `Set-Cookie`, `X-Cookie`, indented Cookie lines, folded continuation lines, or prose containing the word `Cookie`.
- Exact header-like `Cookie:` lines inside message bodies may be sanitized because full HTTP body-boundary parsing remains deferred.

Safe per-value parsing:

- Per-value redaction is allowed only when the complete Cookie header value parses safely.
- A safely parsed Cookie header consists of one or more non-empty `name=value` pairs separated by semicolons.
- Cookie names must be non-empty and use only the ASCII HTTP token character set:

```text
!#$%&'*+-.^_`|~0-9A-Za-z
```

- `$` is allowed in cookie names because it is an HTTP token character.
- Non-ASCII or malformed cookie names trigger whole-header fallback.
- Preserve spaces or tabs around `=`, spaces or tabs around `;`, original pair order, duplicate names, and trailing horizontal whitespace at the end of the header.
- The first `=` separates name from value.
- Empty values, such as `session=`, are valid and must be redacted.
- Unquoted values may contain additional `=`, commas, colons, slashes, printable punctuation other than semicolons, and non-ASCII text.
- Quoted values are supported; preserve the surrounding quote characters and replace only the quoted payload.
- Semicolons inside quoted values are part of the value, not pair delimiters.
- Valid escaped characters inside quoted values are supported.
- Missing closing quotes, dangling escapes, and non-horizontal junk after the closing quote before `;` or line end trigger whole-header fallback.

Whole-header fallback:

- For any non-empty, non-marker, exact non-folded Cookie header that cannot be completely and deterministically parsed, replace the complete trimmed header value with `<REDACTED:cookie.header>`.
- Fallback triggers include missing `=`, empty name, leading semicolon, trailing semicolon, consecutive semicolons, malformed segments mixed with valid segments, malformed quoted syntax, missing closing quote, dangling escape, invalid non-ASCII cookie name, unsupported control characters, junk after a closing quote, or any other condition that prevents complete safe parsing.
- Do not partially sanitize a malformed header.
- A fallback header produces no `cookie.value` findings.

Unchanged and deferred forms:

- `Cookie:` remains unchanged and produces no finding.
- `Cookie:` followed only by spaces or tabs remains unchanged and produces no finding.
- `Set-Cookie` remains unchanged and out of scope.
- `X-Cookie` remains unchanged.
- Indented Cookie lines remain unchanged.
- Folded Cookie headers remain unchanged. If an exact `Cookie:` line is immediately followed by a physical line beginning with a space or tab, leave the entire folded form unchanged and do not sanitize only the first physical line.
- Full folded-header parsing is deferred.
- Full HTTP body-boundary parsing is deferred.
- Cookie-name classification is deferred to milestone 4.

Approved milestone 3 markers:

```text
<REDACTED:cookie.value>
<REDACTED:cookie.header>
```

Approved milestone 3 rule IDs:

```text
cookie.value
cookie.header
```

Marker policy:

- An exact approved Cookie marker used as a complete individual cookie value is already sanitized and produces no finding.
- An exact approved Cookie marker used as the complete trimmed Cookie header value is already sanitized and produces no finding.
- This applies even when the marker is used in an unexpected Cookie context.
- The sanitizer must not correct or normalize wrong-context markers.
- A marker embedded inside a larger raw value is not already sanitized and must be redacted.
- Trailing spaces and tabs after exact markers are preserved.
- Repeated sanitization must produce byte-identical output.

Reporting semantics:

- `cookie.value` counts each individual cookie value actually replaced.
- `cookie.header` counts each Cookie header line changed through fallback.
- A fallback header must not also increment `cookie.value`.
- Already-redacted values produce no count.
- Empty headers produce no count.
- Cookie names must never become rule IDs.
- Reports, CLI output, errors, logs, and snapshots must never include cookie values or source excerpts.

Cookie-name disclosure:

- Milestone 3 intentionally preserves safely parsed cookie names.
- Preserved names may reveal framework details, authentication mechanisms, identity concepts, tenancy concepts, and application internals.
- Examples include `ASP.NET_SessionId`, `JSESSIONID`, `username`, `email`, `customerId`, `tenant`, and `portalAuth`.
- Preserving names is approved because it provides useful penetration-testing evidence context while values are removed.
- Milestone 3 must not classify or selectively hide cookie names.
- Milestone 4 will define deterministic name categories such as sensitive, telemetry, harmless, and unknown.

Control-character behavior:

- NUL remains rejected by the existing input-validation path.
- CR and LF remain line delimiters, not Cookie-value characters.
- Other unsupported control characters inside a Cookie value trigger whole-header fallback rather than a new global error.

Accepted milestone 3 limitations:

- Exact header-like Cookie lines inside message bodies may be sanitized.
- Full HTTP body-boundary parsing remains deferred.
- Folded or indented Cookie header lines remain unsupported and unchanged.
- Folded Cookie headers may retain sensitive values.
- `Set-Cookie` remains out of scope.
- Cookie names may disclose application structure.
- Cookie-name classification is deferred to milestone 4.
- The tool does not guarantee detection of every possible secret.
- Marker collisions are accepted and handled deterministically.

### Milestone 3 Acceptance Criteria

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
- Folded Cookie forms remain completely unchanged.
- Approved Cookie markers are idempotent as individual values and as complete trimmed header values.
- Embedded Cookie markers inside larger raw values are redacted.
- Rule counts use only `cookie.value` and `cookie.header` for Cookie findings.
- `cookie.value` counts each individual cookie value actually replaced, and `cookie.header` counts each Cookie header line changed through fallback.
- Cookie names never become rule IDs and are not included in reports as dynamic identifiers.
- Reports, CLI output, exceptions, logs, tests, and snapshots do not include cookie values or source excerpts.
- Cookie-name classification, sensitive/telemetry/harmless/unknown categories, telemetry allowlists, selective value preservation, and `Set-Cookie` sanitization are not implemented.
- No new dependency, configuration file, plugin, network behavior, telemetry, LLM behavior, persistence, full HTTP parsing, folded-header parsing, directory processing, overwrite mode, or exit code is introduced.
- Existing source immutability, output collision, dry-run, UTF-8, UTF-8 BOM, LF, CRLF, mixed-newline, final-newline, 10 MiB, NUL-byte, safe-error, and exit-code behavior remains unchanged.
- Tests use only synthetic data.

### Milestone 3 Verification Requirements

Expected commands:

```bash
uv sync
uv run evidence-sanitizer --help
uv run python -m evidence_sanitizer --help
uv run evidence-sanitizer sanitize --help
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```

Required unit test coverage:

- Supported per-value Cookie parsing.
- Case-insensitive Cookie header matching.
- Header-name casing and spacing preservation.
- Formatting preservation around `:`, `;`, and `=`.
- Empty values.
- Values containing additional `=`, commas, colons, and slashes.
- Duplicate names and original order preservation.
- Non-ASCII values.
- Empty header and whitespace-only header unchanged.
- Missing `=`, empty names, leading semicolons, trailing semicolons, consecutive semicolons, and malformed mixed segments trigger fallback.
- Quoted values, escaped quoted values, and semicolons inside quoted values.
- Malformed quoted syntax, missing closing quote, dangling escape, and junk after closing quote trigger fallback.
- Existing Cookie value markers and header markers remain idempotent.
- Mixed raw and already-redacted values.
- Embedded Cookie markers are redacted.
- `Set-Cookie` non-match.
- `X-Cookie` non-match.
- Indented and folded Cookie forms remain unchanged.
- Unicode cookie-name fallback and unsupported control-character fallback.
- Multiple Cookie headers and counts.
- Cookie findings do not overlap with Authorization findings.
- Performance coverage only if the chosen parser creates realistic risk.

Required application and CLI test coverage:

- Cookie plus Bearer plus Basic plus custom Authorization in one file.
- Correct fixed counts for `authorization.bearer`, `authorization.basic`, `authorization.other`, `cookie.value`, and `cookie.header`.
- No cookie values in reports, CLI output, errors, or snapshots.
- Source remains byte-for-byte unchanged.
- Dry-run creates no output.
- Existing output is not overwritten.
- BOM and newline preservation remain unchanged.
- Mixed line endings remain unchanged.
- No-final-newline behavior remains unchanged.
- Full fallback behavior.
- Idempotence.
- Existing Authorization regression coverage remains passing.
- Existing exit-code behavior remains unchanged.
- Console-script and module entry points remain consistent.

## Future Milestones

Future milestones are deferred and must be approved before implementation.

Possible future topics:

- Cookie-name classification after deterministic categories are approved.
- `Set-Cookie` header redaction after false-positive behavior is defined.
- Additional deterministic HTTP header rules, such as selected API-key headers.
- Email or client-identifier redaction after scope and false-positive behavior are defined.
- Optional machine-readable safe report format.
- More precise parsing for structured evidence formats.
- Directory processing with explicit partial-failure semantics.
- More robust atomic-output strategy.
- Optional stable pseudonymous replacements if approved.
- Performance improvements if the 10 MiB limit becomes too restrictive.

## Functionality Explicitly Deferred

- `Set-Cookie` sanitization.
- Cookie-name classification, including sensitive, telemetry, harmless, and unknown categories.
- Telemetry allowlists and selective cookie-value preservation.
- API-key-specific header sanitization.
- Email redaction.
- Client-identifier redaction.
- Full HTTP header/body parsing.
- Folded-header parsing.
- Directory recursion.
- Multiple input files.
- Configuration files.
- User-defined rules.
- Plugin system.
- LLM-assisted detection.
- Network integrations.
- Telemetry.
- Persistence.
- Debug mode.
- Overwrite mode.
- Atomic replacement guarantee.
- Metadata preservation.
- Comprehensive hard-link, junction, mount-point, or adversarial race handling.
- Generalized overlap-resolution system.
- Broad binary-file detection.
- Guaranteeing removal of every secret.
