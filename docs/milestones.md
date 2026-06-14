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

## Future Milestones

Future milestones are deferred and must be approved before implementation.

Possible future topics:

- Cookie or Set-Cookie header redaction after false-positive behavior is defined.
- Additional deterministic HTTP header rules, such as selected API-key headers.
- Email or client-identifier redaction after scope and false-positive behavior are defined.
- Optional machine-readable safe report format.
- More precise parsing for structured evidence formats.
- Directory processing with explicit partial-failure semantics.
- More robust atomic-output strategy.
- Optional stable pseudonymous replacements if approved.
- Performance improvements if the 10 MiB limit becomes too restrictive.

## Functionality Explicitly Deferred

- Cookie and Set-Cookie sanitization.
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
