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

## Future Milestones

Future milestones are deferred and must be approved before implementation.

Possible milestone 2 topics:

- Additional deterministic HTTP header rules, such as selected API-key headers.
- Cookie header redaction after false-positive behavior is defined.
- Optional machine-readable safe report format.
- More precise parsing for structured evidence formats.

Possible milestone 3 topics:

- Directory processing with explicit partial-failure semantics.
- More robust atomic-output strategy.
- Optional stable pseudonymous replacements if approved.
- Performance improvements if the 10 MiB limit becomes too restrictive.

## Functionality Explicitly Deferred

- Directory recursion.
- Multiple input files.
- Configuration files.
- User-defined rules.
- Plugin system.
- LLM-assisted detection.
- Network integrations.
- Telemetry.
- Debug mode.
- Overwrite mode.
- Atomic replacement guarantee.
- Metadata preservation.
- Comprehensive hard-link, junction, mount-point, or adversarial race handling.
- Generalized overlap-resolution system.
- Broad binary-file detection.
- Guaranteeing removal of every secret.
