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

## Non-Goals

- In-place modification of evidence.
- Directory processing in milestone 1.
- Binary file sanitization.
- Guaranteed detection of every secret.
- Heuristic binary classification beyond NUL-byte rejection and strict UTF-8 decoding failure.
- Preservation of permissions, ownership, timestamps, ACLs, extended attributes, or other metadata.
- Network features, telemetry, update checks, sync, or remote scanning.
- LLM-based detection or replacement.
- User-defined rules, configuration files, or plugins in the first version.
- Database storage.
- Web application features.
- Debug mode.
- Comprehensive defense against adversarial filesystem races, junction attacks, or hard-link attacks in milestone 1.

## User Stories

- As a tester, I can sanitize `request.txt` into `request.sanitized.txt` while leaving `request.txt` unchanged.
- As a tester, I can run dry-run mode and see that `authorization.bearer` matched once without seeing the token.
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
