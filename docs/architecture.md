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

Do not create modules such as `paths.py`, `reporting.py`, `textio.py`, `engine.py`, or `rules/` merely because they might be useful later. Their creation should be justified by concrete milestone 1 implementation responsibilities.

## Data Flow

Milestone 1 data flow:

1. Typer parses `sanitize INPUT --output OUTPUT [--dry-run]`.
2. The command validates the input path, output path, and output parent directory.
3. The command rejects a destination that already exists.
4. The command rejects a destination that resolves to the input file.
5. The command reads the complete input file in memory, up to 10 MiB.
6. The command rejects NUL bytes.
7. The command decodes strict UTF-8 or UTF-8 with BOM.
8. The sanitizer applies the single `authorization.bearer` rule.
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

- `rule_id`: stable identifier, such as `authorization.bearer`.
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

## Bearer Authorization Rule

Milestone 1 supports only HTTP-style authorization header lines:

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

The rule must produce non-overlapping findings. If overlapping findings occur in milestone 1, treat that as an internal sanitization error rather than designing a generalized overlap system prematurely.

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
