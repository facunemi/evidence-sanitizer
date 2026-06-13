# AGENTS.md

## Project Purpose

`evidence-sanitizer` is a local-first defensive CLI for creating sanitized copies of authorized penetration-testing evidence. It must never modify source evidence in place and must never send evidence over the network.

## Development Principles

- Read the relevant files in `docs/` before editing behavior.
- Keep changes small, explicit, and testable.
- Do not add speculative abstractions, plugin systems, configuration frameworks, async processing, databases, telemetry, network features, or LLM detection.
- Prefer standard library behavior unless a dependency has a concrete approved purpose.
- Introduce modules only when implementation responsibilities justify them.

## Security Rules

- Source evidence must be read-only from the tool's perspective.
- Never log, print, snapshot, or include detected values or evidence contents in exceptions, reports, debug output, or tests.
- Tests must use synthetic data only.
- New behavior must include tests.
- Existing output paths must not be overwritten.
- Dry-run behavior must not create output files.

## Scope Discipline

- Milestone 0 contains no sanitizer implementation.
- Milestone 1 contains only the HTTP-style `Authorization: Bearer` rule.
- Do not add additional rules, directory processing, overwrite mode, metadata preservation, or atomic-output guarantees without an approved spec change.
- Deferred decisions must remain marked as deferred instead of being silently implemented.

## Expected Verification Commands

These commands are placeholders until milestone 0 creates packaging and tooling configuration:

```bash
uv sync
uv run evidence-sanitizer --help
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```
