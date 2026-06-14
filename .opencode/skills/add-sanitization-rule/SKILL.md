---
name: add-sanitization-rule
description: Use only when planning, specifying, implementing, reviewing, or verifying deterministic sanitization rules in the evidence-sanitizer repository.
---

# Add Sanitization Rule

## Purpose

Use this skill only for deterministic sanitization-rule work in this repository. It coordinates safe planning, specification, implementation, independent review, verification, and commit preparation. It does not define future rule semantics, grant edit permission by itself, or replace `AGENTS.md` and `docs/`.

Future rule semantics require human approval and approved specifications before implementation.

## When To Use

Use when the user asks to plan, specify, implement, review, verify, or prepare a commit for a deterministic sanitization rule in `evidence-sanitizer`.

Do not use this skill for unrelated CLI, packaging, dependency, OpenCode configuration, or documentation-only work unless that work directly supports a sanitization rule.

Do not copy existing rule semantics into future rules. Existing rule work is evidence for workflow lessons only: specify behavior first, preserve safety invariants, test idempotence, avoid value leaks, and keep the architecture minimal.

## Required First Reads

Before rule work, read the current relevant context:

- `AGENTS.md`
- `docs/product-spec.md`
- `docs/architecture.md`
- `docs/security-model.md`
- `docs/milestones.md`
- relevant implementation under `src/evidence_sanitizer/`
- relevant tests under `tests/`
- current Git status and diff when applicable

For implementation and review, inspect actual files and diffs, not summaries.

## Source Of Truth

Current approved specifications and explicit user instructions are authoritative. If this skill conflicts with `AGENTS.md`, `docs/`, or the user's current prompt, follow the approved specifications and explicit prompt constraints.

This skill is process guidance only. It must not silently approve deferred behavior, invent rule semantics, or override milestone scope.

## Determine The Requested Stage

Infer the workflow stage from the user's prompt.

Planning signals include `plan`, `analyze`, `design`, `compare strategies`, `read-only`, or `do not modify files`. Planning behavior: inspect only, identify semantic decisions and risks, propose specification changes and tests, and modify nothing.

Specification signals include `update specs`, `encode approved behavior`, or `modify documentation only`. Specification behavior: edit only explicitly approved documentation, do not implement, perform cross-document consistency checks, and do not commit automatically.

Implementation signals include `implement`, `build`, or `add the specified rule`. Implementation behavior: treat specifications as authoritative, modify only objectively necessary production and test files, stop rather than expanding scope, run the complete verification suite, and do not commit automatically.

Independent review signals include `review`, `audit`, `reassess`, or `inspect implementation`. Review behavior: stay read-only, inspect actual code and tests, report findings by severity, distinguish required corrections from optional improvements, and do not demand deferred functionality.

Verification or commit-preparation signals include `verify`, `run checks`, `prepare commit`, or `inspect staged changes`. Verification behavior: run or recommend approved checks, use synthetic manual examples, inspect generated and staged files, and create no commit unless explicitly requested.

If stage ambiguity would change edit permissions, stop and ask for clarification.

## Common Rule-Design Checklist

Every new rule design must explicitly address:

- exact sensitive value being protected
- milestone scope
- non-goals and deferred behavior
- positive-match grammar
- unchanged, malformed, unsupported, and ambiguous cases
- deterministic rule ID and replacement marker
- whether surrounding structure is preserved
- idempotence and already-redacted values
- marker collisions and markers in unexpected contexts
- overlap and ordering with existing rules
- finding and report count semantics
- false positives and false negatives
- encoding and newline preservation
- realistic performance risks
- unit, application, CLI, and regression tests where relevant

Do not force regex. Choose a bounded regex, small parser, or deterministic scanner based on the syntax. Require performance tests only when the chosen mechanism creates realistic risk, such as catastrophic backtracking or unbounded parsing behavior.

## Global Security Invariants

Preserve these unless approved specifications explicitly change them:

- original evidence is never modified
- output is never overwritten
- dry-run creates no output or temporary files
- processing remains local
- no network, telemetry, LLM detection, persistence, plugins, or user configuration
- findings never store original detected values
- reports use fixed safe identifiers and counts
- detected values and source excerpts never appear in CLI output, reports, logs, safe errors, rendered tracebacks, snapshots, or test messages
- tests use only synthetic values
- replacements are deterministic and repeated sanitization is idempotent
- findings do not overlap and replacements apply right-to-left
- existing UTF-8, BOM, newline, NUL-byte, size-limit, safe-error, path-safety, output-creation, and exit-code behavior remains unchanged unless explicitly respecified
- every new rule receives regression testing against existing rules

Do not claim secure memory erasure or that sensitive bytes become unreachable from interpreter memory, debugger access, or process inspection.

## Architecture Guardrails

Use the smallest architecture justified by the current milestone.

- Prefer extending the existing concrete design while responsibilities remain cohesive.
- Do not extract modules merely because future rules may exist.
- Do not create a `rules/` package without a concrete current responsibility.
- Do not introduce registries, plugins, protocols, factories, dependency injection, inheritance hierarchies, generalized precedence systems, async processing, or generalized configuration without an approved requirement.
- Do not create dynamic rule IDs from user input, header names, scheme names, or detected values.
- New constants and helpers must serve current implemented behavior.
- If simple non-overlapping findings cannot be guaranteed, stop and report rather than inventing an overlap framework.

## Planning Stage

Planning is read-only. A planning response must include:

- proposed scope
- strategy alternatives and trade-offs
- recommended semantics
- supported, unsupported, and deferred cases
- rule ID and marker proposal
- idempotence policy
- overlap analysis
- reporting semantics
- architecture impact
- exact files expected to change
- test plan
- security risks and residual limitations
- specification changes required
- human decisions requiring approval
- confirmation that no files were modified

## Specification Stage

Encode only approved semantic decisions. Modify only explicitly approved documentation files. Keep rule IDs, markers, limitations, and acceptance criteria consistent across documents, and make acceptance criteria objectively testable.

Do not change Python implementation or tests. Do not create a commit automatically. If behavior is not approved, stop instead of writing speculative specifications.

Final report: documents modified, decisions encoded, consistency checks, remaining ambiguities, and confirmation that implementation files were untouched.

## Implementation Stage

Read the specifications again immediately before editing. Implement the narrowest specified behavior and preserve unrelated behavior.

Add applicable tests for positive, negative, malformed, idempotent, overlap, leakage, encoding, newline, application, CLI, and existing-rule regression behavior. Keep findings value-free. Avoid assertions and failure messages that echo detected values.

Never decode, normalize, log, or retain sensitive values unless approved behavior objectively requires transformation. Stop if safe handling is uncertain.

Run the approved verification suite, inspect the final diff, do not change docs unless explicitly requested, and do not create a commit automatically.

## Independent Review Stage

Review is read-only and must inspect actual files and diffs.

Check semantic compliance, positive and negative grammar, idempotence, marker behavior, overlaps, report counts, value-free findings, leak paths, error handling, encoding and newline preservation, source immutability, dry-run, exclusive output behavior, regressions, architecture scope, test quality, and generated or tracked artifacts.

Report findings in this order, omitting empty sections: Blocking, High, Medium, Low, Informational.

For every finding include file and exact location, requirement affected, explanation, realistic impact, recommended correction, and whether correction is required before commit.

End with `PASS` or `FAIL`, corrections required before commit, optional deferred improvements, readiness for local verification, and confirmation that no files were modified.

## Verification Stage

Run or recommend these as applicable:

```text
uv sync
uv run evidence-sanitizer --help
uv run python -m evidence_sanitizer --help
uv run evidence-sanitizer sanitize --help
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```

Use only synthetic manual examples. Manual verification should cover expected redaction, original input unchanged, dry-run behavior, idempotence, output collision where relevant, report counts, and absence of sensitive values from safe output.

Do not place real penetration-testing evidence or real credentials in tests or manual examples.

## Commit Preparation

Inspect `git status` plus staged and unstaged diffs. Remove synthetic temporary files. Ensure caches, bytecode, evidence samples, and generated artifacts are not staged.

Stage only intended files. Keep specification and implementation commits separate when specifications changed. Suggest a concise commit message. Create the commit only when the user explicitly requests it.

## Stop Conditions

Stop and report rather than guess when:

- rule semantics are ambiguous
- behavior is not approved by specifications
- the prompt conflicts with specifications
- the requested operation exceeds the current milestone
- a protected invariant must change
- an excluded file appears necessary
- a new dependency appears necessary
- safe handling or leakage prevention cannot be guaranteed
- simple non-overlapping behavior cannot be achieved
- implementation would require speculative architecture
- edit permission is unclear
- the user requests implementation while the active mode is read-only or plan-only

A stop report must identify the conflict, why proceeding would be unsafe or speculative, and the smallest decision or specification change needed.

## Required Final Reports

Planning final report: scope, recommendation, decisions requiring approval, risks, proposed files, and confirmation of no edits.

Specification final report: documents modified, decisions encoded, consistency checks, ambiguities, and confirmation that implementation files were untouched.

Implementation final report: files modified, behavior implemented, tests added or changed, verification results, deviations, and current Git status.

Review final report: findings by severity, verdict, required corrections, optional improvements, readiness for verification, and confirmation of no edits.

Verification and commit-preparation final report: commands run, results, manual checks, files staged or excluded, remaining failures, and commit recommendation.

## Example: Future Cookie Planning

Prompt:

```text
Use the add-sanitization-rule skill to plan request Cookie header sanitization.
Do not include Set-Cookie.
Work read-only.
```

Expected behavior: read the current specifications, recognize that this topic is deferred, compare narrow deterministic strategies without selecting unapproved semantics, identify questions such as whole-value versus per-cookie replacement, propose candidate rule ID, marker, idempotence, malformed-input handling, reporting, architecture, and tests for human approval, recommend specification updates, modify nothing, and refuse implementation until behavior is approved and encoded in the specifications.
