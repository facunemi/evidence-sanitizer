# evidence-sanitizer

Local-first CLI for sanitizing authorized pentest evidence before pasting it into reports, tickets, notes, PoCs, or sharing it internally.

## Why This Exists

Penetration testers and application security engineers often need to share evidence while protecting credentials, tokens, signatures, and other secrets. `evidence-sanitizer` creates a sanitized copy of one text file at a time, replacing known sensitive values with deterministic markers and reporting which rule families triggered, without ever exposing the detected values.

It is intentionally small, deterministic, and best-effort within documented rules. It is not a complete DLP system and does not guarantee removal of every secret.

## What It Sanitizes

The current rule families cover common HTTP-style evidence:

| Rule ID | Marker | Applies to |
| --- | --- | --- |
| `authorization.bearer` | `<REDACTED:authorization.bearer>` | `Authorization: Bearer` credentials |
| `authorization.basic` | `<REDACTED:authorization.basic>` | `Authorization: Basic` credentials |
| `authorization.other` | `<REDACTED:authorization.credentials>` | Other syntactically valid `Authorization` schemes |
| `cookie.value` | `<REDACTED:cookie.value>` | Individual `Cookie` values in safely parsed headers |
| `cookie.header` | `<REDACTED:cookie.header>` | Whole `Cookie` header fallback when safe parsing fails |
| `header.secret` | `<REDACTED:header.secret>` | Selected sensitive API/auth header values |
| `query.secret` | `<REDACTED:query.secret>` | Selected sensitive URL query parameter values |
| `json.value` | `<REDACTED:json.value>` | String values of approved sensitive JSON field names |
| `form.value` | `<REDACTED:form.value>` | Raw values of approved sensitive form-urlencoded field names |

Reports use fixed rule IDs and counts only. They never include raw detected values, source excerpts, field names, or custom names.

## Safety Model

- The source/input file is never modified in place.
- Output is written to a separate, explicitly provided path.
- Existing output files are not overwritten.
- The output parent directory must already exist.
- `--dry-run` performs detection and reporting but writes no output file.
- Reports include fixed rule IDs and counts only.
- Detected raw values are not included in reports or CLI output.
- Redaction markers are deterministic and idempotent.
- Processing is local-only; no network, telemetry, LLM behavior, plugins, persistence, or config files are used.
- Supported input is strict UTF-8 or UTF-8 with BOM.
- Maximum input size is 10 MiB.
- NUL bytes are rejected.
- UTF-8 BOM presence, LF/CRLF/mixed newlines, and final-newline state are preserved.

## Installation

This project uses [uv](https://docs.astral.sh/uv/). Clone the repository and install dependencies locally:

```powershell
uv sync
uv run evidence-sanitizer --help
```

No published package install is required for local development.

## Quick Start

Sanitize one evidence file:

```powershell
uv run evidence-sanitizer sanitize evidence.txt --output evidence.sanitized.txt
```

Preview what would trigger without creating output:

```powershell
uv run evidence-sanitizer sanitize evidence.txt --output evidence.sanitized.txt --dry-run
```

You can also invoke the package as a module:

```powershell
uv run python -m evidence_sanitizer sanitize evidence.txt --output evidence.sanitized.txt
```

## Examples

Examples use only synthetic values and reserved domains such as `example.test`.

### Authorization Headers

Input:

```http
Authorization: Bearer synthetic-bearer-token
Authorization: Basic synthetic-basic-token
Authorization: AMX app:signature:nonce
```

Output:

```http
Authorization: Bearer <REDACTED:authorization.bearer>
Authorization: Basic <REDACTED:authorization.basic>
Authorization: AMX <REDACTED:authorization.credentials>
```

### Cookies

Input:

```http
Cookie: session=synthetic-session-cookie; _ga=synthetic-telemetry-id; theme=dark; unknown=synthetic-value
```

Output:

```http
Cookie: session=<REDACTED:cookie.value>; _ga=<REDACTED:cookie.value>; theme=dark; unknown=<REDACTED:cookie.value>
```

### Sensitive Headers

Input:

```http
X-API-Key: synthetic-api-key
X-Auth-Token: synthetic-auth-token
```

Output:

```http
X-API-Key: <REDACTED:header.secret>
X-Auth-Token: <REDACTED:header.secret>
```

### Query Parameters

Input:

```http
GET /api/profile?access_token=synthetic-token&sig=synthetic-signature&theme=dark HTTP/1.1
```

Output:

```http
GET /api/profile?access_token=<REDACTED:query.secret>&sig=<REDACTED:query.secret>&theme=dark HTTP/1.1
```

### JSON Sensitive Fields

Input:

```json
{"access_token":"synthetic-access-token","refresh_token":"synthetic-refresh-token","token_type":"Bearer","client_secret":"synthetic-client-secret","user_id":"user-123"}
```

Output:

```json
{"access_token":"<REDACTED:json.value>","refresh_token":"<REDACTED:json.value>","token_type":"Bearer","client_secret":"<REDACTED:json.value>","user_id":"user-123"}
```

Only direct string values of approved field names are redacted. Numbers, booleans, null, arrays, and object values are left unchanged. Existing broader findings such as `Authorization: Bearer` remain authoritative.

### Form-URL-Encoded Bodies

Input:

```http
Content-Type: application/x-www-form-urlencoded

access_token=synthetic-token&client_secret=synthetic-secret&grant_type=authorization_code
```

Output:

```http
Content-Type: application/x-www-form-urlencoded

access_token=<REDACTED:form.value>&client_secret=<REDACTED:form.value>&grant_type=authorization_code
```

Form scanning is gated by a line-start `Content-Type: application/x-www-form-urlencoded` header followed by a blank separator line. Only the immediate first physical line after the separator is scanned. Deferred names such as `grant_type`, `scope`, `code`, and `username` remain unchanged. No percent-decoding or plus-decoding is performed.

### Golden Fixtures

The repository includes synthetic golden fixtures under `tests/fixtures/golden/`. Each fixture pairs an `.input.txt` file with a matching `.expected.txt` file showing the sanitized output.

These fixtures use reserved domains such as `example.test`, `api.example.test`, `mobile.example.test`, and `callback.example.test`, and obvious synthetic secret placeholders. They demonstrate realistic before/after evidence for:

- `http_request_mixed` - realistic raw HTTP request.
- `burp_repeater_like` - proxy/repeater-style request, including folded Cookie behavior.
- `api_log_mixed` - line-oriented API gateway log excerpt.
- `mobile_api_trace_like` - mobile/debug trace.
- `report_note_mixed` - human-written notes mixing prose and snippets.
- `edge_cases_markers_and_malformed_cookie` - idempotence, markers, malformed Cookie fallback, and overlap behavior.
- `json_api_body_mixed` - JSON body with sensitive field values and an overlapping Authorization header.
- `form_urlencoded_body_mixed` - form-urlencoded bodies with approved fields, deferred fields, nested query overlap, and idempotence.

## CLI Usage

```text
evidence-sanitizer sanitize INPUT --output OUTPUT [--dry-run]
```

- `INPUT` is the path to the evidence text file to sanitize.
- `--output OUTPUT` is the path where the sanitized copy will be written.
- `--dry-run` reports rule counts without creating the output file.

## Reports And Rule IDs

Successful sanitization prints the output path and a safe report:

```text
Sanitized: evidence.txt -> evidence.sanitized.txt
Rules triggered:
authorization.bearer: 1
cookie.value: 1
header.secret: 1
query.secret: 2
json.value: 3
```

Dry run:

```text
Dry run: no output written
Rules triggered:
authorization.bearer: 1
```

When no rules trigger:

```text
Rules triggered: none
```

Reports contain only fixed rule IDs and counts. They never include detected values, source excerpts, header names, cookie names, or parameter names.

## Limitations

This tool is best-effort within its documented rules. Unsupported formats and patterns may retain secrets, including but not limited to:

- Multipart parsing.
- XML parsing.
- HTML/JavaScript parsing.
- Full JSON parsing, validation, or reserialization; JSON support is conservative raw JSON-like string-key/string-value scanning.
- Non-string direct JSON values such as numbers, booleans, null, arrays, or objects. Nested approved string fields may still redact when matched as their own JSON-like pairs.
- Form scanning is Content-Type-gated to `application/x-www-form-urlencoded`; raw form strings without a supported Content-Type line are not scanned.
- Only the immediate first physical line after the blank header/body separator is scanned; multi-line or wrapped form bodies are not supported.
- No percent-decoding or plus-decoding of form field names or values.
- Semicolon-separated form fields are not supported; `&` is the only form separator.
- No full HTTP parser, Content-Length-based body parsing, or chunked-transfer decoding.
- Recursive URL parsing.
- URL decoding or re-encoding.
- Percent-encoded query parameter names.
- `Set-Cookie` header sanitization.
- `Proxy-Authorization` sanitization.
- Folded or indented supported headers, which may remain unchanged.
- Directory scanning or batch processing.
- Entropy-based secret detection.
- Arbitrary regex, configurable, or user-defined rules.

There is no guarantee of complete secret removal. Atomic output replacement is not guaranteed; abrupt termination may leave a partial output file. File metadata preservation is not provided.

## Development Commands

```powershell
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
git diff --check
```

## Roadmap

Potential future work:

- Proxy-Authorization and selected signature headers
- Optional JSON report output

Roadmap items are tentative and subject to explicit approval before implementation. They are not current behavior. Unsupported formats may retain secrets until they are explicitly specified, implemented, and tested.

## Responsible Use

This tool is intended for authorized security testing and internal evidence handling only. Users are responsible for reviewing sanitized output before sharing it. Do not use `evidence-sanitizer` as a substitute for manual review or organizational data handling requirements.

## License

MIT License. See `LICENSE`.
