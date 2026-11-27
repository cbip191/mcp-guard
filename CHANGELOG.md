# Changelog

All notable changes to `@4sails/mcp-guard` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`mcp-guard init`, `mcp-guard.schema.json` & `mcp-guard policy test` (`src/policy.mjs`, `bin/mcp-guard.mjs`, `mcp-guard.schema.json`):** Packaged JSON Schema Draft 2020-12 (`mcp-guard.schema.json`) with `$schema` support in `validatePolicy`, added `POLICY_PRESETS` & `generateStarterPolicy()` (`default`, `github`, `jira`, `slack`, `strict`), `mcp-guard init [--preset ...] [--force]`, and `mcp-guard policy test <policy.json> <tool> [jsonArgs] [--json]` offline debugger.
- **Real-world MCP compatibility & Windows `npx` support (`src/proxy.mjs`, `src/http-proxy.mjs`, `test/compat.test.mjs`, `scripts/smoke-real-mcp.mjs`):** Added `resolveSpawnSpec()` for safe Windows `.cmd`/`.bat` shim spawning (`npx`, `npm`, `pnpm`, `yarn`, `corepack`), added MCP `2025-03-26` lifecycle, Streamable HTTP OAuth `401`/`WWW-Authenticate`/`Mcp-Session-Id`/`Last-Event-ID`, and live Windows `.cmd` CI compatibility tests, plus `scripts/smoke-real-mcp.mjs` for live verification against `@modelcontextprotocol/server-filesystem`.
- **Custom redaction rules, rule suppression & allowlist patterns (`src/redact.mjs`, `src/policy.mjs`):** Added `compileSafeRegex()` (syntax, flag, nested-quantifier, and adversarial ReDoS probe guard), `redaction.disabledRules` (validated against built-in rule IDs), `redaction.customRules` (always one-way `[REDACTED:<ID>]`), and `redaction.allowPatterns` across `redactText`, `redactPayload`, `guardMcpResponse`, `mcp-guard.json`, stdio proxy, and HTTP/SSE proxy.
- **Automated npm OIDC provenance release workflow (`.github/workflows/release.yml`):** Tag-triggered (`v*.*.*`) GitHub Actions workflow verifying `tag === v<package.json.version>`, running `npm run check && npm test && npm run demo`, and publishing with `npm publish --provenance --access public` via npm OIDC Trusted Publishing (zero long-lived npm secrets), documented in `CONTRIBUTING.md` and `SECURITY.md`.

### Fixed
- **Streamable HTTP OAuth 2.1 compatibility (`src/http-proxy.mjs`):** Preserved exact HTTP status codes on empty-body non-2xx responses (such as `401 Unauthorized` + `WWW-Authenticate` discovery challenges, previously rewritten to `204`) and routed RFC 9728 `/.well-known/*` OAuth discovery requests to the upstream origin root instead of nesting under the upstream MCP path.

## [0.4.1] - 2026-11-27

### Documentation
- Switched `README.md` Quickstart, `mcp.json`, CLI, and Programmatic API examples to the published `@4sails/mcp-guard` npm package (`npx -y @4sails/mcp-guard`).
- Added an explicit **Threat Model & Non-Goals** section to `README.md` and added the `v1.0.0` production-readiness roadmap (`#24`–`#29`) to `ROADMAP.md`.

## [0.4.0] - 2026-11-27

### Added
- **Session-scoped deterministic PII pseudonymization & broader PII (`src/pseudonymize.mjs`, `src/redact.mjs`):** Added `createPiiPseudonymizer()`, `PII_PSEUDONYM_PREFIX`, `--pseudonymize-pii` (CLI `proxy`, `http-proxy`, `scan`, `wrap`), and `redaction.pseudonymizePii` policy support mapping PII consistently per session (`[EMAIL_1]`, `[EMAIL_2]`, `[PHONE_1]`, `[CARD_1]`, `[SSN_1]`, `[IBAN_1]`) while keeping all secrets strictly one-way redacted (`[REDACTED:...]`). Added Luhn-validated `CREDIT_CARD` (`isValidLuhn`), SSA-validated `US_SSN`, and ISO 13616 MOD-97 `IBAN` (`isValidIban`) detectors verified with `0/350` false positives on the Apache Kafka corpus and `<50 ms` on 50 KB ReDoS inputs.
- **`mcp-guard wrap` / `unwrap` auto-installer (`src/wrap.mjs`, `bin/mcp-guard.mjs`):** Added idempotent `wrapMcpConfig`, `unwrapMcpConfig`, `isWrappedServer`, `formatJsonDiff`, and `applyMcpConfigTransform` supporting Cursor, Claude Desktop, Claude Code (`.mcp.json`), and VS Code (`servers`), defaulting to `--dry-run` diff preview, creating `.bak` backups on `--apply`, and supporting `--local` and `--server` filtering.
- **Streamable HTTP / SSE MCP transport proxy (`src/http-proxy.mjs`, `bin/mcp-guard.mjs`):** Added `mcp-guard http-proxy --upstream https://... --port 8787` (`startHttpProxy`, `createSseParser`, `encodeSseEvent`) built with zero-dep `node:http` and `fetch`, binding to `127.0.0.1` by default, supporting JSON `POST`, Streamable HTTP & legacy `GET` SSE streaming, `DELETE` session termination, `/_mcp-guard/health`, `413` body-size enforcement, and reusing the full `mcp-guard.json` policy, redaction, taint/blocking, and JSONL `--audit-log` core.

## [0.3.0] - 2026-11-27

### Added
- **Declarative `mcp-guard.json` policy engine (`src/policy.mjs`, `src/proxy.mjs`, `bin/mcp-guard.mjs`):** Added `--policy <mcp-guard.json>` (or `MCP_GUARD_POLICY`) with strict fail-closed schema validation, linear-time `matchGlob`, `tools.allow` / `tools.deny` globs, fail-closed `tools.argConstraints` (supporting exact values, globs, and nested dot paths), per-tool secret field allowlists (`tools.allowSecretFields` via `redactPayload` `skipPaths`), JSON-RPC `-32002` pre-execution blocking, and portable shared ACL vectors (`test/fixtures/acl-vectors.json`).
- **Structured JSONL audit logging (`src/audit.mjs`, `src/proxy.mjs`, `bin/mcp-guard.mjs`):** Added `--audit-log <path.jsonl>` emitting append-only `{ ts, dir, method, tool, action, rules, secretHashes, latencyMs }` records (owner-only `0600` permissions on POSIX, one-way `sha256:` secret fingerprints via `hashSecret()`, never raw secrets/previews/snippets, and automatic `tools/call` request→response tool correlation) plus `mcp-guard audit <logfile|-> [--json]` terminal/JSON summary CLI.

### Security
- **Bounded frame parser (`src/proxy.mjs`):** Added `DEFAULT_MAX_FRAME_BYTES` (`16 MiB`, configurable via `maxFrameBytes`) to `createFrameParser` so runaway NDJSON lines without newlines or oversized `Content-Length` headers are discarded in O(1) memory instead of causing unbounded buffering.
- **CI-safe `scan` output (`bin/mcp-guard.mjs`):** `mcp-guard scan` now omits secret `preview` substrings by default (emitting `sha256:` hashes only) so public CI logs never leak partial credentials; pass `--show-previews` for local debugging.

## [0.2.0] - 2026-11-26

### Added
- **Expanded secret & AI-provider detection (`src/redact.mjs`):** Added `AWS_SECRET_ACCESS_KEY`, `ATLASSIAN_API_TOKEN`, `GITLAB_PAT`, `GCP_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `OPENROUTER_API_KEY`, `GROQ_API_KEY`, `HUGGINGFACE_TOKEN`, `PERPLEXITY_API_KEY`, `XAI_API_KEY`, `NPM_TOKEN`, `PYPI_TOKEN`, encrypted & truncated PEM private key blocks, and context-anchored Shannon entropy detection (`HIGH_ENTROPY_SECRET`, `shannonEntropy()`).
- **Bidirectional stdio MCP proxy (`src/proxy.mjs`):** Full inspection of both `agent → MCP` (`stdin`) and `MCP → agent` (`stdout`), dual NDJSON + `Content-Length` framing with UTF-8 byte-length recalculation, JSON-RPC batch support, and mock-server E2E test suite (`test/proxy.test.mjs`).
- **Opt-in outbound PII redaction (`--redact-outbound-pii`):** Outbound `agent → MCP` always scrubs secrets while preserving legitimate PII query arguments (such as Jira `assignee` emails) unless `--redact-outbound-pii` is explicitly enabled.
- **Prompt-injection tripwire & taint-by-default (`src/injection.mjs`, `src/proxy.mjs`):** Made non-destructive taint quarantine (`taintUntrusted: true`) the default proxy behavior (`--no-taint` to opt out), required `critical` severity or `--block-min-rules 2` distinct rules before `--block-injections` replaces/drops a message, added `AI_READER_DIRECTIVE` (`Note to AI assistants...`), `UNICODE_TAG_SMUGGLING`, `LLM_CONTROL_TOKEN`, role-turn credential-upload detection, NFKC/zero-width normalization (`normalizeForInjectionScan`), and `--injection-threshold <low|medium|high|critical>`.
- **Scored Apache Kafka benchmark corpus (`scripts/benchmark.mjs`, `test/corpus.test.mjs`):** Added 350 public Apache Kafka JIRA issues & `dev@kafka.apache.org` emails (`scripts/fetch-kafka-corpus.mjs`), 8 benign engineering probes, 24 planted synthetic secrets, and 26 labelled attacks enforced as a CI regression gate (`0/350` benign FPs, `24/24` secret catch, `20/26` tripwire catch / `23.1%` documented miss rate, `0.34 ms` p99 locally).
- **CLI & TypeScript DX:** Added `src/index.d.ts`, dynamic `-v`/`--version` from `package.json`, `--flag=value` parsing, `scan -` (stdin), automatic JSONL detection (`--jsonl`), `--no-pii` on `scan`, and clean exit-code-2 errors.
- **Contributor guardrails & CI:** Added zero-dep `npm run check` (`scripts/check.mjs`), ReDoS adversarial latency tests (`test/redos.test.mjs`), TypeScript validation (`test/types.check.ts`), cross-OS GitHub Actions CI, `SECURITY.md`, `CONTRIBUTING.md`, and `CODE_OF_CONDUCT.md`.

### Fixed
- Fixed `OPENAI_API_KEY` shadowing `ANTHROPIC_API_KEY` and `OPENROUTER_API_KEY`.
- Fixed `PHONE_NUMBER` corrupting IPv4 addresses (`192.168.100.1`), git diff lines, semantic/calendar versions (`v2025.104.2026`), and ticket IDs.
- Fixed `DATABASE_URI_CREDENTIALS` missing password-only URIs (`redis://:pass@host`) and consuming trailing backslashes in escaped JSON.
- Fixed `PRIVATE_KEY_BLOCK` quadratic backtracking on repeated `BEGIN` headers without `END`.
- Fixed `redactPayload` to redact object keys with collision disambiguation, preserve JSON-RPC 2.0 envelopes and JSON Schema refs, enforce case-insensitive `allowEmailDomains`, guard circular references with a `WeakSet`, and reuse precompiled regexes.
- Fixed `guardMcpResponse` to **fail closed** (`sanitized: null`, `report.safe: false`) when `callerScopes` is passed against a payload without a `.facts` array.
- Fixed `src/proxy.mjs` stdout drain race condition, fail-open unparseable fallback, JSON-RPC blocking semantics (stripping raw attacker snippets from `error.data`, dropping injected notifications, replying `-32001` to injected server-to-client requests), and `ENOENT`/`EPIPE`/`SIGINT`/`SIGTERM` handling.
- Removed noisy prompt-injection false positives (`act as`, `bash ... .env`, `send ... token`) that broke normal engineering tickets.

## [0.1.0] - 2026-11-26

### Added
- Initial MIT release with deterministic secret/PII redaction (`src/redact.mjs`), fail-closed citation-scope ACL filtering (`src/acl.mjs`), indirect prompt-injection detection (`src/injection.mjs`), stdio proxy (`src/proxy.mjs`), and CLI (`demo`, `scan`, `proxy`).
