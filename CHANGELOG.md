# Changelog

All notable changes to `@4sails/mcp-guard` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Structured JSONL audit logging (`src/audit.mjs`, `src/proxy.mjs`, `bin/mcp-guard.mjs`):** Added `--audit-log <path.jsonl>` emitting append-only `{ ts, dir, method, tool, action, rules, secretHashes, latencyMs }` records (owner-only `0600` permissions on POSIX, one-way `sha256:` secret fingerprints via `hashSecret()`, never raw secrets/previews/snippets, and automatic `tools/call` request→response tool correlation) plus `mcp-guard audit <logfile|-> [--json]` terminal/JSON summary CLI.

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
