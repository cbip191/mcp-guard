# `mcp-guard` — Engineering Review & Roadmap (`v0.2` → `v1.0`)

> **Positioning:** The zero-dependency, bidirectional firewall & DLP proxy for `mcp.json` — deterministic, sub-millisecond, policy-driven guardrails for *both* directions of any stdio/HTTP MCP server.

---

## 1. Internal Review Summary (`v0.1.0` → `v0.2.0`)

An internal engineering review of `v0.1.0` established the core architectural principles and identified the correctness gaps prioritized for `v0.2.0`–`v1.0.0`:

### Core Strengths to Preserve
- **Zero npm runtime dependencies** (pure Node.js 20+ built-ins: `node:test`, `node:child_process`, `node:http`).
- **Small, pure, immutable core functions** (`redactText`, `redactPayload`, `filterFactsForPrincipal`, `detectPromptInjection`, `taintUntrustedPayload`, `inspectFrame`).
- **Strict `stderr` vs `stdout` stream separation** in `src/proxy.mjs` so audit telemetry never corrupts MCP JSON-RPC frames.
- **Fail-closed citation-scope ACL primitive** in `src/acl.mjs` & `src/index.mjs` (dropping unauthorized facts, stripping private citations, and failing closed when `callerScopes` is passed against unrecognized payload shapes).

### Key Gaps Addressed in `v0.2.0`
- Bidirectional stdio proxy (`agent → MCP` secret DLP with opt-in `--redact-outbound-pii`, plus `MCP → agent` secret/PII scrubbing and prompt-injection blocking/quarantine).
- Dual `NDJSON` + `Content-Length` framing, fail-closed unparseable frame scrubbing, spec-compliant JSON-RPC blocking (without echoing attacker snippets), stdout drain before exit, `ENOENT`/`EPIPE`/`SIGINT`/`SIGTERM` handling, and mock-server E2E tests.
- Fixed `ANTHROPIC_API_KEY` & `OPENROUTER_API_KEY` precedence ahead of `OPENAI_API_KEY`, IPv4/semver-safe `PHONE_NUMBER`, password-only Redis/AMQP URIs, 25+ secret/AI-provider detectors (including Gemini, Mistral, AWS Secret, Atlassian/Jira, GitLab, GCP, npm, PyPI, encrypted/truncated PEMs, Shannon entropy), object-key redaction, JSON-RPC envelope preservation, `WeakSet` cycle guards, and linear-time ReDoS tests.
- Eliminated engineering false positives in `src/injection.mjs`, added NFKC + zero-width/Unicode-tag normalization, severity thresholds (`--injection-threshold`), and non-destructive `--taint-untrusted` quarantine mode.

---

## 2. Prioritized Engineering Roadmap

### Milestone `v0.2.0` — Correctness, Bidirectional Proxy & Contributor Guardrails
- [x] **#1 (`P0`) — Fix `src/redact.mjs` bugs & expand real B2B/AI secret rules:** `ANTHROPIC_API_KEY`/`OPENROUTER_API_KEY` precedence, IPv4-safe phone matching, password-only DB URIs, AWS Secret / Atlassian / GitLab / GCP / Gemini / Mistral / Groq / HF / Perplexity / xAI / npm / PyPI rules, object-key redaction, case-insensitive `allowEmailDomains`, `WeakSet` cycle guard, envelope skipping, precompiled regexes + Shannon entropy.
- [x] **#2 (`P0`) — Rewrite `src/proxy.mjs` into a bidirectional JSON-RPC proxy + E2E tests:** Inspect both `stdin` (secrets always; PII opt-in via `--redact-outbound-pii`) and `stdout`, wait for stdout drain + child `close`, handle `ENOENT`/`EPIPE`/`SIGINT`/`SIGTERM`, never fail open on unparseable frames, support NDJSON + `Content-Length`, fix JSON-RPC blocking semantics, wire `--allow-domain`, and add mock-server E2E tests (`test/proxy.test.mjs`).
- [x] **#3 (`P0`) — Fix `src/injection.mjs` false positives + add `--taint-untrusted` quarantine mode:** Remove noisy triggers (`act as`, `bash ... .env`, `send ... token`), add NFKC/zero-width/Unicode-tag normalization, catch role-turn credential uploads, split severity thresholds (`--injection-threshold`), and support non-destructive quarantine wrapping.
- [ ] **#4 (`P1`) — `v0.2.0` DX, TypeScript types, CI guardrails & npm publish:** Dynamic version, `--flag=value`, `scan -` (stdin), JSONL input, `src/index.d.ts`, `scripts/check.mjs`, GitHub Actions CI + ReDoS tests, `SECURITY.md`/`CONTRIBUTING.md`/`CHANGELOG.md`, and publish `@4sails/mcp-guard@0.2.0` to npm.

### Milestone `v0.3.0` — Policy Engine, Auditability & 10-Second Onboarding
- [ ] **#5 (`P1`) — Declarative `mcp-guard.json` policy file & tool-level ACLs:** Support `tools.allow`/`tools.deny` globs and `tools.argConstraints` (`jira_*: { project_key: ["HBR"] }`, `slack_*: { channel_id: [...] }`, `github_*: { repo: [...] }`) enforced before upstream execution in `mcp-guard proxy`.
- [ ] **#6 (`P1`) — Structured JSONL `--audit-log` + `mcp-guard audit` summary CLI:** Append-only `{ ts, dir, method, tool, action, rules, secretHashes, latencyMs }` (never raw secrets) plus a terminal summary command.
- [ ] **#7 (`P1`) — `mcp-guard wrap` / `unwrap` auto-installer:** Automatically wrap/revert stdio servers inside `.cursor/mcp.json` or Claude Desktop config with `--dry-run` and `.bak` backup.

### Milestone `v1.0.0` — Production MCP Firewall
- [ ] **#8 (`P2`) — Streamable HTTP / SSE MCP transport proxy:** `mcp-guard http-proxy --upstream https://... --port 8787` using zero-dep `node:http` & `fetch`.
- [ ] **#9 (`P2`) — Session-scoped deterministic pseudonymization:** Replace PII with consistent session tokens (`[EMAIL_1]`, `[EMAIL_2]`) while keeping secrets strictly one-way redacted.
- [ ] **#10 (`P2`) — Public benchmark & fixture regression corpus:** Anonymized Jira/Slack/GitHub transcript fixtures in `test/fixtures/` enforcing 0% clean false positives, 100% secret catch rate, and `<2ms` p99 proxy latency published in `README.md`.
