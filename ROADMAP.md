# `mcp-guard` — Engineering Review & Roadmap

> **Positioning:** A zero-dependency, bidirectional DLP proxy, fail-closed citation-scope ACL gate, and measured prompt-injection tripwire for stdio MCP servers.

---

## 1. Internal Review Summary (`v0.1.0` → `v0.2.0`)

Internal engineering reviews of `v0.1.0` and early `v0.2.0` established our core principles and reordered the roadmap so **measured proof comes before new features**:

### Core Differentiators & Principles
- **Zero npm dependencies** (pure Node.js 20+ built-ins: `node:test`, `node:child_process`, `node:http`).
- **Outbound secret DLP without breaking query PII:** strips `.env`/API/DB secrets before they leave the machine into Jira/Slack/GitHub while keeping legitimate query parameters (such as `assignee: "maria@client.com"`) working unless `--redact-outbound-pii` is opted in.
- **Fail-closed citation-scope ACL gate** (`src/acl.mjs`, `src/index.mjs`): facts carry source citations, callers only see facts backed by scopes they can access, and unrecognized payload shapes fail closed (`sanitized: null`, `safe: false`).
- **Measured precision & recall in CI:** every claim in `README.md` is backed by `npm run benchmark` and `test/corpus.test.mjs` over 350 public Apache Kafka JIRA issues & dev-list threads (`0/350` FPs, `24/24` planted secrets, `20/26 (76.9%)` tripwire attack recall with a transparent `23.1%` miss rate on subtle natural-language attacks, `0.34 ms` p99 locally).
- **Strict `stderr` vs `stdout` stream separation** so audit telemetry never corrupts MCP JSON-RPC frames.

---

## 2. Prioritized Engineering Roadmap

### Milestone `v0.2.0` — Correctness, Bidirectional Proxy & Measured Proof
- [x] **#1 (`P0`) — Fix `src/redact.mjs` bugs & expand B2B/AI secret rules:** `ANTHROPIC_API_KEY`/`OPENROUTER_API_KEY` precedence, IPv4-safe phone matching, password-only DB URIs, 24+ secret/AI-provider detectors (AWS Secret, Atlassian, GitLab, GCP, Gemini, Mistral, Groq, HF, Perplexity, xAI, npm, PyPI, encrypted/truncated PEMs, Shannon entropy), object-key redaction, case-insensitive `allowEmailDomains`, `WeakSet` cycle guard, envelope skipping, precompiled regexes, and ReDoS regression tests.
- [x] **#2 (`P0`) — Rewrite `src/proxy.mjs` as a bidirectional JSON-RPC proxy + E2E tests:** Inspect both `stdin` (secrets always; PII opt-in via `--redact-outbound-pii`) and `stdout`, wait for stdout drain + child `close`, handle `ENOENT`/`EPIPE`/`SIGINT`/`SIGTERM`, never fail open on unparseable frames, support NDJSON + `Content-Length`, fix JSON-RPC blocking semantics, wire `--allow-domain`, and add mock-server E2E tests (`test/proxy.test.mjs`).
- [x] **#10 (`P0`, moved to front) — Public Apache Kafka fixture corpus & CI precision/latency gate:** 350 real public Apache Kafka JIRA issues & dev-list threads (`test/fixtures/corpus/kafka-benign.jsonl`), 8 tricky benign probes, 24 planted synthetic secrets, 26 labelled attacks, `npm run benchmark`, and `test/corpus.test.mjs` enforced in CI.
- [x] **#3 (`P0`, reopened & completed) — Measured prompt-injection tripwire & taint-by-default:** Made `--taint-untrusted` the default proxy stance (`--no-taint` to opt out), required `critical` severity or `--block-min-rules 2` distinct rules before `--block-injections` drops/replaces a frame, tightened `<system>` XML matching to eliminate XML-config false positives, added `AI_READER_DIRECTIVE` & reworded override/persona rules, and verified `0/350` Kafka FPs + `0/8` benign blocks + `20/26` attack recall in CI.
- [x] **#4 (`P1`) — npm publish (`@4sails/mcp-guard`) & DX:** Published `@4sails/mcp-guard@0.4.0` to npm (`npx -y @4sails/mcp-guard`), dynamic `--version`, `--flag=value`, `scan -` (stdin), JSONL input, `src/index.d.ts`, cross-OS CI + `npm run check`, `SECURITY.md`, `CONTRIBUTING.md`, and `CHANGELOG.md`.

### Milestone `v0.3.0` — Policy Engine, Auditability & Shared ACL Vectors
- [x] **#6 (`P1`) — Structured JSONL `--audit-log` + `mcp-guard audit` summary CLI:** Append-only `{ ts, dir, method, tool, action, rules, secretHashes, latencyMs }` (SHA-256 hashes only, never raw secrets) with `tools/call` request→response correlation plus a terminal/JSON summary command.
- [x] **#5 (`P1`) — Declarative `mcp-guard.json` policy engine, tool/arg ACLs & shared ACL vectors:** Pre-execution `tools.allow` / `tools.deny` globs, fail-closed `tools.argConstraints` (`jira_*: { project_key }`, `slack_*: { channel_id }`, `github_*: { repo }`), per-tool secret exceptions (`tools.allowSecretFields`), bounded `16 MiB` frame buffer cap, CI-safe `scan` preview omission, and portable `test/fixtures/acl-vectors.json`.

### Milestone `v0.4.0` — Remote MCP Transport
- [x] **#8 (`P1`) — Streamable HTTP / SSE MCP transport proxy:** `mcp-guard http-proxy --upstream https://... --port 8787` built with zero-dep `node:http` & `fetch`, reusing the full policy, redaction, SSE taint/blocking, and JSONL audit core.

### Later / Demand-Driven (`v1.0.0`, P2)
- [x] **#7 (`P2`) — `mcp-guard wrap` / `unwrap` auto-installer:** Idempotently wrap/revert stdio servers in `.cursor/mcp.json`, Claude Desktop, Claude Code, or VS Code config with `--dry-run` diff preview, `--local` support, and `.bak` backup.
- [x] **#9 (`P2`) — Session-scoped deterministic pseudonymization & broader PII:** Replace PII with consistent session tokens (`[EMAIL_1]`, `[EMAIL_2]`, `[PHONE_1]`, `[CARD_1]`, `[SSN_1]`, `[IBAN_1]`) via `--pseudonymize-pii` / `createPiiPseudonymizer()` while keeping secrets strictly one-way redacted, plus Luhn credit card, US SSN, and ISO 13616 MOD-97 IBAN detectors verified with 0 FPs on the 350-item Kafka corpus.
