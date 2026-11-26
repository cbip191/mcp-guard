# `mcp-guard` — Architecture Audit & Engineering Roadmap (`v0.2` → `v1.0`)

> **Positioning:** The zero-dependency, bidirectional firewall & DLP proxy for `mcp.json` (`npx -y @4sails/mcp-guard`) — deterministic, sub-millisecond, policy-driven guardrails for *both* directions of any stdio/HTTP MCP server.

---

## 1. Architecture & Code Audit Summary (`v0.1.0` Baseline)

An independent engineering audit of `v0.1.0` identified what works well and what must be fixed before broad developer adoption:

### What Works Well
- **Zero npm dependencies** (pure Node.js 20+ built-ins: `node:test`, `node:child_process`, `node:readline`).
- **Small, pure, immutable core functions** (`redactText`, `redactPayload`, `filterFactsForPrincipal`, `detectPromptInjection`).
- **Clean `stderr` vs `stdout` stream separation** in `src/proxy.mjs` so audit telemetry never corrupts MCP JSON-RPC frames.
- **Sound scope-intersection primitive** in `src/acl.mjs` (dropping unauthorized facts and stripping private citations).

### Critical Weak Points & Bugs to Fix in `v0.2.0`
1. **One-way proxy blindness (`src/proxy.mjs:19`):** `process.stdin.pipe(child.stdin)` does not inspect outbound tool calls (agent → MCP server), allowing `.env`/secret leaks into Jira, Slack, or GitHub.
2. **Exit race condition & fail-open fallback (`src/proxy.mjs:29-34, 66-68`):** Exiting on child `"exit"` instead of `"close"` can truncate buffered JSON-RPC responses; unparseable/multi-line frames fall through unredacted; no `ENOENT`/`EPIPE`/`SIGINT` handling; blocking mode misses notifications and echoes attacker injection snippets in `error.data`.
3. **Dead code & IPv4 corruption (`src/redact.mjs:38-46, 76-79`):** `OPENAI_API_KEY` matches `sk-ant-...` before `ANTHROPIC_API_KEY` (making Anthropic rule unreachable); `PHONE_NUMBER` accepts dots without a leading boundary, corrupting IPv4 addresses (`192.168.100.1` → `[REDACTED:PHONE_NUMBER].1`) and version strings; misses AWS Secret Access Keys, Atlassian/Jira tokens (`ATATT3x...`), password-only Redis URIs (`redis://:pass@host`), GitLab PATs, and object keys; recompiles regexes per string leaf.
4. **High false-positive injection rules (`src/injection.mjs:10-31`):** Triggers on routine engineering tickets (`"act as a proxy"`, `"bash setup.sh .env"`, `"send a reset token"`), lacks Unicode normalization, and lacks a non-destructive taint/quarantine mode.
5. **Fail-open ACL gap (`src/index.mjs:33`, `src/acl.mjs`):** `acl.mjs` isn't wired into `proxy.mjs` and silently skips enforcement when passed real upstream Jira/Slack/GitHub MCP JSON instead of a `.facts` array.
6. **Onboarding friction (`bin/mcp-guard.mjs`, `package.json`, `README.md`):** Not published to npm (`npx`), no copy-paste Claude Code / Cursor / Claude Desktop `mcp.json` snippet, no `mcp-guard.json` policy file, and no structured JSONL audit log.

---

## 2. Prioritized Engineering Roadmap

### Milestone `v0.2.0` — Correctness, Bidirectional Proxy & npm DX ("Stop Breaking Real Traffic")
- **#1 (`P0`) — Fix `src/redact.mjs` bugs & expand real B2B secret rules:** Fix `ANTHROPIC_API_KEY` precedence, IPv4-safe phone matching, password-only DB URIs, AWS Secret Access Keys, Jira `ATATT3x...` / GitLab `glpat-` / GCP `AIza...` tokens, object-key redaction, case-insensitive `allowEmailDomains`, circular-ref guard, envelope skipping, and pre-compiled regexes + Shannon entropy checks.
- **#2 (`P0`) — Rewrite `src/proxy.mjs` into a bidirectional JSON-RPC proxy + integration tests:** Inspect both `stdin` and `stdout`, wait for `"close"` drain, handle `ENOENT`/`EPIPE`/`SIGINT`/`SIGTERM`, remove fail-open fallback (support NDJSON + `Content-Length`), fix JSON-RPC blocking semantics (never echo snippets back to LLM), wire `--allow-domain`, and add mock-server E2E tests (`test/proxy.test.mjs`).
- **#3 (`P0`) — Fix `src/injection.mjs` false positives + add `--taint-untrusted` quarantine mode:** Remove broad triggers (`act as`, `bash ... .env`, `send ... token`), add NFKC/zero-width normalization, split high-confidence vs. heuristic thresholds (`--injection-threshold`), and support non-destructive taint-wrapping for untrusted external content.
- **#4 (`P1`) — Publish `@4sails/mcp-guard` to npm + `mcp.json` quickstart & TypeScript types:** Publish `0.2.0` for `npx -y @4sails/mcp-guard`, put Claude Code / Cursor / Claude Desktop `mcp.json` snippets at top of README, read version from `package.json`, add `--flag=value`, `scan -` (stdin), JSONL input, and `src/index.d.ts`.

### Milestone `v0.3.0` — Policy Engine, Auditability & 10-Second Onboarding
- **#5 (`P1`) — Declarative `mcp-guard.json` policy file & tool-level ACLs:** Support `tools.allow`/`tools.deny` globs and `tools.argConstraints` (`jira_*: { project_key: ["HBR"] }`, `slack_*: { channel_id: [...] }`, `github_*: { repo: [...] }`) enforced before upstream execution; make `guardMcpResponse` fail closed when `callerScopes` is passed against unrecognized shapes.
- **#6 (`P1`) — Structured JSONL `--audit-log` + `mcp-guard audit` summary CLI:** Append-only `{ ts, dir, method, tool, action, rules, secretHashes, latencyMs }` (never raw secrets) plus a terminal summary command.
- **#7 (`P1`) — `mcp-guard wrap` / `unwrap` auto-installer:** Automatically wrap/revert stdio servers inside `~/.cursor/mcp.json` or Claude Desktop config with `--dry-run` and `.bak` backup.

### Milestone `v1.0.0` — Production MCP Firewall
- **#8 (`P2`) — Streamable HTTP / SSE MCP transport proxy:** `mcp-guard http-proxy --upstream https://... --port 8787` using zero-dep `node:http` & `fetch`.
- **#9 (`P2`) — Session-scoped deterministic pseudonymization:** Replace PII with consistent session tokens (`[EMAIL_1]`, `[EMAIL_2]`) while keeping secrets strictly one-way redacted.
- **#10 (`P2`) — Public benchmark & fixture regression corpus:** Anonymized Jira/Slack/GitHub transcript fixtures in `test/fixtures/` enforcing 0% clean false positives, 100% secret catch rate, and `<2ms` p99 proxy latency published in `README.md`.
