# `@4sails/mcp-guard`

**Zero-dependency bidirectional DLP proxy, `mcp-guard.json` tool/arg firewall, fail-closed citation-scope ACL gate, and prompt-injection tripwire for stdio & Streamable HTTP/SSE MCP servers.**

- **Zero npm dependencies** (pure Node.js 20+ ESM built-ins)
- **Smart bidirectional secret DLP:**
  - **Outbound (`agent → MCP`):** always redacts secrets before tool arguments reach Jira, Slack, or GitHub, while keeping legitimate PII query arguments (like `assignee: "maria@client.com"`) intact unless you opt into `--redact-outbound-pii`.
  - **Inbound (`MCP → agent`):** redacts secrets and external PII before responses enter the LLM context window (respecting `--allow-domain`).
- **Taint-by-default prompt-injection tripwire:** flags known indirect prompt-injection patterns non-destructively by wrapping only the flagged string in `[MCP_GUARD_UNTRUSTED_DATA ...]` markers (disable with `--no-taint`; strict `--block-injections` blocks only on `critical` rules or `>= 2` distinct rules by default).
- **Fail-closed citation-scope ACL gate:** `guardMcpResponse(..., { callerScopes })` filters facts by permitted citation scopes and fails closed (`sanitized: null`, `safe: false`) on unrecognized payload shapes.
- **Strict `stdout` / `stderr` separation:** audit telemetry writes only to `stderr` so MCP JSON-RPC frames on `stdout` are never corrupted.

Built by [4sails](https://4sails.tech) — architecture overview at [4sails.tech/open-source/mcp-guard](https://4sails.tech/open-source/mcp-guard).

---

## Measured Benchmarks (Reproducible in CI)

Run `npm run benchmark` (and enforced on every PR by `test/corpus.test.mjs`) against **350 public Apache Kafka JIRA issues & `dev@kafka.apache.org` emails** (`530.7 KB`, Apache License 2.0), 8 engineering edge-case probes, 24 planted synthetic secrets, and 26 labelled prompt-injection attacks:

| Metric | Measured Result | Scope / Notes |
| --- | --- | --- |
| **Secret redaction false positives (Kafka corpus)** | **0 / 350 (0.0%)** | Real JIRA descriptions, comments, stack traces, and dev-list threads |
| **Phone / IPv4 / version corruption (`redactPii: true`)** | **0 / 350 (0.0%)** | Zero IPv4s, Kafka versions, or build IDs mangled |
| **Injection tripwire false positives (Kafka corpus)** | **0 / 350 (0.0%)** | Measured at default `medium` threshold |
| **Benign engineering probes blocked (`--block-injections`)** | **0 / 8 (0.0%)** | Includes `"Ignore previous instructions about the deadline"` and `"Use the <system> tag in the XML config"` |
| **Planted synthetic secret catch rate** | **24 / 24 (100.0%)** | All 24 supported secret formats planted inside real Kafka tickets |
| **Labelled prompt-injection tripwire catch rate** | **20 / 26 (76.9%)** | **23.1% miss rate:** catches structured, reworded, AI-reader, delimiter, and obfuscated attacks; intentionally misses subtle paraphrased, base64, and non-English social engineering (regex tripwires are not a semantic classifier) |
| **Proxy frame inspection latency (`inspectFrame`)** | **0.05 ms p50 · 0.14 ms p95 · 0.34 ms p99** | Full JSON parse + secret scan + injection scan + serialize across 350 Kafka JSON-RPC frames (`14.8 MB/s` on Apple Silicon; CI enforces `< 5 ms` p99 on shared runners) |

---

## Quickstart (Node.js 20+, Zero Dependencies)

```bash
# Run the built-in multi-client agency demo directly via npx
npx -y @4sails/mcp-guard demo

# Preview wrapping your existing Cursor / Claude Desktop / Claude Code stdio MCP servers (dry-run by default)
npx -y @4sails/mcp-guard wrap ~/.cursor/mcp.json --dry-run --allow-domain youragency.com

# Apply changes safely (writes a .bak backup automatically)
npx -y @4sails/mcp-guard wrap ~/.cursor/mcp.json --apply --allow-domain youragency.com
```

### Wrap Any Stdio MCP Server (`mcp.json`)

All examples below use the **taint-by-default** stance so suspicious external comments are quarantined with `[MCP_GUARD_UNTRUSTED_DATA ...]` markers without hiding legitimate tickets:

#### Claude Code
```bash
claude mcp add guarded-github -- \
  npx -y @4sails/mcp-guard proxy --allow-domain youragency.com -- \
  npx -y @modelcontextprotocol/server-github
```

#### Cursor (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": [
        "-y",
        "@4sails/mcp-guard",
        "proxy",
        "--allow-domain",
        "youragency.com",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github"
      ]
    }
  }
}
```

#### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "jira": {
      "command": "npx",
      "args": [
        "-y",
        "@4sails/mcp-guard",
        "proxy",
        "--allow-domain",
        "youragency.com",
        "--",
        "npx",
        "-y",
        "your-jira-mcp-server"
      ]
    }
  }
}
```

> Opt into strict blocking only when needed (`--block-injections`, which blocks only on `critical` exfiltration/extraction rules or `>= 2` distinct high-confidence rules via `--block-min-rules`).

---

## Capabilities & Scope

### 1. Deterministic Secret & PII Redaction (`src/redact.mjs`)
- **Cloud & DevOps:** AWS Access Keys (`AKIA`/`ASIA`) & context-anchored AWS Secret Access Keys, GCP API Keys (`AIza...`), GitHub classic & fine-grained PATs, GitLab tokens (`glpat-`, `gloas-`, `gldt-`, `glrt-`, `glcbt-`), Atlassian/Jira API tokens (`AT[A-Z]TT3x...`), npm & PyPI tokens.
- **AI Providers:** Anthropic (`sk-ant-...`), OpenAI (`sk-...` / `sk-proj-...`), OpenRouter (`sk-or-v1-...`), Google Gemini (`GEMINI_API_KEY=AIza...`), Mistral (`MISTRAL_API_KEY=...`), Groq (`gsk_...`), Hugging Face (`hf_...`), Perplexity (`pplx-...`), xAI (`xai-...`).
- **Infra & Auth:** Slack tokens & webhooks, Stripe keys, JWTs, Bearer tokens, full/encrypted/truncated PEM private keys, database & password-only URIs (`postgres://`, `mysql://`, `mongodb+srv://`, `redis://:pass@host`, `rediss://`, `amqps://`), plus context-anchored Shannon entropy detection (`HIGH_ENTROPY_SECRET`).
- **Payload Safety & Session PII Pseudonymization (`src/pseudonymize.mjs`):** Case-insensitive `allowEmailDomains`, IPv4/semver-safe phone matching, Luhn-validated credit cards (`CREDIT_CARD`), SSA-validated US SSNs (`US_SSN`), ISO 13616 MOD-97 IBANs (`IBAN`), opt-in session-scoped deterministic PII pseudonymization (`--pseudonymize-pii` / `createPiiPseudonymizer()`, mapping distinct contacts to `[EMAIL_1]`, `[EMAIL_2]`, `[PHONE_1]`, `[CARD_1]`, `[SSN_1]`, `[IBAN_1]` with optional outbound re-hydration via `--rehydrate-outbound-pii` or per-tool policy globs while keeping all secrets strictly one-way `[REDACTED:...]`), safe object-key redaction with collision disambiguation, JSON-RPC 2.0 envelope preservation, `WeakSet` cycle protection, and linear-time ReDoS tests (`test/redos.test.mjs`).

### 2. Prompt-Injection Early-Warning Tripwire (`src/injection.mjs`)
- Designed as a fast, deterministic **early-warning tripwire** — not an LLM classifier (see the measured `20/26` catch rate and `23.1%` miss rate on subtle natural-language/base64/multilingual attacks in the benchmark table above).
- Normalizes NFKC homoglyphs and strips zero-width/bidi/invisible characters before matching; detects instruction overrides, text addressed directly to an AI reader (`Note to AI assistants...`), role/turn hijacks, credential file uploads, shell exfiltration, LLM control tokens (`<|im_start|>`), attributed/pseudo XML control tags, and Unicode Tag smuggling (`U+E0000..U+E007F`).
- **Taint by default (`taintUntrusted: true`):** wraps only flagged string fields in `[MCP_GUARD_UNTRUSTED_DATA ...]` markers (escaping spoofed closing tags) while leaving clean sibling items intact. Opt out with `--no-taint` or escalate with `--block-injections [--block-min-rules 2] [--injection-threshold <low|medium|high|critical>]`.

### 3. Declarative `mcp-guard.json` Policy Engine & Citation-Scope ACLs (`src/policy.mjs`, `src/acl.mjs`)
- **Pre-execution tool & argument firewall (`--policy mcp-guard.json`):** Blocks disallowed tools and out-of-scope arguments with a JSON-RPC `-32002` error **before** they reach the upstream MCP server (and logs the block to `--audit-log`). Supports `tools.allow`, `tools.deny` (deny always wins), `tools.argConstraints` (exact values, globs, nested dot-paths, fail-closed on missing args), and per-tool secret exceptions (`tools.allowSecretFields`) for tools that legitimately accept credentials.

```json
{
  "tools": {
    "allow": ["jira_*", "github_*", "vault_write_secret"],
    "deny": ["*_delete*", "*_destroy*", "github_merge_*"],
    "argConstraints": {
      "jira_*": { "project_key": ["HBR"] },
      "github_*": { "repo": ["agency/harbor-*"] }
    },
    "allowSecretFields": {
      "vault_write_secret": ["value"]
    }
  },
  "redaction": {
    "disabledRules": ["PHONE_NUMBER"],
    "customRules": [
      { "id": "ACME_INTERNAL_TOKEN", "pattern": "acme_tok_[a-z0-9]{16,32}", "severity": "critical" }
    ],
    "allowPatterns": ["^support-bot@client\\.example$"]
  }
}
```

- **Fail-closed citation-scope ACL gate (`filterFactsForPrincipal`, `guardMcpResponse`):** Intersects fact citations against the caller's permitted Jira/Slack/Git scopes — dropping uncited or unauthorized facts, stripping private citations, and failing closed (`sanitized: null`, `report.acl.blocked: true`, `report.safe: false`) on unrecognized payload shapes. Verified against portable shared vectors in [`test/fixtures/acl-vectors.json`](./test/fixtures/acl-vectors.json).

### 4. Bidirectional Stdio + Streamable HTTP/SSE Proxy & Audit Log (`src/proxy.mjs`, `src/http-proxy.mjs`, `src/audit.mjs`)
- **Stdio proxy (`mcp-guard proxy`):** Supports both **NDJSON** and **`Content-Length`** framing (recalculating UTF-8 byte lengths after redaction) with a bounded `16 MiB` default `maxFrameBytes` DoS cap plus JSON-RPC batch arrays.
- **Streamable HTTP / SSE proxy (`mcp-guard http-proxy`):** Built with zero-dep `node:http` and `fetch`, binding to `127.0.0.1` by default — protects remote Streamable HTTP & legacy SSE MCP servers (GitHub, Linear, Atlassian, Stripe) using the exact same `mcp-guard.json` policy engine, outbound/inbound redaction, SSE event taint/blocking, and `--audit-log` core.
- Never fails open on unparseable frames; drains streams cleanly on exit; handles `ENOENT`, `EPIPE`, `SIGINT`, and `SIGTERM`.
- Pass `--audit-log <path.jsonl>` to record append-only structured events (`{ ts, dir, method, tool, action, rules, secretHashes, latencyMs }`) with one-way SHA-256 secret fingerprints (never raw secrets) and `tools/call` request→response tool correlation, then inspect them with `mcp-guard audit <path.jsonl>`.

---

## CLI Usage

```bash
# Built-in multi-client agency demo
npx -y @4sails/mcp-guard demo

# Wrap an upstream stdio MCP server with policy enforcement, session PII pseudonymization, and audit logging
npx -y @4sails/mcp-guard proxy --policy ./mcp-guard.json --allow-domain youragency.com \
  --pseudonymize-pii --audit-log ./mcp-audit.jsonl -- \
  npx -y @modelcontextprotocol/server-github

# Start a local Streamable HTTP / SSE proxy in front of a remote MCP server
npx -y @4sails/mcp-guard http-proxy --upstream https://mcp.example.com/mcp --port 8787 \
  --policy ./mcp-guard.json --allow-domain youragency.com --audit-log ./mcp-audit.jsonl

# Auto-wrap stdio servers inside Cursor / Claude Desktop / Claude Code mcp.json (dry-run preview first!)
npx -y @4sails/mcp-guard wrap ~/.cursor/mcp.json --dry-run --allow-domain youragency.com
npx -y @4sails/mcp-guard wrap ~/.cursor/mcp.json --apply --allow-domain youragency.com
npx -y @4sails/mcp-guard unwrap ~/.cursor/mcp.json --apply

# Scaffold a starter mcp-guard.json policy (with JSON Schema autocomplete) and dry-run test rules offline
npx -y @4sails/mcp-guard init --preset github
npx -y @4sails/mcp-guard policy test ./mcp-guard.json github_get_issue '{"repo":"your-org/app"}'

# Summarize an audit log in the terminal (or --json for SIEM/CI)
npx -y @4sails/mcp-guard audit ./mcp-audit.jsonl

# Scan a JSON or JSONL export in CI (omits secret previews by default; pass --show-previews locally)
npx -y @4sails/mcp-guard scan ./jira-export.json \
  --scopes=jira:project:HBR,slack:channel:C04HARBORDEV \
  --allow-domain=youragency.com \
  --injection-threshold=high

# Pipe JSON or JSONL from stdin
cat mcp-transcript.jsonl | npx -y @4sails/mcp-guard scan - --taint-untrusted

# Print version
npx -y @4sails/mcp-guard --version
```

---

## Programmatic API (ESM + TypeScript)

Install as a zero-dependency library (ships with TypeScript declarations in [`src/index.d.ts`](./src/index.d.ts)):

```bash
npm install @4sails/mcp-guard
```

```js
import { guardMcpResponse, createPiiPseudonymizer } from "@4sails/mcp-guard";

const pseudonymizer = createPiiPseudonymizer();

const { sanitized, report } = guardMcpResponse(rawPayload, {
  callerScopes: ["jira:project:HBR", "slack:channel:C04HARBORDEV"],
  allowEmailDomains: ["youragency.com"],
  pseudonymizer,
  injectionThreshold: "high",
  taintUntrusted: true,
});

console.log(report.secretsAndPiiRedacted, report.injectionAlerts, report.taintedPaths);
```

### Local Development & Verification

```bash
git clone https://github.com/cbip191/mcp-guard.git
cd mcp-guard
npm run check && npm test && npm run benchmark
```

---

## Threat Model & Non-Goals

`mcp-guard` protects the **MCP tool boundary** (stdio and Streamable HTTP/SSE traffic between your AI client and MCP servers):

- **What it enforces deterministically:** pre-execution tool/argument policy blocks (`mcp-guard.json`), outbound secret redaction, inbound secret/PII redaction or session pseudonymization, fail-closed citation-scope ACLs, bounded frame sizes, and secret-free JSONL audit logging.
- **What it treats as best-effort early warning:** regex/Unicode prompt-injection detection (`20/26` on our benchmark, `23.1%` documented miss rate). Taint markers (`[MCP_GUARD_UNTRUSTED_DATA ...]`) help steer the model but are not a cryptographic sandbox against every LLM override.
- **Out of scope:** direct local shell, file-system, or browser tools built into your coding agent (Claude Code, Cursor) that bypass MCP entirely. Pair `mcp-guard` with least-privilege OAuth scopes, OS sandboxing, and client-side tool approvals.

---

## Contributing & Security

- Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before opening a pull request.
- Report security vulnerabilities privately via [GitHub Security Advisories](https://github.com/cbip191/mcp-guard/security/advisories/new) — see [SECURITY.md](./SECURITY.md).
- Release history is tracked in [CHANGELOG.md](./CHANGELOG.md).

---

## Looking for managed cross-tool reconciliation + permissioned MCP?

If you run a multi-client software agency or IT consultancy and want **continuous reconciliation across Jira, Slack, and Git** while serving verified, permission-mirrored facts to Claude Code and Cursor over MCP, check out **[4sails.tech](https://4sails.tech)** and read our **[B2B MCP Security Architecture Guide](https://4sails.tech/blog/b2b-agentic-data-layer-mcp-guide)**.

## License

MIT © 2026 [4sails](https://4sails.tech)
