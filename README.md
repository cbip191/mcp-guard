# `@4sails/mcp-guard`

**Zero-dependency bidirectional DLP proxy, fail-closed citation-scope ACL gate, and prompt-injection tripwire for stdio MCP servers.**

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

## Quickstart (Node.js 20+, Run from Git Clone)

```bash
git clone https://github.com/cbip191/mcp-guard.git
cd mcp-guard

# Run the built-in multi-client agency demo
npm run demo

# Run static checks, full test suite (35 tests), and corpus benchmark
npm run check && npm test && npm run benchmark
```

### Wrap Any Stdio MCP Server (`mcp.json`)

All examples below use the **taint-by-default** stance so suspicious external comments are quarantined with `[MCP_GUARD_UNTRUSTED_DATA ...]` markers without hiding legitimate tickets. Replace `/path/to/mcp-guard` with your local clone path:

#### Claude Code
```bash
claude mcp add guarded-github -- \
  node /path/to/mcp-guard/bin/mcp-guard.mjs proxy --allow-domain youragency.com -- \
  npx -y @modelcontextprotocol/server-github
```

#### Cursor (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "github": {
      "command": "node",
      "args": [
        "/path/to/mcp-guard/bin/mcp-guard.mjs",
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
      "command": "node",
      "args": [
        "/path/to/mcp-guard/bin/mcp-guard.mjs",
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
- **Payload Safety:** Case-insensitive `allowEmailDomains`, IPv4/semver-safe phone matching, safe object-key redaction with collision disambiguation, JSON-RPC 2.0 envelope preservation, `WeakSet` cycle protection, and linear-time ReDoS tests (`test/redos.test.mjs`).

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
  }
}
```

- **Fail-closed citation-scope ACL gate (`filterFactsForPrincipal`, `guardMcpResponse`):** Intersects fact citations against the caller's permitted Jira/Slack/Git scopes — dropping uncited or unauthorized facts, stripping private citations, and failing closed (`sanitized: null`, `report.acl.blocked: true`, `report.safe: false`) on unrecognized payload shapes. Verified against portable shared vectors in [`test/fixtures/acl-vectors.json`](./test/fixtures/acl-vectors.json).

### 4. Bidirectional Stdio Proxy & JSONL Audit Log (`src/proxy.mjs`, `src/audit.mjs`)
- Supports both **NDJSON** and **`Content-Length`** framing (recalculating UTF-8 byte lengths after redaction) with a bounded `16 MiB` default `maxFrameBytes` DoS cap plus JSON-RPC batch arrays.
- Never fails open on unparseable frames; drains child `stdout` completely before exit; handles `ENOENT`, `EPIPE`, `SIGINT`, and `SIGTERM` cleanly.
- Pass `--audit-log <path.jsonl>` to record append-only structured events (`{ ts, dir, method, tool, action, rules, secretHashes, latencyMs }`) with one-way SHA-256 secret fingerprints (never raw secrets) and `tools/call` request→response tool correlation, then inspect them with `mcp-guard audit <path.jsonl>`.

---

## CLI Usage

```bash
# Built-in multi-client agency demo
node ./bin/mcp-guard.mjs demo

# Wrap an upstream stdio MCP server with policy enforcement + structured JSONL audit logging
node ./bin/mcp-guard.mjs proxy --policy ./mcp-guard.json --allow-domain youragency.com --audit-log ./mcp-audit.jsonl -- \
  npx -y @modelcontextprotocol/server-github

# Summarize an audit log in the terminal (or --json for SIEM/CI)
node ./bin/mcp-guard.mjs audit ./mcp-audit.jsonl

# Scan a JSON or JSONL export in CI (omits secret previews by default; pass --show-previews locally)
node ./bin/mcp-guard.mjs scan ./jira-export.json \
  --scopes=jira:project:HBR,slack:channel:C04HARBORDEV \
  --allow-domain=youragency.com \
  --injection-threshold=high

# Pipe JSON or JSONL from stdin
cat mcp-transcript.jsonl | node ./bin/mcp-guard.mjs scan - --taint-untrusted

# Print version
node ./bin/mcp-guard.mjs --version
```

---

## Programmatic API (ESM + TypeScript)

Ships with TypeScript declarations ([`src/index.d.ts`](./src/index.d.ts)):

```js
import { guardMcpResponse } from "./src/index.mjs";

const { sanitized, report } = guardMcpResponse(rawPayload, {
  callerScopes: ["jira:project:HBR", "slack:channel:C04HARBORDEV"],
  allowEmailDomains: ["youragency.com"],
  injectionThreshold: "high",
  taintUntrusted: true,
});

console.log(report.secretsAndPiiRedacted, report.injectionAlerts, report.taintedPaths);
```

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
