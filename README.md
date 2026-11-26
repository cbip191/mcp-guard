# `@4sails/mcp-guard`

**The zero-dependency, bidirectional firewall & DLP proxy for `mcp.json`** — deterministic, sub-millisecond secret/PII redaction, indirect prompt-injection quarantine, and fail-closed ACL gating for any stdio MCP server.

- **Zero npm runtime dependencies** (pure Node.js 20+ ESM built-ins)
- **Bidirectional DLP:** scrubs secrets & PII on **both** `agent → MCP` (`stdin`, stopping `.env` leaks into Jira/Slack/GitHub) and `MCP → agent` (`stdout`)
- **Non-destructive quarantine (`--taint-untrusted`)** or **strict JSON-RPC blocking (`--block-injections`)**
- **Strict `stdout` / `stderr` separation:** audit logs write only to `stderr` so MCP JSON-RPC frames on `stdout` are never corrupted

Built by [4sails](https://4sails.tech) — architecture spec & live overview at [4sails.tech/open-source/mcp-guard](https://4sails.tech/open-source/mcp-guard).

---

## 30-Second Quickstart (`mcp.json`)

Wrap any existing stdio MCP server by prefixing its command with `npx -y @4sails/mcp-guard proxy ... --`:

### Claude Code (`.mcp.json` or `claude mcp add`)
```bash
claude mcp add guarded-github -- \
  npx -y @4sails/mcp-guard proxy --taint-untrusted --allow-domain youragency.com -- \
  npx -y @modelcontextprotocol/server-github
```

### Cursor (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": [
        "-y",
        "@4sails/mcp-guard",
        "proxy",
        "--taint-untrusted",
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

### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "jira": {
      "command": "npx",
      "args": [
        "-y",
        "@4sails/mcp-guard",
        "proxy",
        "--block-injections",
        "--injection-threshold",
        "high",
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

---

## Why This Exists

Connecting a coding agent directly to raw Jira, Slack, and GitHub MCP servers creates three immediate production risks:

1. **Outbound secret leaks (`agent → MCP`):** Coding agents with workspace access can paste local `.env` credentials, API keys, or DB URIs straight into Jira comments, Slack channels, or PR bodies.
2. **Inbound secret & PII exposure (`MCP → agent`):** Upstream tokens, Redis/Postgres URIs, PEM keys, and external client emails/phones get pulled straight into LLM context windows.
3. **Indirect prompt injection:** External Jira comments, Slack Connect messages, or PR descriptions can hide instructions (`Ignore the previous instructions`, zero-width Unicode smuggling, `<|im_start|>`, multiline `curl ~/.ssh/id_rsa`) aimed at hijacking the agent.

---

## What It Catches

### Secret & PII Redaction (`src/redact.mjs`)
- **Cloud & DevOps:** AWS Access Keys (`AKIA`/`ASIA`) & context-anchored AWS Secret Access Keys, GCP API Keys (`AIza...`), GitHub classic & fine-grained PATs, GitLab tokens (`glpat-`, `gloas-`, `gldt-`, `glrt-`, `glcbt-`), Atlassian/Jira API tokens (`AT[A-Z]TT3x...`), npm & PyPI tokens.
- **AI Providers:** Anthropic (`sk-ant-...`), OpenAI (`sk-...` / `sk-proj-...`), OpenRouter (`sk-or-v1-...`), Google Gemini (`GEMINI_API_KEY=AIza...`), Mistral (`MISTRAL_API_KEY=...`), Groq (`gsk_...`), Hugging Face (`hf_...`), Perplexity (`pplx-...`), xAI (`xai-...`).
- **Infra & Auth:** Slack tokens & webhooks, Stripe keys, JWTs, Bearer tokens, full/encrypted/truncated PEM private keys, database & password-only URIs (`postgres://`, `mysql://`, `mongodb+srv://`, `redis://:pass@host`, `rediss://`, `amqps://`), plus context-anchored Shannon entropy detection (`HIGH_ENTROPY_SECRET`).
- **PII & Payload Safety:** Case-insensitive `allowEmailDomains`, IPv4/semver-safe phone redaction (never corrupts `192.168.100.1` or `v2025.104.2026`), object-key redaction with collision handling, JSON-RPC 2.0 envelope preservation, and `WeakSet` cycle protection.

### Prompt-Injection Detection & Quarantine (`src/injection.mjs`)
- **Zero false positives on real engineering tickets:** Routine tickets mentioning `"act as a reverse proxy"`, `"bash setup.sh .env"`, or `"send a password reset token"` pass cleanly.
- **Evasion-resistant:** Strips zero-width/bidi/invisible characters, applies Unicode `NFKC` normalization, detects invisible Unicode Tag smuggling (`U+E0000..U+E007F`), LLM control tokens (`<|im_start|>`), multiline shell exfil, and XML tags with attributes.
- **Two enforcement modes:**
  - `--taint-untrusted`: Wraps *only* flagged string fields in `[MCP_GUARD_UNTRUSTED_DATA ...]` boundary markers (escaping spoofed closing tags) while keeping clean sibling items intact.
  - `--block-injections`: Replaces blocked responses with a spec-compliant JSON-RPC `-32001` error (never echoing attacker snippets in `error.data`), drops injected notifications, and answers injected server-to-client requests with `-32001`.
  - Tune sensitivity with `--injection-threshold <low|medium|high|critical>` (default `medium`).

### Bidirectional Stdio Proxy (`src/proxy.mjs`)
- Supports both **NDJSON** and **`Content-Length`** framing (recalculating UTF-8 byte lengths after redaction) plus JSON-RPC batch arrays.
- Never fails open on unparseable frames; drains child `stdout` before exit; handles `ENOENT`, `EPIPE`, `SIGINT`, and `SIGTERM` cleanly.

---

## CLI Usage

```bash
# Built-in multi-client agency security demo
npx -y @4sails/mcp-guard demo

# Scan a JSON or JSONL export in CI (exits 0=clean, 1=findings, 2=error)
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

Ships with full TypeScript declarations ([`src/index.d.ts`](./src/index.d.ts)):

```ts
import {
  guardMcpResponse,
  redactText,
  redactPayload,
  detectPromptInjection,
  taintUntrustedPayload,
  filterFactsForPrincipal,
  runStdioProxy,
} from "@4sails/mcp-guard";

const { sanitized, report } = guardMcpResponse(rawPayload, {
  callerScopes: ["jira:project:HBR", "slack:channel:C04HARBORDEV"],
  allowEmailDomains: ["youragency.com"],
  injectionThreshold: "high",
  taintUntrusted: true,
});

console.log(report.secretsAndPiiRedacted, report.injectionAlerts, report.taintedPaths);
```

---

## Development

```bash
git clone https://github.com/cbip191/mcp-guard.git
cd mcp-guard
npm test
npm run demo
```

See [ROADMAP.md](./ROADMAP.md) for the `v0.2.0 → v0.3.0 → v1.0.0` engineering plan.

---

## Looking for managed cross-tool reconciliation + permissioned MCP?

`mcp-guard` solves deterministic scrubbing, ACL gating, and prompt-injection protection on individual MCP payloads.

If you run a multi-client software agency or IT consultancy and want **continuous reconciliation across Jira, Slack, and Git** while serving verified, permission-mirrored facts to Claude Code and Cursor over MCP, check out **[4sails.tech](https://4sails.tech)** and our **[B2B MCP Security Architecture Guide](https://4sails.tech/blog/b2b-agentic-data-layer-mcp-guide)**.

## License

MIT © 2026 [4sails](https://4sails.tech)
