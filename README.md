# mcp-guard

**Zero-dependency MCP security middleware & CLI for B2B teams connecting Claude Code, Cursor, or AI agents to Jira, Slack, and Git.**

Built by [4sails](https://4sails.tech) — full architecture spec at [4sails.tech/open-source/mcp-guard](https://4sails.tech/open-source/mcp-guard).

---

## Why this exists

Connecting a coding agent directly to raw Jira and Slack MCP servers works in a single-product startup. Inside a **multi-client software agency or IT consultancy**, raw MCP connectors create three immediate risks:

1. **Cross-client NDA leaks:** Shared service tokens expose Client B's tickets or `#executive-margins` channels to engineers assigned only to Client A.
2. **Secret & PII exposure:** API keys, database URIs, bearer tokens, and client emails pasted into Slack or Jira get forwarded straight into external LLM context windows.
3. **Indirect prompt injection:** Untrusted external comments in Jira tickets or Slack Connect messages can hide instructions aimed at exfiltrating local `.env` or `~/.ssh` files.

`mcp-guard` gives you three deterministic, zero-dependency building blocks you can run today as a CLI scanner, library, or stdio MCP proxy wrapper:

- **Deterministic Secret & PII Redactor** (`redactText`, `redactPayload`): Strips AWS keys, GitHub tokens, Slack tokens/webhooks, Stripe keys, OpenAI/Anthropic keys, JWTs, PEM blocks, database credentials, and external PII before LLM ingestion.
- **Fail-Closed Inherited ACL Gate** (`filterFactsForPrincipal`): Intersects fact citations against the calling user's real Jira, Slack, and Git access scopes — dropping unauthorized facts silently and stripping private-only citations.
- **Indirect Prompt-Injection Detector** (`detectPromptInjection`): Flags instruction overrides, role hijacks, shell exfiltration attempts (`curl ~/.ssh/id_rsa`), and hidden XML tag injections.
- **Stdio MCP Proxy** (`mcp-guard proxy -- <upstream-mcp>`): Wraps any existing stdio MCP server and scrubs secrets/PII live on every JSON-RPC response (with optional `--block-injections`).

---

## Quickstart (Node.js 20+, zero dependencies)

```bash
git clone https://github.com/cbip191/mcp-guard.git
cd mcp-guard

# 1. Run the built-in multi-client agency security demo
node ./bin/mcp-guard.mjs demo

# 2. Run the automated test suite
npm test
```

### Scan any Jira / Slack / MCP JSON export in CI
```bash
node ./bin/mcp-guard.mjs scan ./sample-export.json \
  --scopes jira:project:HBR,slack:channel:C04HARBORDEV \
  --allow-domain youragency.com
```
Exits `0` if clean, `1` if unredacted secrets, PII, or prompt-injection patterns are found.

### Wrap any existing stdio MCP server
```bash
node ./bin/mcp-guard.mjs proxy --block-injections -- npx @modelcontextprotocol/server-everything
```
Audit telemetry writes strictly to `stderr`; scrubbed JSON-RPC flows cleanly on `stdout`.

---

## Programmatic Usage

```js
import { guardMcpResponse } from "@4sails/mcp-guard";

const { sanitized, report } = guardMcpResponse(rawPayload, {
  callerScopes: ["jira:project:HBR", "slack:channel:C04HARBORDEV"],
  allowEmailDomains: ["youragency.com"],
});

console.log(report.secretsAndPiiRedacted, report.injectionAlerts, report.acl);
```

---

## Looking for managed cross-tool reconciliation + permissioned MCP?

`mcp-guard` solves deterministic scrubbing, ACL gating, and prompt-injection detection on individual MCP payloads.

If you run a multi-client software agency or IT consultancy and want **continuous reconciliation across Jira, Slack, and Git** (catching 9-day silent stalls, source conflicts, and scope drift while serving verified, permission-mirrored facts to Claude Code and Cursor over MCP), check out **[4sails.tech](https://4sails.tech)** and read our **[B2B MCP Security Architecture Guide](https://4sails.tech/blog/b2b-agentic-data-layer-mcp-guide)**.

## License
MIT © 2026 [4sails](https://4sails.tech)
