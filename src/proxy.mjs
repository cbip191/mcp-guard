import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { redactPayload } from "./redact.mjs";
import { detectPromptInjection } from "./injection.mjs";

/**
 * Wraps any stdio MCP server process and deterministically scrubs secrets/PII
 * plus detects indirect prompt injections on every outbound JSON-RPC message.
 * Audit telemetry is written strictly to stderr so stdout stays valid MCP JSON-RPC.
 */
export function runStdioProxy(command, args = [], options = {}) {
  const { redactPii = true, blockInjections = false, allowEmailDomains = [] } = options;

  const child = spawn(command, args, {
    stdio: ["pipe", "pipe", "inherit"],
    env: process.env,
  });

  process.stdin.pipe(child.stdin);

  const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
  rl.on("line", (line) => {
    if (!line.trim()) {
      process.stdout.write("\n");
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      process.stdout.write(`${line}\n`);
      return;
    }

    const { sanitized, findings } = redactPayload(parsed, {
      redactPii,
      allowEmailDomains,
    });
    const injectionAlerts = detectPromptInjection(sanitized);

    if (findings.length > 0 || injectionAlerts.length > 0) {
      process.stderr.write(
        `[mcp-guard] scrubbed=${findings.length} injection_alerts=${injectionAlerts.length}\n`
      );
    }

    if (blockInjections && injectionAlerts.length > 0 && sanitized.id !== undefined) {
      const blocked = {
        jsonrpc: "2.0",
        id: sanitized.id,
        error: {
          code: -32001,
          message:
            "Blocked by mcp-guard: potential indirect prompt injection detected in upstream MCP payload.",
          data: { alerts: injectionAlerts },
        },
      };
      process.stdout.write(`${JSON.stringify(blocked)}\n`);
      return;
    }

    process.stdout.write(`${JSON.stringify(sanitized)}\n`);
  });

  child.on("exit", (code) => {
    process.exit(code ?? 0);
  });

  return child;
}
