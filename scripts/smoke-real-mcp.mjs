#!/usr/bin/env node
/**
 * Optional live smoke test against the real official `@modelcontextprotocol/server-filesystem`
 * MCP server via `npx -y`, wrapped inside `mcp-guard proxy`.
 *
 * Run locally (requires network to fetch `@modelcontextprotocol/server-filesystem` if not cached):
 *   node ./scripts/smoke-real-mcp.mjs
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createFrameParser } from "../src/index.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI_PATH = resolve(ROOT, "bin/mcp-guard.mjs");
const SYNTHETIC_STRIPE = ["sk", "live", "51N9xRealSmokeStripeKey987654321"].join("_");

const workDir = mkdtempSync(join(tmpdir(), "mcp-guard-real-fs-"));
const secretFile = join(workDir, "notes.txt");
writeFileSync(
  secretFile,
  `Client contact: maria@client.example\nStripe key: ${SYNTHETIC_STRIPE}\nSafe status: ready\n`
);

const child = spawn(
  process.execPath,
  [
    CLI_PATH,
    "proxy",
    "--pseudonymize-pii",
    "--",
    "npx",
    "-y",
    "@modelcontextprotocol/server-filesystem",
    workDir,
  ],
  { stdio: ["pipe", "pipe", "pipe"] }
);

const responses = new Map();
const waiters = new Map();

const parser = createFrameParser(({ raw }) => {
  const msg = JSON.parse(raw);
  if (msg.id !== undefined && msg.id !== null) {
    responses.set(msg.id, msg);
    const resolveWaiter = waiters.get(msg.id);
    if (resolveWaiter) {
      waiters.delete(msg.id);
      resolveWaiter(msg);
    }
  }
});

child.stdout.on("data", (chunk) => parser.push(chunk));
child.stderr.on("data", (chunk) => process.stderr.write(chunk));

function rpc(id, method, params = {}) {
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  return new Promise((resolveResp, rejectResp) => {
    if (responses.has(id)) {
      resolveResp(responses.get(id));
      return;
    }
    const timer = setTimeout(() => rejectResp(new Error(`Timed out waiting for ${method}`)), 30000);
    waiters.set(id, (msg) => {
      clearTimeout(timer);
      resolveResp(msg);
    });
  });
}

try {
  const init = await rpc(1, "initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "mcp-guard-smoke", version: "0.4.1" },
  });
  assert.ok(init.result?.serverInfo?.name, "Expected serverInfo from filesystem MCP server");

  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);

  const tools = await rpc(2, "tools/list", {});
  const toolNames = (tools.result?.tools || []).map((t) => t.name);
  assert.ok(toolNames.includes("read_file") || toolNames.includes("read_text_file"));

  const readTool = toolNames.includes("read_text_file") ? "read_text_file" : "read_file";
  const readRes = await rpc(3, "tools/call", {
    name: readTool,
    arguments: { path: secretFile },
  });
  const text = readRes.result?.content?.[0]?.text ?? "";
  assert.ok(text.includes("[REDACTED:STRIPE_SECRET_KEY]"), `Expected redacted secret, got: ${text}`);
  assert.ok(text.includes("[EMAIL_1]"), `Expected pseudonymized email, got: ${text}`);
  assert.ok(text.includes("Safe status: ready"));
  assert.ok(!text.includes(SYNTHETIC_STRIPE));
  assert.ok(!text.includes("maria@client.example"));

  console.log(
    `[smoke-real-mcp] OK — verified ${init.result.serverInfo.name} (${toolNames.length} tools), secret redacted & PII pseudonymized.`
  );
} finally {
  child.stdin.end();
  child.kill("SIGTERM");
  rmSync(workDir, { recursive: true, force: true });
}
