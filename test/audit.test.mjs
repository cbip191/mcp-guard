import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  hashSecret,
  redactText,
  buildAuditEntry,
  summarizeAuditLog,
  formatAuditSummary,
} from "../src/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, "../bin/mcp-guard.mjs");
const MOCK_SERVER_PATH = resolve(__dirname, "./fixtures/mock-mcp-server.mjs");

function runCli(args, stdinChunks = []) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d.toString("utf8");
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (code) => resolvePromise({ code, stdout, stderr }));

    for (const chunk of stdinChunks) {
      child.stdin.write(chunk);
    }
    child.stdin.end();
  });
}

test("hashSecret produces deterministic one-way sha256 fingerprints and never exposes raw secrets", () => {
  const secret = ["sk", "live", "51N9xAuditHashTestSecret1234567890"].join("_");
  const h1 = hashSecret(secret);
  const h2 = hashSecret(secret);

  assert.equal(h1, h2);
  assert.match(h1, /^sha256:[0-9a-f]{16}$/);
  assert.ok(!h1.includes("51N9x"));

  const { findings } = redactText(`Key=${secret}`, { redactPii: false });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].hash, h1);

  const entry = buildAuditEntry({
    ts: "2026-11-27T12:00:00.000Z",
    dir: "agent->mcp",
    method: "tools/call",
    tool: "jira_add_comment",
    action: "redacted",
    findings,
    latencyMs: 0.1234,
  });

  assert.deepEqual(entry, {
    ts: "2026-11-27T12:00:00.000Z",
    dir: "agent->mcp",
    method: "tools/call",
    tool: "jira_add_comment",
    action: "redacted",
    rules: ["STRIPE_SECRET_KEY"],
    secretHashes: [h1],
    latencyMs: 0.123,
  });
  assert.ok(!JSON.stringify(entry).includes("51N9x"));
});

test("summarizeAuditLog and formatAuditSummary aggregate rules, tools, actions, latency, and skip malformed lines", () => {
  const sampleLog = [
    JSON.stringify({
      ts: "2026-11-27T10:00:00.000Z",
      dir: "agent->mcp",
      method: "tools/call",
      tool: "jira_add_comment",
      action: "redacted",
      rules: ["AWS_ACCESS_KEY"],
      secretHashes: ["sha256:1111111111111111"],
      latencyMs: 0.12,
    }),
    "not-valid-jsonl-line",
    JSON.stringify({
      ts: "2026-11-27T10:00:05.000Z",
      dir: "mcp->agent",
      method: "tools/call",
      tool: "jira_get_issue",
      action: "blocked",
      rules: ["OVERRIDE_INSTRUCTIONS", "SHELL_EXFILTRATION"],
      secretHashes: [],
      latencyMs: 0.45,
    }),
    JSON.stringify({
      ts: "2026-11-27T10:00:10.000Z",
      dir: "mcp->agent",
      method: "tools/call",
      tool: "jira_get_issue",
      action: "redacted",
      rules: ["AWS_ACCESS_KEY", "EMAIL_ADDRESS"],
      secretHashes: ["sha256:1111111111111111", "sha256:2222222222222222"],
      latencyMs: 0.25,
    }),
  ].join("\n");

  const summary = summarizeAuditLog(sampleLog);
  assert.equal(summary.totalEvents, 3);
  assert.equal(summary.malformedLines, 1);
  assert.equal(summary.byDirection["agent->mcp"], 1);
  assert.equal(summary.byDirection["mcp->agent"], 2);
  assert.equal(summary.byAction.redacted, 2);
  assert.equal(summary.byAction.blocked, 1);
  assert.equal(summary.blockedOrDropped, 1);
  assert.equal(summary.uniqueSecretHashes, 2);
  assert.equal(summary.topRules[0].ruleId, "AWS_ACCESS_KEY");
  assert.equal(summary.topRules[0].count, 2);
  assert.equal(summary.topTools[0].tool, "jira_get_issue");
  assert.equal(summary.topTools[0].events, 2);
  assert.equal(summary.topTools[0].blocked, 1);
  assert.equal(summary.latencyMs.max, 0.45);

  const formatted = formatAuditSummary(summary);
  assert.match(formatted, /=== mcp-guard Audit Log Summary ===/);
  assert.match(formatted, /AWS_ACCESS_KEY: 2/);
  assert.match(formatted, /jira_get_issue: events=2 redacted=1 tainted=0 blocked=1 dropped=0/);
});

test("E2E proxy --audit-log writes correlated JSONL without raw secrets and mcp-guard audit summarizes it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-guard-audit-"));
  const logFile = join(dir, "nested", "audit.jsonl");

  try {
    const outboundAws = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    const req1 = JSON.stringify({
      jsonrpc: "2.0",
      id: "call-1",
      method: "tools/call",
      params: { name: "jira_add_comment", arguments: { body: `Leaked ${outboundAws}` } },
    });
    const req2 = JSON.stringify({
      jsonrpc: "2.0",
      id: "call-2",
      method: "tools/call",
      params: { name: "jira_get_issue", arguments: { key: "HBR-1" } },
    });
    const req3 = JSON.stringify({
      jsonrpc: "2.0",
      id: "call-3",
      method: "tools/call",
      params: { name: "jira_get_issue", arguments: { key: "HBR-2", poison: true } },
    });

    const proxyRes = await runCli(
      [
        "proxy",
        "--block-injections",
        "--audit-log",
        logFile,
        "--",
        process.execPath,
        MOCK_SERVER_PATH,
      ],
      [`${req1}\n`, `${req2}\n`, `${req3}\n`]
    );
    assert.equal(proxyRes.code, 0);

    const logText = readFileSync(logFile, "utf8");
    const entries = logText
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));

    // 3 requests + 3 responses = 6 correlated audit entries
    assert.equal(entries.length, 6);

    // Zero raw secrets or injection snippets anywhere in audit log
    assert.ok(!logText.includes("IOSFODNN7EXAMPLE"));
    assert.ok(!logText.includes("MockServerSecretKey"));
    assert.ok(!logText.includes("maria@client.com"));
    assert.ok(!logText.includes("Ignore previous instructions"));

    // Verify request->response tool correlation
    const outComment = entries.find((e) => e.dir === "agent->mcp" && e.tool === "jira_add_comment");
    assert.equal(outComment.action, "redacted");
    assert.deepEqual(outComment.rules, ["AWS_ACCESS_KEY"]);
    assert.equal(outComment.secretHashes.length, 1);
    assert.match(outComment.secretHashes[0], /^sha256:[0-9a-f]{16}$/);

    const blockedIssue = entries.find((e) => e.dir === "mcp->agent" && e.action === "blocked");
    assert.equal(blockedIssue.method, "tools/call");
    assert.equal(blockedIssue.tool, "jira_get_issue");
    assert.ok(blockedIssue.rules.includes("SHELL_EXFILTRATION"));

    // Verify `mcp-guard audit <logfile>` CLI (text + --json)
    const auditText = await runCli(["audit", logFile]);
    assert.equal(auditText.code, 0);
    assert.match(auditText.stdout, /Events: 6/);
    assert.match(auditText.stdout, /jira_get_issue:/);
    assert.match(auditText.stdout, /AWS_ACCESS_KEY:/);

    const auditJson = await runCli(["audit", logFile, "--json"]);
    assert.equal(auditJson.code, 0);
    const parsedSummary = JSON.parse(auditJson.stdout);
    assert.equal(parsedSummary.totalEvents, 6);
    assert.equal(parsedSummary.byAction.blocked, 1);
    assert.equal(parsedSummary.byAction.redacted, 2);
    assert.ok(parsedSummary.uniqueSecretHashes >= 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
