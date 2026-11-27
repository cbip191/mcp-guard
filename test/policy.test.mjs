import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  matchGlob,
  validatePolicy,
  evaluateToolCallPolicy,
  getOutboundSecretSkipPaths,
  createFrameParser,
  encodeFrame,
} from "../src/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, "../bin/mcp-guard.mjs");
const MOCK_SERVER_PATH = resolve(__dirname, "./fixtures/mock-mcp-server.mjs");

function runProxy(flags, stdinLines) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(
      process.execPath,
      [CLI_PATH, "proxy", ...flags, "--", process.execPath, MOCK_SERVER_PATH],
      { stdio: ["pipe", "pipe", "pipe"] }
    );
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

    for (const line of stdinLines) {
      child.stdin.write(line);
    }
    child.stdin.end();
  });
}

test("matchGlob handles wildcards linearly and validatePolicy fails closed on typos", () => {
  assert.equal(matchGlob("jira_*", "jira_get_issue"), true);
  assert.equal(matchGlob("*_delete*", "jira_delete_issue"), true);
  assert.equal(matchGlob("agency/harbor-?", "agency/harbor-1"), true);
  assert.equal(matchGlob("agency/harbor-?", "agency/harbor-12"), false);

  // Unknown top-level key fails closed so a typo ("tool" vs "tools") never silently disables policy
  assert.throws(() => validatePolicy({ tool: { deny: ["*"] } }), /unknown key "tool"/);
  assert.throws(() => validatePolicy({ tools: { allow: "jira_*" } }), /array of non-empty strings/);
  assert.throws(() => validatePolicy({ injection: { threshold: "bogus" } }), /injection\.threshold/);
});

test("evaluateToolCallPolicy enforces deny-first, allowlist, nested argConstraints, and fail-closed missing args", () => {
  const policy = validatePolicy({
    tools: {
      allow: ["jira_*", "github_*", "vault_write_secret"],
      deny: ["*_delete*", "github_merge_*"],
      argConstraints: {
        "jira_*": { project_key: ["HBR"] },
        "github_*": { "target.repo": ["agency/harbor-*"] },
      },
      allowSecretFields: {
        vault_write_secret: ["value"],
      },
    },
  });

  // Explicit deny beats allow
  const del = evaluateToolCallPolicy("jira_delete_issue", { project_key: "HBR" }, policy);
  assert.equal(del.allowed, false);
  assert.equal(del.ruleId, "POLICY_TOOL_DENIED");

  // Unlisted tool blocked by tools.allow
  const slack = evaluateToolCallPolicy("slack_post_message", { channel_id: "C1" }, policy);
  assert.equal(slack.allowed, false);
  assert.equal(slack.ruleId, "POLICY_TOOL_NOT_ALLOWED");

  // Wrong project_key blocked
  const wrongProj = evaluateToolCallPolicy("jira_get_issue", { project_key: "PIN" }, policy);
  assert.equal(wrongProj.allowed, false);
  assert.equal(wrongProj.ruleId, "POLICY_ARG_CONSTRAINT");

  // Missing constrained argument fails closed
  const missingProj = evaluateToolCallPolicy("jira_get_issue", {}, policy);
  assert.equal(missingProj.allowed, false);
  assert.equal(missingProj.ruleId, "POLICY_ARG_CONSTRAINT");

  // Matching project_key & nested glob repo allowed
  assert.equal(evaluateToolCallPolicy("jira_get_issue", { project_key: "HBR" }, policy).allowed, true);
  assert.equal(
    evaluateToolCallPolicy("github_list_prs", { target: { repo: "agency/harbor-web" } }, policy).allowed,
    true
  );
  assert.equal(
    evaluateToolCallPolicy("github_list_prs", { target: { repo: "other/repo" } }, policy).allowed,
    false
  );

  // Per-tool allowSecretFields resolves cleanly to params.arguments.<field>
  assert.deepEqual(
    [...getOutboundSecretSkipPaths("vault_write_secret", policy)],
    ["params.arguments.value"]
  );
});

test("createFrameParser enforces maxFrameBytes on both NDJSON and Content-Length streams without OOM", () => {
  const frames = [];
  const errors = [];
  const parser = createFrameParser((f) => frames.push(f), {
    maxFrameBytes: 128,
    onError: (e) => errors.push(e),
  });

  // 1. Oversized Content-Length frame is discarded while subsequent valid frame still parses
  const hugeBody = "x".repeat(300);
  parser.push(`Content-Length: 300\r\n\r\n${hugeBody}`);
  parser.push(encodeFrame(JSON.stringify({ jsonrpc: "2.0", id: 1, ok: true }), "content-length"));

  // 2. Oversized NDJSON line without newline is discarded cleanly until \n, then normal framing resumes
  parser.push("a".repeat(200));
  parser.push("b".repeat(200));
  parser.push("\n");
  parser.push(`${JSON.stringify({ jsonrpc: "2.0", id: 2, ok: true })}\n`);
  parser.end();

  assert.equal(errors.length, 2);
  assert.ok(errors.every((e) => e.code === "FRAME_TOO_LARGE"));
  assert.equal(frames.length, 2);
  assert.equal(JSON.parse(frames[0].raw).id, 1);
  assert.equal(JSON.parse(frames[1].raw).id, 2);
});

test("E2E proxy --policy blocks denied tools & bad args before upstream execution, allows per-tool secret fields, and logs to --audit-log", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-guard-policy-"));
  const policyFile = join(dir, "mcp-guard.json");
  const auditFile = join(dir, "audit.jsonl");

  const policy = {
    tools: {
      allow: ["jira_*", "vault_write_secret"],
      deny: ["*_delete*"],
      argConstraints: {
        "jira_*": { project_key: ["HBR"] },
      },
      allowSecretFields: {
        vault_write_secret: ["value"],
      },
    },
  };
  writeFileSync(policyFile, JSON.stringify(policy, null, 2), "utf8");

  try {
    const sampleStripe = ["sk", "live", "51N9xVaultAllowedSecretKey1234567890"].join("_");
    const sampleAws = ["AKIA", "IOSFODNN7EXAMPLE"].join("");

    const reqDeniedTool = JSON.stringify({
      jsonrpc: "2.0",
      id: "p1",
      method: "tools/call",
      params: { name: "jira_delete_issue", arguments: { project_key: "HBR" } },
    });
    const reqBadArg = JSON.stringify({
      jsonrpc: "2.0",
      id: "p2",
      method: "tools/call",
      params: { name: "jira_get_issue", arguments: { project_key: "PIN" } },
    });
    const reqAllowed = JSON.stringify({
      jsonrpc: "2.0",
      id: "p3",
      method: "tools/call",
      params: { name: "jira_get_issue", arguments: { project_key: "HBR" } },
    });
    const reqVault = JSON.stringify({
      jsonrpc: "2.0",
      id: "p4",
      method: "tools/call",
      params: {
        name: "vault_write_secret",
        arguments: { value: sampleStripe, note: `accidental ${sampleAws}` },
      },
    });

    const { code, stdout, stderr } = await runProxy(
      ["--policy", policyFile, "--audit-log", auditFile],
      [`${reqDeniedTool}\n`, `${reqBadArg}\n`, `${reqAllowed}\n`, `${reqVault}\n`]
    );

    assert.equal(code, 0);
    // Confirm denied tool NEVER reached the upstream mock MCP server
    assert.ok(!stderr.includes("DANGER: jira_delete_issue executed"));

    const responses = stdout
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    assert.equal(responses.length, 4);

    const r1 = responses.find((r) => r.id === "p1");
    assert.equal(r1.error.code, -32002);
    assert.equal(r1.error.data.ruleId, "POLICY_TOOL_DENIED");

    const r2 = responses.find((r) => r.id === "p2");
    assert.equal(r2.error.code, -32002);
    assert.equal(r2.error.data.ruleId, "POLICY_ARG_CONSTRAINT");

    const r3 = responses.find((r) => r.id === "p3");
    assert.ok(r3.result);
    assert.match(r3.result.body, /\[REDACTED:STRIPE_SECRET_KEY\]/);

    // vault_write_secret received raw Stripe key in allowlisted `value`, while `note` AWS key was STILL redacted
    const r4 = responses.find((r) => r.id === "p4");
    assert.equal(r4.result.storedRawSecret, true);
    assert.equal(r4.result.noteWasRedacted, true);

    // Audit log recorded both policy blocks and zero raw secrets
    const auditText = readFileSync(auditFile, "utf8");
    assert.ok(!auditText.includes("51N9xVaultAllowed"));
    assert.ok(!auditText.includes("IOSFODNN7EXAMPLE"));
    const entries = auditText
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    assert.ok(entries.some((e) => e.action === "blocked" && e.rules.includes("POLICY_TOOL_DENIED")));
    assert.ok(entries.some((e) => e.action === "blocked" && e.rules.includes("POLICY_ARG_CONSTRAINT")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
