import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  POLICY_PRESETS,
  generateStarterPolicy,
  validatePolicy,
} from "../src/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const CLI_PATH = resolve(ROOT, "bin/mcp-guard.mjs");

function runCli(args) {
  try {
    const stdout = execFileSync(process.execPath, [CLI_PATH, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, stdout, stderr: "" };
  } catch (err) {
    return {
      status: err.status ?? 1,
      stdout: err.stdout?.toString("utf8") ?? "",
      stderr: err.stderr?.toString("utf8") ?? "",
    };
  }
}

test("mcp-guard.schema.json is valid JSON, packaged in package.json, and all POLICY_PRESETS pass validatePolicy", () => {
  const schema = JSON.parse(readFileSync(resolve(ROOT, "mcp-guard.schema.json"), "utf8"));
  assert.equal(schema.type, "object");
  assert.ok(schema.properties.$schema);
  assert.ok(schema.properties.tools);
  assert.ok(schema.properties.redaction);
  assert.ok(schema.properties.injection);

  const pkg = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8"));
  assert.ok(pkg.files.includes("mcp-guard.schema.json"));

  for (const preset of POLICY_PRESETS) {
    const raw = generateStarterPolicy(preset);
    assert.ok(typeof raw.$schema === "string" && raw.$schema.endsWith("mcp-guard.schema.json"));
    const validated = validatePolicy(raw);
    assert.ok(validated.tools);
  }

  assert.throws(() => generateStarterPolicy("nonexistent"), /Unknown policy preset/);
  assert.throws(() => validatePolicy({ $schema: 123 }), /\$schema/);
});

test("CLI mcp-guard init and mcp-guard policy test work end-to-end", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-guard-init-"));
  const policyPath = join(dir, "mcp-guard.json");
  try {
    // 1. init with jira preset creates valid policy file
    const initRes = runCli(["init", policyPath, "--preset", "jira"]);
    assert.equal(initRes.status, 0);
    assert.match(initRes.stdout, /Created .*preset: jira/);

    const created = JSON.parse(readFileSync(policyPath, "utf8"));
    assert.deepEqual(created.tools.argConstraints["jira_*"].project_key, ["PROJ"]);

    // 2. init refuses overwrite without --force
    const overwriteBlocked = runCli(["init", policyPath]);
    assert.equal(overwriteBlocked.status, 2);
    assert.match(overwriteBlocked.stderr, /already exists/);

    // 3. init overwrites with --force
    const overwriteOk = runCli(["init", policyPath, "--preset", "github", "--force"]);
    assert.equal(overwriteOk.status, 0);

    // 4. policy test exits 0 when allowed (matching repo glob)
    const allowRes = runCli([
      "policy",
      "test",
      policyPath,
      "github_get_issue",
      '{"repo":"your-org/checkout"}',
      "--json",
    ]);
    assert.equal(allowRes.status, 0);
    const allowJson = JSON.parse(allowRes.stdout);
    assert.equal(allowJson.allowed, true);
    assert.equal(allowJson.ruleId, null);

    // 5. policy test exits 1 when denied by tools.deny
    const denyRes = runCli([
      "policy",
      "test",
      policyPath,
      "github_delete_repo",
      '{"repo":"your-org/checkout"}',
    ]);
    assert.equal(denyRes.status, 1);
    assert.match(denyRes.stdout, /^DENY\s+tool=github_delete_repo rule=POLICY_TOOL_DENIED/);

    // 6. policy test exits 1 when denied by argConstraints
    const badArgRes = runCli([
      "policy",
      "test",
      policyPath,
      "github_get_issue",
      '{"repo":"other-org/secret"}',
      "--json",
    ]);
    assert.equal(badArgRes.status, 1);
    assert.equal(JSON.parse(badArgRes.stdout).ruleId, "POLICY_ARG_CONSTRAINT");

    // 7. policy test exits 2 on invalid JSON args
    const badJsonRes = runCli(["policy", "test", policyPath, "github_get_issue", "{bad"]);
    assert.equal(badJsonRes.status, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
