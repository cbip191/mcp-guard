import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isWrappedServer, wrapMcpConfig, unwrapMcpConfig } from "../src/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, "../bin/mcp-guard.mjs");

function runCli(args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
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
  });
}

test("wrapMcpConfig and unwrapMcpConfig are idempotent, preserve env/remote servers, and support VS Code servers key", () => {
  const original = {
    mcpServers: {
      github: {
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-github"],
        env: { GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}" },
      },
      remoteLinear: {
        url: "https://mcp.linear.app/sse",
      },
    },
  };

  const w1 = wrapMcpConfig(original, {
    proxyFlags: ["--allow-domain", "agency.dev", "--policy", "./mcp-guard.json"],
  });
  assert.equal(w1.changed, true);
  assert.deepEqual(w1.wrapped, ["github"]);
  assert.deepEqual(w1.alreadyWrapped, []);
  assert.equal(w1.skipped.length, 1);
  assert.equal(w1.skipped[0].name, "remoteLinear");
  assert.equal(isWrappedServer(w1.config.mcpServers.github), true);
  assert.deepEqual(w1.config.mcpServers.github.args, [
    "-y",
    "@4sails/mcp-guard",
    "proxy",
    "--allow-domain",
    "agency.dev",
    "--policy",
    "./mcp-guard.json",
    "--",
    "npx",
    "-y",
    "@modelcontextprotocol/server-github",
  ]);
  assert.deepEqual(w1.config.mcpServers.github.env, original.mcpServers.github.env);

  // Idempotent second wrap
  const w2 = wrapMcpConfig(w1.config);
  assert.equal(w2.changed, false);
  assert.deepEqual(w2.alreadyWrapped, ["github"]);

  // Clean unwrap restores original exact command & args
  const u1 = unwrapMcpConfig(w1.config);
  assert.equal(u1.changed, true);
  assert.deepEqual(u1.unwrapped, ["github"]);
  assert.deepEqual(u1.config, original);

  // VS Code `.vscode/mcp.json` uses top-level `servers`
  const vscodeCfg = { servers: { local: { command: "node", args: ["server.js"] } } };
  const vw = wrapMcpConfig(vscodeCfg);
  assert.equal(vw.serversKey, "servers");
  assert.deepEqual(unwrapMcpConfig(vw.config).config, vscodeCfg);
});

test("CLI wrap --dry-run, wrap --apply (with .bak backup), and unwrap --apply work end-to-end", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-guard-wrap-"));
  const cfgPath = join(dir, "mcp.json");
  const initial = {
    mcpServers: {
      jira: { command: "npx", args: ["-y", "jira-mcp-server"] },
      slack: { command: "npx", args: ["-y", "slack-mcp-server"] },
    },
  };
  writeFileSync(cfgPath, `${JSON.stringify(initial, null, 2)}\n`, "utf8");

  try {
    // 1. Dry-run previews diff and does NOT mutate file
    const dry = await runCli([
      "wrap",
      cfgPath,
      "--dry-run",
      "--server",
      "jira",
      "--allow-domain",
      "agency.dev",
    ]);
    assert.equal(dry.code, 0);
    assert.match(dry.stdout, /\+.*"@4sails\/mcp-guard"/);
    assert.match(dry.stdout, /Dry run only/);
    assert.deepEqual(JSON.parse(readFileSync(cfgPath, "utf8")), initial);
    assert.equal(existsSync(`${cfgPath}.bak`), false);

    // 2. Apply wraps selected server and writes .bak backup
    const applied = await runCli([
      "wrap",
      cfgPath,
      "--apply",
      "--local",
      "--server",
      "jira",
      "--allow-domain",
      "agency.dev",
    ]);
    assert.equal(applied.code, 0);
    assert.equal(existsSync(`${cfgPath}.bak`), true);
    assert.deepEqual(JSON.parse(readFileSync(`${cfgPath}.bak`, "utf8")), initial);

    const wrappedOnDisk = JSON.parse(readFileSync(cfgPath, "utf8"));
    assert.equal(wrappedOnDisk.mcpServers.jira.command, "node");
    assert.equal(isWrappedServer(wrappedOnDisk.mcpServers.jira), true);
    assert.equal(isWrappedServer(wrappedOnDisk.mcpServers.slack), false);

    // 3. Unwrap reverts cleanly back to initial config
    const unwrapped = await runCli(["unwrap", cfgPath, "--apply"]);
    assert.equal(unwrapped.code, 0);
    assert.deepEqual(JSON.parse(readFileSync(cfgPath, "utf8")), initial);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
