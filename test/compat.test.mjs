import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  resolveSpawnSpec,
  inspectFrame,
  encodeFrame,
  createFrameParser,
  wrapMcpConfig,
  unwrapMcpConfig,
} from "../src/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, "../bin/mcp-guard.mjs");

const SYNTHETIC_GH = ["ghp", "abcdefghijklmnopqrstuvwxyz1234567890"].join("_");

test("Full MCP 2025-03-26 protocol lifecycle (initialize, tools/list GitHub+Filesystem schemas, resources, prompts) passes with zero false positives", () => {
  const initRes = {
    jsonrpc: "2.0",
    id: 1,
    result: {
      protocolVersion: "2025-03-26",
      capabilities: { tools: { listChanged: true }, resources: {}, prompts: {} },
      serverInfo: { name: "@modelcontextprotocol/server-filesystem", version: "0.6.2" },
    },
  };

  const toolsListRes = {
    jsonrpc: "2.0",
    id: 2,
    result: {
      tools: [
        {
          name: "read_file",
          description: "Read the complete contents of a file from the file system, e.g. /workspace/README.md or .env.example.",
          inputSchema: {
            $schema: "http://json-schema.org/draft-07/schema#",
            type: "object",
            properties: {
              path: { type: "string", description: "Absolute or relative file path" },
            },
            required: ["path"],
          },
        },
        {
          name: "search_issues",
          description: "Search GitHub issues and pull requests by assignee, labels, or milestone.",
          inputSchema: {
            $schema: "http://json-schema.org/draft-07/schema#",
            type: "object",
            properties: {
              q: { type: "string", description: "GitHub search query such as repo:org/app is:open" },
              page: { type: "number" },
            },
            required: ["q"],
          },
        },
      ],
    },
  };

  const resourcesListRes = {
    jsonrpc: "2.0",
    id: 3,
    result: {
      resources: [
        { uri: "file:///workspace/package.json", name: "package.json", mimeType: "application/json" },
      ],
    },
  };

  const promptsListRes = {
    jsonrpc: "2.0",
    id: 4,
    result: {
      prompts: [
        { name: "review_pr", description: "Review a GitHub pull request diff for security issues." },
      ],
    },
  };

  for (const frame of [initRes, toolsListRes, resourcesListRes, promptsListRes]) {
    const inspected = inspectFrame(JSON.stringify(frame), "mcp->agent", {
      taintUntrusted: true,
      blockInjections: true,
      redactPii: true,
    });
    assert.equal(inspected.action, "forward");
    assert.equal(inspected.findings.length, 0);
    assert.equal(inspected.injectionAlerts.length, 0);
    assert.deepEqual(JSON.parse(inspected.output), frame);
  }

  // Verify JSON-RPC Content-Length framing round-trip over tools/list + secret-bearing read_file response
  const readFileRes = {
    jsonrpc: "2.0",
    id: 5,
    result: {
      content: [{ type: "text", text: `GITHUB_TOKEN=${SYNTHETIC_GH}\nPORT=8080\n` }],
    },
  };
  const inspectedRead = inspectFrame(JSON.stringify(readFileRes), "mcp->agent");
  const wire = encodeFrame(inspectedRead.output, "content-length");
  const parsedFrames = [];
  const parser = createFrameParser((f) => parsedFrames.push(f));
  parser.push(wire);
  parser.end();

  assert.equal(parsedFrames.length, 1);
  assert.equal(parsedFrames[0].framing, "content-length");
  const decoded = JSON.parse(parsedFrames[0].raw);
  assert.ok(decoded.result.content[0].text.includes("[REDACTED:GITHUB_TOKEN]"));
  assert.ok(decoded.result.content[0].text.includes("PORT=8080"));
  assert.ok(!decoded.result.content[0].text.includes(SYNTHETIC_GH));
});

test("resolveSpawnSpec handles Windows npx/.cmd shims safely while leaving Unix and native binaries untouched", () => {
  const unixSpec = resolveSpawnSpec("npx", ["-y", "@modelcontextprotocol/server-github"], "linux");
  assert.equal(unixSpec.command, "npx");
  assert.deepEqual(unixSpec.args, ["-y", "@modelcontextprotocol/server-github"]);
  assert.deepEqual(unixSpec.options, {});

  const macSpec = resolveSpawnSpec("npx", ["-y", "@modelcontextprotocol/server-github"], "darwin");
  assert.equal(macSpec.command, "npx");
  assert.deepEqual(macSpec.options, {});

  const winNode = resolveSpawnSpec("node", ["server.mjs"], "win32");
  assert.equal(winNode.command, "node");
  assert.deepEqual(winNode.options, {});

  const winNpx = resolveSpawnSpec("npx", ["-y", "@modelcontextprotocol/server-filesystem", "C:\\My Docs\\dir"], "win32");
  assert.ok(winNpx.command.toLowerCase().endsWith("cmd.exe"));
  assert.equal(winNpx.args[0], "/d");
  assert.equal(winNpx.args[1], "/s");
  assert.equal(winNpx.args[2], "/c");
  assert.ok(winNpx.args[3].includes("npx.cmd"));
  assert.ok(winNpx.args[3].includes("@modelcontextprotocol/server-filesystem"));
  assert.ok(winNpx.args[3].includes('"C:\\My Docs\\dir"'));
  assert.equal(winNpx.options.windowsVerbatimArguments, true);
  assert.equal(winNpx.options.windowsHide, true);
});

test("Windows live .cmd shim execution through mcp-guard proxy works end-to-end", {
  skip: process.platform !== "win32",
}, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-guard-win-cmd-"));
  const shimPath = join(dir, "echo-mcp.cmd");
  try {
    writeFileSync(
      shimPath,
      `@echo off\r\n"${process.execPath}" -e "process.stdin.on('data', d => process.stdout.write(d));"\r\n`
    );

    const child = spawn(
      process.execPath,
      [CLI_PATH, "proxy", "--", shimPath],
      { stdio: ["pipe", "pipe", "pipe"] }
    );

    const stdoutChunks = [];
    child.stdout.on("data", (c) => stdoutChunks.push(c));

    const req = {
      jsonrpc: "2.0",
      id: 1,
      result: { text: `leaked ${SYNTHETIC_GH}` },
    };
    child.stdin.write(`${JSON.stringify(req)}\n`);
    child.stdin.end();

    const exitCode = await new Promise((resolveExit, reject) => {
      child.on("error", reject);
      child.on("close", (code) => resolveExit(code));
    });

    assert.equal(exitCode, 0);
    const out = JSON.parse(Buffer.concat(stdoutChunks).toString("utf8").trim());
    assert.ok(out.result.text.includes("[REDACTED:GITHUB_TOKEN]"));
    assert.ok(!out.result.text.includes(SYNTHETIC_GH));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("wrap/unwrap round-trips Cursor, Claude Desktop, Claude Code, and VS Code multi-server configs cleanly", () => {
  const configs = [
    {
      name: "Cursor / Claude Desktop / Claude Code",
      raw: {
        mcpServers: {
          filesystem: {
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
            env: { NODE_ENV: "production" },
          },
          github: {
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-github"],
            env: { GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}" },
          },
          linearRemote: {
            url: "https://mcp.linear.app/sse",
          },
        },
      },
    },
    {
      name: "VS Code servers layout",
      raw: {
        servers: {
          postgres: {
            type: "stdio",
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/app"],
          },
          stripeRemote: {
            type: "http",
            url: "https://mcp.stripe.com",
          },
        },
      },
    },
  ];

  for (const { raw } of configs) {
    const wrapped = wrapMcpConfig(raw, { proxyFlags: ["--allow-domain", "agency.dev"] });
    assert.equal(wrapped.changed, true);
    assert.equal(wrapped.skipped.length, 1);

    // Second wrap is a no-op
    const wrappedAgain = wrapMcpConfig(wrapped.config, { proxyFlags: ["--allow-domain", "agency.dev"] });
    assert.equal(wrappedAgain.changed, false);

    // Unwrap restores original config identically
    const unwrapped = unwrapMcpConfig(wrapped.config);
    assert.equal(unwrapped.changed, true);
    assert.deepEqual(unwrapped.config, raw);
  }
});
