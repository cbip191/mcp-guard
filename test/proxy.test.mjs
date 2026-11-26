import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { createFrameParser, encodeFrame, inspectFrame } from "../src/proxy.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, "../bin/mcp-guard.mjs");
const MOCK_SERVER_PATH = resolve(__dirname, "./fixtures/mock-mcp-server.mjs");

function runProxyCli(proxyFlags, upstreamArgs, stdinChunks) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(
      process.execPath,
      [CLI_PATH, "proxy", ...proxyFlags, "--", ...upstreamArgs],
      { stdio: ["pipe", "pipe", "pipe"] }
    );

    const stdoutChunks = [];
    const stderrChunks = [];

    child.stdout.on("data", (d) => stdoutChunks.push(d));
    child.stderr.on("data", (d) => stderrChunks.push(d));
    child.on("error", reject);
    child.on("close", (code, signal) => {
      resolvePromise({
        code,
        signal,
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
      });
    });

    for (const chunk of stdinChunks) {
      child.stdin.write(chunk);
    }
    child.stdin.end();
  });
}

test("createFrameParser handles split chunks, Content-Length with multi-byte UTF-8, and NDJSON", () => {
  const frames = [];
  const parser = createFrameParser((frame) => frames.push(frame));

  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, result: { text: "Hello 🚀 world" } });
  const clFramed = encodeFrame(body, "content-length");
  const ndjsonLine = `${JSON.stringify({ jsonrpc: "2.0", id: 2, result: "ok" })}\n`;

  // Split mid-header and mid-UTF8 body
  parser.push(clFramed.slice(0, 7));
  parser.push(clFramed.slice(7, 25));
  parser.push(clFramed.slice(25));
  parser.push(ndjsonLine.slice(0, 10));
  parser.push(ndjsonLine.slice(10));
  parser.end();

  assert.equal(frames.length, 2);
  assert.equal(frames[0].framing, "content-length");
  assert.deepEqual(JSON.parse(frames[0].raw).result, { text: "Hello 🚀 world" });
  assert.equal(frames[1].framing, "ndjson");
  assert.equal(JSON.parse(frames[1].raw).id, 2);
});

test("inspectFrame never fails open on unparseable frames", () => {
  const sampleGh = ["ghp", "abcdefghijklmnopqrstuvwxyz1234567890"].join("_");
  const res = inspectFrame(`RAW_GARBAGE token=${sampleGh} email=foo@bar.com`, "mcp->agent", {
    redactPii: true,
  });

  assert.equal(res.unparseable, true);
  assert.equal(res.action, "forward");
  assert.equal(res.findings.length, 2);
  assert.ok(!res.output.includes("abcdefghijklmnopqrstuvwxyz"));
  assert.match(res.output, /\[REDACTED:GITHUB_TOKEN\]/);
  assert.match(res.output, /\[REDACTED:EMAIL_ADDRESS\]/);
});

test("E2E proxy redacts outbound stdin (agent -> MCP) and inbound stdout (MCP -> agent) with --allow-domain", async () => {
  const outboundAws = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
  const outboundSlack = ["xoxb", "111111111111", "2222222222222", "SecretTokenHere"].join("-");

  const req1 = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "echo",
    params: {
      comment: `Pushing ${outboundAws} and ${outboundSlack} for dana@agency.dev and bob@client.io`,
    },
  });
  const req2 = JSON.stringify({
    jsonrpc: "2.0",
    id: 2,
    method: "leak_secrets",
  });

  const { code, stdout, stderr } = await runProxyCli(
    ["--allow-domain", "agency.dev"],
    [process.execPath, MOCK_SERVER_PATH],
    [`${req1}\n`, `${req2}\n`]
  );

  assert.equal(code, 0);
  const lines = stdout.trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(lines.length, 2);

  // Verify upstream server received ALREADY-REDACTED stdin params
  const echoedComment = lines[0].result.echoed.comment;
  assert.match(echoedComment, /\[REDACTED:AWS_ACCESS_KEY\]/);
  assert.match(echoedComment, /\[REDACTED:SLACK_TOKEN\]/);
  assert.ok(echoedComment.includes("dana@agency.dev"));
  assert.ok(!echoedComment.includes("bob@client.io"));
  assert.match(echoedComment, /\[REDACTED:EMAIL_ADDRESS\]/);

  // Verify downstream response was scrubbed while respecting --allow-domain agency.dev
  const leakedText = lines[1].result.content[0].text;
  assert.match(leakedText, /Stripe=\[REDACTED:STRIPE_SECRET_KEY\]/);
  assert.ok(leakedText.includes("Owner=dana@agency.dev"));
  assert.ok(!leakedText.includes("maria@client.com"));

  // Audit telemetry went strictly to stderr
  assert.match(stderr, /dir=agent->mcp/);
  assert.match(stderr, /dir=mcp->agent/);
});

test("E2E proxy supports Content-Length framing and recalculates UTF-8 byte lengths after redaction", async () => {
  const req = JSON.stringify({
    jsonrpc: "2.0",
    id: "cl-1",
    method: "leak_secrets",
  });
  const framedReq = encodeFrame(req, "content-length");

  const { code, stdout } = await runProxyCli(
    ["--allow-domain=agency.dev"],
    [process.execPath, MOCK_SERVER_PATH],
    [framedReq]
  );

  assert.equal(code, 0);
  assert.match(stdout, /^Content-Length: \d+\r\n\r\n/);

  const parsedFrames = [];
  const parser = createFrameParser((f) => parsedFrames.push(f));
  parser.push(stdout);
  parser.end();

  assert.equal(parsedFrames.length, 1);
  assert.equal(parsedFrames[0].framing, "content-length");
  const msg = JSON.parse(parsedFrames[0].raw);
  assert.equal(msg.id, "cl-1");
  assert.match(msg.result.content[0].text, /\[REDACTED:STRIPE_SECRET_KEY\]/);
  assert.ok(msg.result.content[0].text.includes("Emoji=🚀"));
});

test("E2E proxy blocks injected responses without echoing snippets, drops injected notifications, and replies to injected server requests", async () => {
  const req1 = JSON.stringify({ jsonrpc: "2.0", id: 10, method: "send_injection_response" });
  const req2 = JSON.stringify({ jsonrpc: "2.0", id: 11, method: "send_injection_notification" });
  const req3 = JSON.stringify({ jsonrpc: "2.0", id: 12, method: "send_injection_server_request" });

  // Keep stdin open until the upstream server receives the proxy's -32001 reply to its server-initiated request
  const { code, stdout, stderr } = await new Promise((resolvePromise, reject) => {
    const child = spawn(
      process.execPath,
      [CLI_PATH, "proxy", "--block-injections", "--", process.execPath, MOCK_SERVER_PATH],
      { stdio: ["pipe", "pipe", "pipe"] }
    );

    const stdoutChunks = [];
    const stderrChunks = [];
    let stdinClosed = false;

    child.stdout.on("data", (d) => {
      stdoutChunks.push(d);
      const out = Buffer.concat(stdoutChunks).toString("utf8");
      if (!stdinClosed && out.trim().split("\n").length >= 3) {
        stdinClosed = true;
        setTimeout(() => child.stdin.end(), 30);
      }
    });
    child.stderr.on("data", (d) => stderrChunks.push(d));
    child.on("error", reject);
    child.on("close", (exitCode) => {
      resolvePromise({
        code: exitCode,
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
      });
    });

    child.stdin.write(`${req1}\n`);
    child.stdin.write(`${req2}\n`);
    child.stdin.write(`${req3}\n`);
  });

  assert.equal(code, 0);
  const messages = stdout.trim().split("\n").map((l) => JSON.parse(l));
  // Expect 3 messages total: blocked error for id=10, clean ack for id=11 (notification dropped), clean ack for id=12 (server req dropped)
  assert.equal(messages.length, 3);

  // 1) Response with injection -> JSON-RPC -32001 error, NO raw snippet echoed in error.data
  const blockedResp = messages.find((m) => m.id === 10);
  assert.ok(blockedResp.error);
  assert.equal(blockedResp.error.code, -32001);
  assert.ok(blockedResp.error.data.alertCount >= 2);
  assert.ok(blockedResp.error.data.alerts.every((a) => a.snippet === undefined));
  assert.ok(!JSON.stringify(blockedResp).includes("Ignore previous instructions"));
  assert.ok(!JSON.stringify(blockedResp).includes("id_rsa"));

  // 2) Notification with injection -> dropped (only clean ack id=11 arrives)
  assert.ok(!messages.some((m) => m.method === "notifications/message"));
  assert.deepEqual(messages.find((m) => m.id === 11).result, { ok: true });

  // 3) Server-to-client request with injection -> dropped toward agent AND server got -32001 error reply
  assert.ok(!messages.some((m) => m.method === "sampling/createMessage"));
  assert.deepEqual(messages.find((m) => m.id === 12).result, { triggered: true });
  assert.match(stderr, /\[mock-mcp\] server_request_reply=.*"id":"srv-req-1".*"code":-32001/);
});

test("E2E proxy scrubs unparseable raw lines from upstream instead of failing open", async () => {
  const req = JSON.stringify({ jsonrpc: "2.0", id: 20, method: "send_unparseable_secret" });

  const { code, stdout, stderr } = await runProxyCli(
    [],
    [process.execPath, MOCK_SERVER_PATH],
    [`${req}\n`]
  );

  assert.equal(code, 0);
  assert.ok(!stdout.includes("MockServerGitHubToken"));
  assert.ok(!stdout.includes("leak@client.com"));
  assert.match(stdout, /NON_JSON_LOG_LINE token=\[REDACTED:GITHUB_TOKEN\] email=\[REDACTED:EMAIL_ADDRESS\]/);
  assert.match(stderr, /unparseable_frame=true/);
});

test("E2E proxy drains all buffered stdout frames before exiting (no exit race condition)", async () => {
  const count = 25;
  const req = JSON.stringify({ jsonrpc: "2.0", id: 99, method: "burst_and_exit", params: { count } });

  const { code, stdout } = await runProxyCli(
    [],
    [process.execPath, MOCK_SERVER_PATH],
    [`${req}\n`]
  );

  assert.equal(code, 0);
  const lines = stdout.trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(lines.length, count);
  assert.equal(lines[0].result.seq, 1);
  assert.equal(lines[count - 1].result.seq, count);
  assert.ok(lines.every((m) => m.result.token === "[REDACTED:STRIPE_SECRET_KEY]"));
});

test("E2E proxy handles ENOENT cleanly with exit code 127 and stderr diagnostic", async () => {
  const missingBin = resolve(__dirname, "./fixtures/does-not-exist-4sails-test");
  const { code, stdout, stderr } = await runProxyCli([], [missingBin], []);

  assert.equal(code, 127);
  assert.equal(stdout, "");
  assert.match(stderr, /spawn_error.*ENOENT/);
});

test("E2E proxy supports --taint-untrusted and --injection-threshold without dropping clean fields", async () => {
  const req = JSON.stringify({ jsonrpc: "2.0", id: 30, method: "send_injection_response" });

  const { code, stdout, stderr } = await runProxyCli(
    ["--taint-untrusted", "--injection-threshold", "high"],
    [process.execPath, MOCK_SERVER_PATH],
    [`${req}\n`]
  );

  assert.equal(code, 0);
  const msg = JSON.parse(stdout.trim());
  assert.equal(msg.id, 30);
  assert.ok(msg.result);
  assert.match(msg.result.body, /^\[MCP_GUARD_UNTRUSTED_DATA rules=.*severity=critical/);
  assert.ok(msg.result.body.endsWith("[/MCP_GUARD_UNTRUSTED_DATA]"));
  assert.match(stderr, /action=tainted/);
});

test("E2E proxy forwards SIGTERM to upstream child and exits cleanly", async () => {
  const result = await new Promise((resolvePromise, reject) => {
    const child = spawn(
      process.execPath,
      [CLI_PATH, "proxy", "--", process.execPath, MOCK_SERVER_PATH, "sleep"],
      { stdio: ["pipe", "pipe", "pipe"] }
    );

    let stderr = "";
    child.stderr.on("data", (d) => {
      stderr += d.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (code, signal) => resolvePromise({ code, signal, stderr }));

    setTimeout(() => {
      child.kill("SIGTERM");
    }, 150);
  });

  assert.equal(result.code, 0);
  assert.match(result.stderr, /\[mock-mcp\] received SIGTERM/);
});
