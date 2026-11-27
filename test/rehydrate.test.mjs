import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPiiPseudonymizer,
  inspectFrame,
  validatePolicy,
} from "../src/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, "../bin/mcp-guard.mjs");
const MOCK_SERVER_PATH = resolve(__dirname, "./fixtures/mock-mcp-server.mjs");

const SYNTHETIC_AWS = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
const SYNTHETIC_STRIPE = ["sk", "live", "51N9xFakeStripeKeyValue987654321"].join("_");

test("createPiiPseudonymizer rehydrateText/rehydratePayload restore known PII tokens, ignore unknown/secret tokens, and reset cleanly", () => {
  const pseudo = createPiiPseudonymizer();
  const emailTok = pseudo.pseudonymize("EMAIL_ADDRESS", "maria@client.com");
  const phoneTok = pseudo.pseudonymize("PHONE_NUMBER", "(555) 234-8910");
  const secretTok = pseudo.pseudonymize("STRIPE_SECRET_KEY", SYNTHETIC_STRIPE);

  assert.equal(emailTok, "[EMAIL_1]");
  assert.equal(phoneTok, "[PHONE_1]");
  assert.equal(secretTok, "[REDACTED:STRIPE_SECRET_KEY]");

  const textRes = pseudo.rehydrateText(
    `Send to ${emailTok} at ${phoneTok} (unknown [EMAIL_99], secret ${secretTok})`
  );
  assert.equal(textRes.rehydratedCount, 2);
  assert.deepEqual(textRes.tokens, ["[EMAIL_1]", "[PHONE_1]"]);
  assert.ok(textRes.text.includes("maria@client.com"));
  assert.ok(textRes.text.includes("(555) 234-8910"));
  assert.ok(textRes.text.includes("[EMAIL_99]"));
  assert.ok(textRes.text.includes("[REDACTED:STRIPE_SECRET_KEY]"));
  assert.ok(!textRes.text.includes(SYNTHETIC_STRIPE));

  const payloadRes = pseudo.rehydratePayload({
    jsonrpc: "2.0",
    id: "[EMAIL_1]",
    method: "tools/call",
    params: { name: "jira_search", arguments: { assignee: "[EMAIL_1]", phone: "[PHONE_1]" } },
  });
  assert.equal(payloadRes.payload.id, "[EMAIL_1]", "JSON-RPC envelope id must stay untouched");
  assert.equal(payloadRes.payload.params.arguments.assignee, "maria@client.com");
  assert.equal(payloadRes.payload.params.arguments.phone, "(555) 234-8910");

  // stats() never exposes raw PII
  assert.ok(!JSON.stringify(pseudo.stats()).includes("maria@client.com"));

  // reset() clears reverse lookup as well
  pseudo.reset();
  const afterReset = pseudo.rehydrateText("Send to [EMAIL_1]");
  assert.equal(afterReset.rehydratedCount, 0);
  assert.equal(afterReset.text, "Send to [EMAIL_1]");
});

test("rehydrateOutboundPii policy supports boolean and per-tool glob allowlists while keeping secrets one-way", () => {
  const boolPolicy = validatePolicy({ redaction: { rehydrateOutboundPii: true } });
  assert.equal(boolPolicy.redaction.rehydrateOutboundPii, true);

  const globPolicy = validatePolicy({
    redaction: { pseudonymizePii: true, rehydrateOutboundPii: ["jira_*"] },
  });
  assert.deepEqual(globPolicy.redaction.rehydrateOutboundPii, ["jira_*"]);

  assert.throws(
    () => validatePolicy({ redaction: { rehydrateOutboundPii: [] } }),
    /at least one tool pattern/
  );
  assert.throws(
    () => validatePolicy({ redaction: { rehydrateOutboundPii: "jira_*" } }),
    /boolean or an array/
  );

  // Per-tool glob: jira_add_comment rehydrates, untrusted_export does NOT
  const pseudo = createPiiPseudonymizer();
  pseudo.pseudonymize("EMAIL_ADDRESS", "maria@client.com");

  const allowedTool = inspectFrame(
    JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "jira_add_comment",
        arguments: { assignee: "[EMAIL_1]", leak: SYNTHETIC_AWS },
      },
    }),
    "agent->mcp",
    {
      pseudonymizePii: true,
      pseudonymizer: pseudo,
      rehydrateOutboundPii: ["jira_*"],
    }
  );
  const allowedMsg = JSON.parse(allowedTool.output);
  assert.equal(allowedMsg.params.arguments.assignee, "maria@client.com");
  assert.equal(allowedMsg.params.arguments.leak, "[REDACTED:AWS_ACCESS_KEY]");

  const blockedTool = inspectFrame(
    JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "untrusted_export",
        arguments: { assignee: "[EMAIL_1]" },
      },
    }),
    "agent->mcp",
    {
      pseudonymizePii: true,
      pseudonymizer: pseudo,
      rehydrateOutboundPii: ["jira_*"],
    }
  );
  const blockedMsg = JSON.parse(blockedTool.output);
  assert.equal(blockedMsg.params.arguments.assignee, "[EMAIL_1]");
});

test("E2E stdio proxy --pseudonymize-pii --rehydrate-outbound-pii enables full read+write PII workflow while keeping secrets redacted", async () => {
  const child = spawn(
    process.execPath,
    [
      CLI_PATH,
      "proxy",
      "--pseudonymize-pii",
      "--rehydrate-outbound-pii",
      "--allow-domain",
      "agency.dev",
      "--",
      process.execPath,
      MOCK_SERVER_PATH,
    ],
    { stdio: ["pipe", "pipe", "pipe"] }
  );

  const stdoutLines = [];
  let buf = "";
  const waiters = [];

  child.stdout.on("data", (chunk) => {
    buf += chunk.toString("utf8");
    let nl;
    while ((nl = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      const parsed = JSON.parse(line);
      const next = waiters.shift();
      if (next) next(parsed);
      else stdoutLines.push(parsed);
    }
  });

  function nextResp() {
    if (stdoutLines.length > 0) return Promise.resolve(stdoutLines.shift());
    return new Promise((r) => waiters.push(r));
  }

  try {
    // Step 1: Inbound response leaks maria@client.com + Stripe key -> agent sees [EMAIL_1] & [REDACTED:STRIPE_SECRET_KEY]
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "leak_secrets" })}\n`);
    const resp1 = await nextResp();
    assert.ok(resp1.result.content[0].text.includes("[EMAIL_1]"));
    assert.ok(resp1.result.content[0].text.includes("[REDACTED:STRIPE_SECRET_KEY]"));
    assert.ok(!resp1.result.content[0].text.includes("maria@client.com"));

    // Step 2: Agent sends [EMAIL_1] (and a secret) back to upstream `echo` -> upstream sees raw maria@client.com (rehydrated),
    // secret is scrubbed to [REDACTED:AWS_ACCESS_KEY], and echoed inbound response re-pseudonymizes back to [EMAIL_1] for the LLM!
    child.stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "echo",
        params: { assignee: "bob@client.io", note: `Notify [EMAIL_1] with ${SYNTHETIC_AWS}` },
      })}\n`
    );
    const resp2 = await nextResp();
    assert.equal(resp2.result.receivedRawAssignee, true);
    assert.ok(resp2.result.echoed.note.includes("[EMAIL_1]"));
    assert.ok(resp2.result.echoed.note.includes("[REDACTED:AWS_ACCESS_KEY]"));
    assert.ok(!resp2.result.echoed.note.includes(SYNTHETIC_AWS));
    assert.ok(!resp2.result.echoed.note.includes("maria@client.com"));

    // Step 3: Now agent calls `echo` with `assignee: "[EMAIL_2]"` (bob@client.io) -> upstream verifies `receivedRawAssignee === true`!
    child.stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "echo",
        params: { assignee: "[EMAIL_2]" },
      })}\n`
    );
    const resp3 = await nextResp();
    assert.equal(resp3.result.receivedRawAssignee, true, "Upstream must receive re-hydrated bob@client.io!");
    assert.equal(resp3.result.echoed.assignee, "[EMAIL_2]", "Agent still only sees [EMAIL_2] on inbound return!");

    child.stdin.end();
    const exitCode = await new Promise((resolveExit, reject) => {
      child.on("error", reject);
      child.on("close", (code) => resolveExit(code));
    });
    assert.equal(exitCode, 0);
  } finally {
    child.stdin.end();
    if (child.exitCode === null) child.kill("SIGTERM");
  }
});
