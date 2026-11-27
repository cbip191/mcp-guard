import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  compileSafeRegex,
  redactText,
  redactPayload,
  guardMcpResponse,
  validatePolicy,
} from "../src/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, "../bin/mcp-guard.mjs");
const MOCK_SERVER_PATH = resolve(__dirname, "./fixtures/mock-mcp-server.mjs");

const SYNTHETIC_STRIPE = ["sk", "live", "51N9xFakeStripeKeyValue987654321"].join("_");
const SYNTHETIC_ACME = ["acme", "tok", "9f8e7d6c5b4a3210fedcba"].join("_");

test("compileSafeRegex accepts valid rules and rejects invalid syntax, bad flags, and ReDoS patterns", () => {
  const ok = compileSafeRegex("acme_tok_[a-z0-9]{16}", "i", { requireGlobal: true });
  assert.equal(ok.global, true);
  assert.equal(ok.ignoreCase, true);

  const allow = compileSafeRegex("^555-01\\d{2}$", "g", { requireGlobal: false });
  assert.equal(allow.global, false);

  assert.throws(() => compileSafeRegex("", ""), /non-empty/);
  assert.throws(() => compileSafeRegex("[unclosed", ""), /Invalid regex syntax/);
  assert.throws(() => compileSafeRegex("abc", "y"), /unsupported flag/);
  assert.throws(() => compileSafeRegex("(a+)+", ""), /Unsafe regex rejected/);
  assert.throws(() => compileSafeRegex("^(a|a)+$", ""), /Unsafe regex rejected/);
});

test("disabledRules, customRules, and allowPatterns work across redactText, redactPayload, and guardMcpResponse", () => {
  // 1. disabledRules suppresses PHONE_NUMBER and context-aware HIGH_ENTROPY_SECRET while keeping other rules
  const res1 = redactText(`Call 555-234-8910 or email maria@client.com key=${SYNTHETIC_STRIPE}`, {
    disabledRules: ["PHONE_NUMBER"],
  });
  assert.ok(res1.text.includes("555-234-8910"));
  assert.ok(!res1.text.includes("maria@client.com"));
  assert.ok(res1.text.includes("[REDACTED:STRIPE_SECRET_KEY]"));

  const highEntropyVal = ["K9mP2xQ7", "vL4nR8wT", "1yB6zC3f"].join("");
  const resEntropy = redactPayload(
    { api_secret: highEntropyVal },
    { disabledRules: ["HIGH_ENTROPY_SECRET"] }
  );
  assert.equal(resEntropy.sanitized.api_secret, highEntropyVal);
  assert.equal(resEntropy.findings.length, 0);

  // 2. customRules redacts org-specific tokens (always one-way even under pseudonymizePii)
  const res2 = guardMcpResponse(
    { body: `Internal ${SYNTHETIC_ACME} for maria@client.com` },
    {
      pseudonymizePii: true,
      customRules: [{ id: "ACME_INTERNAL_TOKEN", pattern: "acme_tok_[a-z0-9]{16,32}", severity: "critical" }],
    }
  );
  assert.ok(res2.sanitized.body.includes("[REDACTED:ACME_INTERNAL_TOKEN]"));
  assert.ok(res2.sanitized.body.includes("[EMAIL_1]"));
  assert.ok(!res2.sanitized.body.includes(SYNTHETIC_ACME));

  // 3. allowPatterns preserves benign matches while still redacting non-allowed matches
  const res3 = redactText("Demo: 555-010-1234 Real: 555-234-8910", {
    allowPatterns: ["^555-010-\\d{4}$"],
  });
  assert.ok(res3.text.includes("555-010-1234"));
  assert.ok(!res3.text.includes("555-234-8910"));
  assert.equal(res3.findings.length, 1);
});

test("validatePolicy enforces strict fail-closed validation on disabledRules, customRules, and allowPatterns", () => {
  const valid = validatePolicy({
    redaction: {
      disabledRules: ["PHONE_NUMBER", "US_SSN"],
      customRules: [{ id: "ACME_TOKEN", pattern: "acme_tok_[a-z0-9]{16,32}", severity: "critical" }],
      allowPatterns: ["^555-010-\\d{4}$"],
    },
  });
  assert.deepEqual(valid.redaction.disabledRules, ["PHONE_NUMBER", "US_SSN"]);
  assert.equal(valid.redaction.customRules.length, 1);
  assert.equal(valid.redaction.customRules[0].pattern instanceof RegExp, true);
  assert.equal(valid.redaction.allowPatterns[0] instanceof RegExp, true);

  // Unknown built-in rule typo fails closed
  assert.throws(
    () => validatePolicy({ redaction: { disabledRules: ["PHNE_NUMBER"] } }),
    /unknown built-in rule/
  );
  // Colliding with built-in rule fails closed
  assert.throws(
    () => validatePolicy({ redaction: { customRules: [{ id: "STRIPE_SECRET_KEY", pattern: "abc" }] } }),
    /duplicate or built-in colliding/
  );
  // Lowercase custom rule id fails closed
  assert.throws(
    () => validatePolicy({ redaction: { customRules: [{ id: "acme_token", pattern: "abc" }] } }),
    /must match/
  );
  // ReDoS custom rule fails closed
  assert.throws(
    () => validatePolicy({ redaction: { customRules: [{ id: "BAD_REDOS", pattern: "(a+)+" }] } }),
    /Unsafe regex rejected/
  );
  // ReDoS allowPattern fails closed
  assert.throws(
    () => validatePolicy({ redaction: { allowPatterns: ["(a+)+"] } }),
    /Unsafe regex rejected/
  );
});

test("E2E stdio proxy --policy applies disabledRules, customRules, and allowPatterns", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-guard-custom-"));
  const policyPath = join(dir, "mcp-guard.json");
  try {
    writeFileSync(
      policyPath,
      JSON.stringify({
        redaction: {
          disabledRules: ["PHONE_NUMBER"],
          customRules: [
            { id: "ACME_INTERNAL_TOKEN", pattern: "acme_tok_[a-z0-9]{16,32}", severity: "critical" },
          ],
          allowPatterns: ["^allowed-bot@client\\.example$"],
        },
      })
    );

    const child = spawn(
      process.execPath,
      [CLI_PATH, "proxy", "--policy", policyPath, "--", process.execPath, MOCK_SERVER_PATH],
      { stdio: ["pipe", "pipe", "pipe"] }
    );

    const stdoutChunks = [];
    child.stdout.on("data", (c) => stdoutChunks.push(c));

    const req = {
      jsonrpc: "2.0",
      id: 1,
      method: "echo",
      params: {
        body: `Phone 555-234-8910, bot allowed-bot@client.example, real maria@client.com, tok ${SYNTHETIC_ACME}`,
      },
    };
    child.stdin.write(`${JSON.stringify(req)}\n`);
    child.stdin.end();

    const exitCode = await new Promise((resolveExit, reject) => {
      child.on("error", reject);
      child.on("close", (code) => resolveExit(code));
    });

    assert.equal(exitCode, 0);
    const resp = JSON.parse(Buffer.concat(stdoutChunks).toString("utf8").trim());
    const out = resp.result.echoed.body;

    assert.ok(out.includes("555-234-8910"), "disabled PHONE_NUMBER should be preserved");
    assert.ok(out.includes("allowed-bot@client.example"), "allowPatterns email should be preserved");
    assert.ok(!out.includes("maria@client.com"), "non-allowed email should be redacted");
    assert.ok(out.includes("[REDACTED:ACME_INTERNAL_TOKEN]"), "custom rule should redact token");
    assert.ok(!out.includes(SYNTHETIC_ACME));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
