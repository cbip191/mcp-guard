import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  redactText,
  redactPayload,
  guardMcpResponse,
  isValidLuhn,
  isValidIban,
  createPiiPseudonymizer,
  validatePolicy,
} from "../src/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, "../bin/mcp-guard.mjs");
const MOCK_SERVER_PATH = resolve(__dirname, "./fixtures/mock-mcp-server.mjs");
const KAFKA_CORPUS_PATH = resolve(__dirname, "./fixtures/corpus/kafka-benign.jsonl");

const SYNTHETIC_STRIPE = ["sk", "live", "51N9xFakeStripeKeyValue987654321"].join("_");
const SYNTHETIC_GH = ["ghp", "abcdefghijklmnopqrstuvwxyz1234567890"].join("_");

test("CREDIT_CARD (Luhn), US_SSN, and IBAN (MOD-97) catch valid PII and ignore invalid/benign numbers", () => {
  assert.equal(isValidLuhn("4242-4242-4242-4242"), true);
  assert.equal(isValidLuhn("4242-4242-4242-4243"), false);
  assert.equal(isValidIban("DE89 3704 0044 0532 0130 00"), true);
  assert.equal(isValidIban("DE89 3704 0044 0532 0130 01"), false);
  assert.equal(isValidIban("DE89 3704 0044"), false);

  const sample = [
    "Visa: 4242-4242-4242-4242",
    "Amex: 3782 822463 10005",
    "BadCard: 4242-4242-4242-4243",
    "SSN: 123-45-6789",
    "BadSSN1: 000-45-6789 BadSSN2: 666-45-6789 BadSSN3: 901-45-6789 BadSSN4: 123-00-6789",
    "IBAN1: DE89 3704 0044 0532 0130 00",
    "IBAN2: GB29NWBK60161331926819",
    "BadIBAN: DE89 3704 0044 0532 0130 01",
    "UUID: 550e8400-e29b-41d4-a716-446655440000",
    "Date: 2026-11-27 IP: 192.168.100.1",
  ].join("\n");

  const { text, findings } = redactText(sample, { redactPii: true });

  assert.ok(!text.includes("4242-4242-4242-4242"));
  assert.ok(!text.includes("3782 822463 10005"));
  assert.ok(!text.includes("123-45-6789"));
  assert.ok(!text.includes("DE89 3704 0044 0532 0130 00"));
  assert.ok(!text.includes("GB29NWBK60161331926819"));

  // Invalid checksums, invalid SSN ranges, UUIDs, dates, and IPs must remain untouched
  assert.ok(text.includes("4242-4242-4242-4243"));
  assert.ok(text.includes("000-45-6789"));
  assert.ok(text.includes("666-45-6789"));
  assert.ok(text.includes("901-45-6789"));
  assert.ok(text.includes("123-00-6789"));
  assert.ok(text.includes("DE89 3704 0044 0532 0130 01"));
  assert.ok(text.includes("550e8400-e29b-41d4-a716-446655440000"));
  assert.ok(text.includes("2026-11-27"));
  assert.ok(text.includes("192.168.100.1"));

  const ruleIds = findings.map((f) => f.ruleId);
  assert.deepEqual(ruleIds, ["CREDIT_CARD", "CREDIT_CARD", "US_SSN", "IBAN", "IBAN"]);
});

test("Broader PII detectors (CREDIT_CARD, US_SSN, IBAN) have 0 false positives on the 350-item Apache Kafka corpus", () => {
  const rows = readFileSync(KAFKA_CORPUS_PATH, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));

  const fps = [];
  for (const row of rows) {
    const res = redactPayload(row, { redactPii: true });
    for (const f of res.findings) {
      if (f.ruleId === "CREDIT_CARD" || f.ruleId === "US_SSN" || f.ruleId === "IBAN") {
        fps.push({ id: row.id, ruleId: f.ruleId });
      }
    }
  }
  assert.equal(fps.length, 0, `Unexpected financial/ID PII FPs on Kafka corpus: ${JSON.stringify(fps)}`);
});

test("createPiiPseudonymizer maps identical PII consistently across calls while keeping secrets strictly one-way redacted", () => {
  const pseudo = createPiiPseudonymizer();

  const first = redactPayload(
    {
      reporter: "Maria@Client.com",
      cc: "bob@vendor.io",
      note: `Call maria@client.com at (555) 234-8910 with card 4242-4242-4242-4242 and key ${SYNTHETIC_STRIPE}`,
      iban: "DE89 3704 0044 0532 0130 00",
      ssn: "123-45-6789",
    },
    { pseudonymizer: pseudo }
  );

  assert.equal(first.sanitized.reporter, "[EMAIL_1]");
  assert.equal(first.sanitized.cc, "[EMAIL_2]");
  assert.ok(first.sanitized.note.includes("[EMAIL_1]"));
  assert.ok(first.sanitized.note.includes("[PHONE_1]"));
  assert.ok(first.sanitized.note.includes("[CARD_1]"));
  assert.ok(first.sanitized.note.includes("[REDACTED:STRIPE_SECRET_KEY]"));
  assert.equal(first.sanitized.iban, "[IBAN_1]");
  assert.equal(first.sanitized.ssn, "[SSN_1]");

  // Second call in the same session reuses exact same tokens even with different formatting/case
  const second = guardMcpResponse(
    {
      followup: `Reply to BOB@vendor.io or 555-234-8910 about card 4242 4242 4242 4242, IBAN DE89370400440532013000, and ${SYNTHETIC_GH}`,
    },
    { pseudonymizer: pseudo }
  );

  assert.ok(second.sanitized.followup.includes("[EMAIL_2]"));
  assert.ok(second.sanitized.followup.includes("[PHONE_1]"));
  assert.ok(second.sanitized.followup.includes("[CARD_1]"));
  assert.ok(second.sanitized.followup.includes("[IBAN_1]"));
  assert.ok(second.sanitized.followup.includes("[REDACTED:GITHUB_TOKEN]"));

  // Fail-safe: direct pseudonymize() on a secret rule refuses to store it
  assert.equal(pseudo.pseudonymize("STRIPE_SECRET_KEY", SYNTHETIC_STRIPE), "[REDACTED:STRIPE_SECRET_KEY]");

  // Stats report counts only (no raw PII)
  const stats = pseudo.stats();
  assert.equal(stats.totalUnique, 6);
  assert.deepEqual(stats.byType, { EMAIL: 2, PHONE: 1, CARD: 1, IBAN: 1, SSN: 1 });
  assert.ok(!JSON.stringify(stats).includes("client.com"));

  // maxEntries cap fails closed to [REDACTED:<RULE_ID>]
  const capped = createPiiPseudonymizer({ maxEntries: 1 });
  assert.equal(capped.pseudonymize("EMAIL_ADDRESS", "a@example.com"), "[EMAIL_1]");
  assert.equal(capped.pseudonymize("EMAIL_ADDRESS", "b@example.com"), "[REDACTED:EMAIL_ADDRESS]");
  capped.reset();
  assert.equal(capped.stats().totalUnique, 0);
  assert.equal(capped.pseudonymize("EMAIL_ADDRESS", "b@example.com"), "[EMAIL_1]");
});

test("validatePolicy supports redaction.pseudonymizePii and rejects non-boolean values", () => {
  const valid = validatePolicy({ redaction: { pseudonymizePii: true } });
  assert.equal(valid.redaction.pseudonymizePii, true);
  assert.throws(
    () => validatePolicy({ redaction: { pseudonymizePii: "yes" } }),
    /pseudonymizePii/
  );
});

test("E2E stdio proxy --pseudonymize-pii keeps session-consistent PII tokens across calls while redacting secrets one-way", async () => {
  const child = spawn(
    process.execPath,
    [CLI_PATH, "proxy", "--pseudonymize-pii", "--", process.execPath, MOCK_SERVER_PATH],
    { stdio: ["pipe", "pipe", "pipe"] }
  );

  const stdoutChunks = [];
  child.stdout.on("data", (c) => stdoutChunks.push(c));

  const call1 = {
    jsonrpc: "2.0",
    id: 1,
    method: "echo",
    params: {
      message: `Owners: maria@client.com, bob@vendor.io, key=${SYNTHETIC_STRIPE}`,
    },
  };
  const call2 = {
    jsonrpc: "2.0",
    id: 2,
    method: "echo",
    params: {
      message: "Follow-up with BOB@vendor.io and maria@client.com on DE89 3704 0044 0532 0130 00",
    },
  };
  const call3 = {
    jsonrpc: "2.0",
    id: 3,
    method: "leak_secrets",
  };

  child.stdin.write(`${JSON.stringify(call1)}\n${JSON.stringify(call2)}\n${JSON.stringify(call3)}\n`);
  child.stdin.end();

  const exitCode = await new Promise((resolveExit, reject) => {
    child.on("error", reject);
    child.on("close", (code) => resolveExit(code));
  });

  assert.equal(exitCode, 0);
  const responses = Buffer.concat(stdoutChunks)
    .toString("utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));

  assert.equal(responses.length, 3);
  const r1 = responses[0].result.echoed.message;
  const r2 = responses[1].result.echoed.message;
  const r3 = responses[2].result.content[0].text;

  assert.ok(r1.includes("[EMAIL_1]"));
  assert.ok(r1.includes("[EMAIL_2]"));
  assert.ok(r1.includes("[REDACTED:STRIPE_SECRET_KEY]"));
  assert.ok(!r1.includes("maria@client.com"));

  assert.ok(r2.includes("[EMAIL_2]"));
  assert.ok(r2.includes("[EMAIL_1]"));
  assert.ok(r2.includes("[IBAN_1]"));
  assert.ok(!r2.includes("DE89"));

  // Upstream-originated response also reuses [EMAIL_1] for maria@client.com while keeping secret one-way
  assert.ok(r3.includes("[REDACTED:STRIPE_SECRET_KEY]"));
  assert.ok(r3.includes("[EMAIL_1]"));
  assert.ok(!r3.includes("maria@client.com"));
});
