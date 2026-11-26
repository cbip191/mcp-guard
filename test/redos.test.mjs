import test from "node:test";
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import {
  redactText,
  detectPromptInjection,
  SECRET_RULES,
  PII_RULES,
  INJECTION_PATTERNS,
} from "../src/index.mjs";

const MAX_RULE_MS = 50;

test("ReDoS guard: every secret, PII, and injection rule stays linear (<50ms) on 50KB adversarial inputs", () => {
  const beginHeader = ["-----BEGIN", "PRIVATE KEY-----"].join(" ");
  const adversarialPayloads = [
    `${beginHeader}\n`.repeat(1500),
    `postgres://${"a".repeat(20000)}:${"b".repeat(20000)}`,
    `api_key=${"a".repeat(40000)}`,
    `${"123-456-".repeat(6000)}`,
    `${"ignore all the your previous ".repeat(1500)}warning`,
    `${"curl ".repeat(5000)}${"x".repeat(20000)}`,
    `<system ${"a=b ".repeat(10000)}`,
    `sk-${"a".repeat(45000)}`,
    `${"user@sub.".repeat(5000)}com`,
  ];

  for (const input of adversarialPayloads) {
    const t0 = performance.now();
    redactText(input, { redactPii: true });
    const redactMs = performance.now() - t0;
    assert.ok(
      redactMs < MAX_RULE_MS,
      `redactText took ${redactMs.toFixed(1)}ms on adversarial input (prefix: ${input.slice(0, 32)})`
    );

    const t1 = performance.now();
    detectPromptInjection(input, { threshold: "low" });
    const injectMs = performance.now() - t1;
    assert.ok(
      injectMs < MAX_RULE_MS,
      `detectPromptInjection took ${injectMs.toFixed(1)}ms on adversarial input (prefix: ${input.slice(0, 32)})`
    );
  }

  // Sanity check that rules were actually exercised
  assert.ok(SECRET_RULES.length >= 15);
  assert.ok(PII_RULES.length >= 2);
  assert.ok(INJECTION_PATTERNS.length >= 7);
});
