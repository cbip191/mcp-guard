#!/usr/bin/env node
/**
 * Reproducible precision, recall, false-positive, and latency benchmark over:
 * - 350 real public Apache Kafka JIRA issues & dev@kafka.apache.org emails
 * - 8 tricky benign engineering probes
 * - 24 labelled indirect prompt-injection attacks (including subtle natural-language misses)
 * - 24 planted synthetic secrets across every supported format (constructed at runtime)
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import {
  redactPayload,
  redactText,
  detectPromptInjection,
  inspectFrame,
} from "../src/index.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS_DIR = resolve(ROOT, "test/fixtures/corpus");

export function buildPlantedSecrets() {
  return [
    { id: "AWS_ACCESS_KEY", value: ["AKIA", "IOSFODNN7EXAMPLE"].join("") },
    {
      id: "AWS_SECRET_ACCESS_KEY",
      value: `AWS_SECRET_ACCESS_KEY=${["wJalrXUtnFEMI", "K7MDENG", "bPxRfiCYExampleKey"].join("/")}`,
    },
    { id: "GITHUB_TOKEN", value: ["ghp", "abcdefghijklmnopqrstuvwxyz1234567890"].join("_") },
    { id: "GITHUB_FINE_GRAINED_PAT", value: ["github_pat", "11AAAAAA0123456789abcdefghij"].join("_") },
    { id: "GITLAB_PAT", value: ["glpat", "AbCdEfGhIjKlMnOpQrStUvWx"].join("-") },
    { id: "ATLASSIAN_API_TOKEN", value: ["ATATT3x", "FfGF0FakeJiraTokenValue1234567890ABCDEF"].join("") },
    { id: "GCP_API_KEY", value: ["AIza", "SyFakeGcpApiKeyExample0123456789AbC"].join("") },
    { id: "GEMINI_API_KEY", value: `GEMINI_API_KEY=${["AIza", "SyFakeGeminiApiKeyExam0123456789XyZ"].join("")}` },
    { id: "MISTRAL_API_KEY", value: `MISTRAL_API_KEY=${["M9kP2xQ7vL4nR8wT", "1yB6zC3fH5jD0sA9"].join("")}` },
    { id: "NPM_TOKEN", value: ["npm", "1234567890abcdefghijklmnopqrstuvwxyz"].join("_") },
    { id: "PYPI_TOKEN", value: ["pypi", "AgEIcHlwaS5vcmcFakePypiTokenBody0123456789ABCDEFGHIJ"].join("-") },
    { id: "SLACK_TOKEN", value: ["xoxb", "123456789012", "1234567890123", "abcdefghijklmnop"].join("-") },
    { id: "SLACK_WEBHOOK", value: ["https://hooks.slack.com/services", "T00000001", "B00000002", "XXXXXXXXXXXXXXXXXXXXXXXX"].join("/") },
    { id: "STRIPE_SECRET_KEY", value: ["sk", "live", "51N9xExampleSecretKey1234567890"].join("_") },
    { id: "ANTHROPIC_API_KEY", value: ["sk", "ant", "api03", "FakeAnthropicKeyValue9876543210ABC"].join("-") },
    {
      id: "OPENROUTER_API_KEY",
      value: ["sk", "or", "v1", "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"].join("-"),
    },
    { id: "OPENAI_API_KEY", value: ["sk", "proj", "FakeOpenAiProjectKey9876543210XYZ"].join("-") },
    { id: "GROQ_API_KEY", value: ["gsk", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMn"].join("_") },
    { id: "HUGGINGFACE_TOKEN", value: ["hf", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"].join("_") },
    { id: "PERPLEXITY_API_KEY", value: ["pplx", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2"].join("-") },
    { id: "XAI_API_KEY", value: ["xai", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh"].join("-") },
    {
      id: "PRIVATE_KEY_BLOCK",
      value: `${["-----BEGIN", "ENCRYPTED", "PRIVATE KEY-----"].join(" ")}\n${["MIIFDjBABgkqhkiG9w0BBQ0w", "MzAbBgkqhkiG9w0BBQwwDgQI"].join("")}`,
    },
    { id: "DATABASE_URI_CREDENTIALS", value: "redis://:s3cr3tpass@cache.internal:6379/0" },
    {
      id: "HIGH_ENTROPY_SECRET",
      value: `STRIPE_WEBHOOK_SECRET=${["K9mP2xQ7", "vL4nR8wT", "1yB6zC3f"].join("")}`,
    },
  ];
}

export function runBenchmark() {
  const kafkaRows = readFileSync(resolve(CORPUS_DIR, "kafka-benign.jsonl"), "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));
  const attacks = JSON.parse(readFileSync(resolve(CORPUS_DIR, "attacks.json"), "utf8"));
  const benignProbes = JSON.parse(readFileSync(resolve(CORPUS_DIR, "benign-probes.json"), "utf8"));
  const plantedSecrets = buildPlantedSecrets();

  // 1. Score benign Apache Kafka corpus (secret FPs, phone/IPv4/version FPs, injection FPs, latency)
  const kafkaSecretFps = [];
  const kafkaPhoneFps = [];
  const kafkaInjectionFps = [];
  const latenciesMs = [];
  let totalBytes = 0;

  for (const row of kafkaRows) {
    const rpc = JSON.stringify({ jsonrpc: "2.0", id: row.id, result: row });
    totalBytes += Buffer.byteLength(rpc, "utf8");

    const t0 = performance.now();
    const res = inspectFrame(rpc, "mcp->agent", {
      redactPii: false,
      taintUntrusted: true,
      blockInjections: false,
      injectionThreshold: "medium",
    });
    latenciesMs.push(performance.now() - t0);

    if (res.findings.length > 0) {
      kafkaSecretFps.push({ id: row.id, rules: res.findings.map((f) => f.ruleId) });
    }
    if (res.injectionAlerts.length > 0) {
      kafkaInjectionFps.push({ id: row.id, rules: res.injectionAlerts.map((a) => a.ruleId) });
    }

    // Verify phone/IPv4/version safety under redactPii: true
    const piiRes = redactPayload(row, { redactPii: true });
    const phoneFindings = piiRes.findings.filter((f) => f.ruleId === "PHONE_NUMBER");
    if (phoneFindings.length > 0) {
      kafkaPhoneFps.push({ id: row.id, previews: phoneFindings.map((f) => f.preview) });
    }
  }

  // 2. Score tricky benign engineering probes
  const probeUnexpectedTaints = [];
  const probeBlockedInBlockMode = [];
  for (const probe of benignProbes) {
    const rpc = JSON.stringify({ jsonrpc: "2.0", id: probe.id, result: { body: probe.text } });
    const taintRes = inspectFrame(rpc, "mcp->agent", {
      redactPii: false,
      taintUntrusted: true,
      blockInjections: false,
      injectionThreshold: "medium",
    });
    if (!probe.allowTaint && taintRes.injectionAlerts.length > 0) {
      probeUnexpectedTaints.push({ id: probe.id, rules: taintRes.injectionAlerts.map((a) => a.ruleId) });
    }
    const blockRes = inspectFrame(rpc, "mcp->agent", {
      redactPii: false,
      taintUntrusted: true,
      blockInjections: true,
      injectionThreshold: "medium",
    });
    if (blockRes.action === "replace" || blockRes.action === "drop") {
      probeBlockedInBlockMode.push({ id: probe.id, rules: blockRes.injectionAlerts.map((a) => a.ruleId) });
    }
  }

  // 3. Score labelled attack corpus planted inside real Kafka tickets
  const attacksCaught = [];
  const attacksMissed = [];
  for (let i = 0; i < attacks.length; i++) {
    const atk = attacks[i];
    const hostTicket = kafkaRows[i % kafkaRows.length];
    const planted = {
      ...hostTicket,
      comments: [...(hostTicket.comments || []), atk.text],
    };
    const alerts = detectPromptInjection(planted, { threshold: "medium" });
    if (alerts.length > 0) {
      attacksCaught.push({
        id: atk.id,
        category: atk.category,
        rules: [...new Set(alerts.map((a) => a.ruleId))],
      });
    } else {
      attacksMissed.push({ id: atk.id, category: atk.category });
    }
  }

  // 4. Score planted synthetic secrets inside real Kafka tickets
  const secretsCaught = [];
  const secretsMissed = [];
  for (let i = 0; i < plantedSecrets.length; i++) {
    const sec = plantedSecrets[i];
    const hostTicket = kafkaRows[i % kafkaRows.length];
    const text = `${hostTicket.summary}\n${sec.value}\nBroker 192.168.100.1 v4.5.0`;
    const { text: out, findings } = redactText(text, { redactPii: true });
    const matched = findings.some((f) => f.ruleId === sec.id);
    const preservedIpAndVersion = out.includes("192.168.100.1") && out.includes("v4.5.0");
    if (matched && preservedIpAndVersion) {
      secretsCaught.push(sec.id);
    } else {
      secretsMissed.push({ id: sec.id, matched, preservedIpAndVersion });
    }
  }

  latenciesMs.sort((a, b) => a - b);
  const pct = (q) => Number(latenciesMs[Math.min(latenciesMs.length - 1, Math.floor(latenciesMs.length * q))].toFixed(3));
  const totalTimeMs = latenciesMs.reduce((a, b) => a + b, 0);

  return {
    benignKafka: {
      total: kafkaRows.length,
      totalKb: Number((totalBytes / 1024).toFixed(1)),
      secretFpCount: kafkaSecretFps.length,
      secretFps: kafkaSecretFps,
      phoneFpCount: kafkaPhoneFps.length,
      phoneFps: kafkaPhoneFps,
      injectionFpCount: kafkaInjectionFps.length,
      injectionFps: kafkaInjectionFps,
    },
    benignProbes: {
      total: benignProbes.length,
      unexpectedTaintCount: probeUnexpectedTaints.length,
      unexpectedTaints: probeUnexpectedTaints,
      blockedInBlockModeCount: probeBlockedInBlockMode.length,
      blockedInBlockMode: probeBlockedInBlockMode,
    },
    attacks: {
      total: attacks.length,
      caughtCount: attacksCaught.length,
      missedCount: attacksMissed.length,
      catchRatePct: Number(((attacksCaught.length / attacks.length) * 100).toFixed(1)),
      caught: attacksCaught,
      missed: attacksMissed,
    },
    secrets: {
      total: plantedSecrets.length,
      caughtCount: secretsCaught.length,
      missedCount: secretsMissed.length,
      catchRatePct: Number(((secretsCaught.length / plantedSecrets.length) * 100).toFixed(1)),
      missed: secretsMissed,
    },
    latency: {
      p50Ms: pct(0.5),
      p95Ms: pct(0.95),
      p99Ms: pct(0.99),
      totalMs: Number(totalTimeMs.toFixed(1)),
      throughputMbPerSec: Number(((totalBytes / (1024 * 1024)) / (totalTimeMs / 1000)).toFixed(1)),
    },
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const report = runBenchmark();
  console.log(JSON.stringify(report, null, 2));
}
