import test from "node:test";
import assert from "node:assert/strict";
import { runBenchmark } from "../scripts/benchmark.mjs";

test("Scored Apache Kafka corpus enforces 0% benign FP rate, 100% secret catch, honest tripwire recall, and low latency", () => {
  const report = runBenchmark();

  // 1. Real public Apache Kafka JIRA + dev-list corpus (350 items): zero false positives
  assert.equal(report.benignKafka.total, 350);
  assert.equal(
    report.benignKafka.secretFpCount,
    0,
    `Unexpected secret FPs on Kafka corpus: ${JSON.stringify(report.benignKafka.secretFps)}`
  );
  assert.equal(
    report.benignKafka.phoneFpCount,
    0,
    `Unexpected phone/IPv4/version FPs on Kafka corpus: ${JSON.stringify(report.benignKafka.phoneFps)}`
  );
  assert.equal(
    report.benignKafka.injectionFpCount,
    0,
    `Unexpected injection FPs on Kafka corpus: ${JSON.stringify(report.benignKafka.injectionFps)}`
  );

  // 2. Tricky benign engineering probes: zero unexpected taints, zero blocked responses
  assert.equal(
    report.benignProbes.unexpectedTaintCount,
    0,
    `Unexpected taints on benign probes: ${JSON.stringify(report.benignProbes.unexpectedTaints)}`
  );
  assert.equal(
    report.benignProbes.blockedInBlockModeCount,
    0,
    `Benign probes wrongly blocked in --block-injections mode: ${JSON.stringify(report.benignProbes.blockedInBlockMode)}`
  );

  // 3. Planted synthetic secrets: 100% catch rate across all 24 supported formats + IPv4/semver preservation
  assert.equal(report.secrets.total, 24);
  assert.equal(
    report.secrets.missedCount,
    0,
    `Missed planted secrets: ${JSON.stringify(report.secrets.missed)}`
  );

  // 4. Labelled attack corpus (20 structured/reworded/AI-reader/obfuscated + 6 subtle natural-language attacks)
  assert.equal(report.attacks.total, 26);
  assert.ok(
    report.attacks.caughtCount >= 20,
    `Attack catch regression: caught ${report.attacks.caughtCount}/${report.attacks.total} (missed: ${JSON.stringify(report.attacks.missed)})`
  );

  // 5. Latency ceiling on real Kafka JSON-RPC frames (measured ~0.2-0.5ms p99 locally; 5ms ceiling for shared CI runners)
  assert.ok(
    report.latency.p99Ms < 5,
    `p99 latency regression: ${report.latency.p99Ms}ms (expected <5ms)`
  );
});
