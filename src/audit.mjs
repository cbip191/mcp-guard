/**
 * Append-only structured JSONL audit logging & summary aggregation for mcp-guard.
 * Never logs raw secrets, previews, or raw prompt-injection snippets — only rule IDs
 * and one-way SHA-256 fingerprints (`sha256:...`).
 */
import { createWriteStream, mkdirSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Builds a canonical JSONL audit event record.
 */
export function buildAuditEntry({
  ts = new Date().toISOString(),
  dir,
  method = null,
  tool = null,
  action = "allow",
  findings = [],
  injectionAlerts = [],
  extraRules = [],
  latencyMs = 0,
}) {
  const ruleSet = new Set();
  const hashSet = new Set();

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    if (f?.ruleId) ruleSet.add(f.ruleId);
    if (typeof f?.hash === "string" && f.hash.startsWith("sha256:")) {
      hashSet.add(f.hash);
    }
  }
  for (let i = 0; i < injectionAlerts.length; i++) {
    const a = injectionAlerts[i];
    if (a?.ruleId) ruleSet.add(a.ruleId);
  }
  for (let i = 0; i < extraRules.length; i++) {
    if (typeof extraRules[i] === "string" && extraRules[i].length > 0) {
      ruleSet.add(extraRules[i]);
    }
  }

  return {
    ts,
    dir,
    method: method ?? null,
    tool: tool ?? null,
    action,
    rules: [...ruleSet],
    secretHashes: [...hashSet],
    latencyMs: Number(Number(latencyMs).toFixed(3)),
  };
}

/**
 * Opens an append-only JSONL audit log stream with owner-only permissions (0600 on POSIX).
 */
export function createAuditLogger(filePath, options = {}) {
  const { onError = null } = options;
  mkdirSync(dirname(filePath), { recursive: true });
  const stream = createWriteStream(filePath, {
    flags: "a",
    encoding: "utf8",
    mode: 0o600,
  });

  let closed = false;

  stream.on("error", (err) => {
    if (onError) onError(err);
  });

  return {
    write(entry) {
      if (closed || stream.destroyed) return false;
      try {
        stream.write(`${JSON.stringify(entry)}\n`);
        return true;
      } catch (err) {
        if (onError) onError(err);
        return false;
      }
    },
    close() {
      if (closed) return Promise.resolve();
      closed = true;
      return new Promise((resolve) => {
        if (stream.destroyed || stream.writableEnded) {
          resolve();
          return;
        }
        stream.once("finish", resolve);
        stream.once("error", resolve);
        stream.end();
      });
    },
  };
}

function percentile(sorted, q) {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * q));
  return Number(sorted[idx].toFixed(3));
}

/**
 * Aggregates a JSONL audit log string into counts, top rules, top tools,
 * blocked/dropped totals, unique secret hashes, and latency percentiles.
 */
export function summarizeAuditLog(jsonlText) {
  const byDirection = { "agent->mcp": 0, "mcp->agent": 0 };
  const byAction = { allow: 0, redacted: 0, tainted: 0, blocked: 0, dropped: 0 };
  const ruleCounts = new Map();
  const toolStats = new Map();
  const uniqueSecretHashes = new Set();
  const latencies = [];

  let totalEvents = 0;
  let malformedLines = 0;
  let firstTs = null;
  let lastTs = null;

  const lines = String(jsonlText || "").split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      malformedLines++;
      continue;
    }

    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      malformedLines++;
      continue;
    }

    totalEvents++;
    if (typeof entry.ts === "string") {
      if (firstTs === null || entry.ts < firstTs) firstTs = entry.ts;
      if (lastTs === null || entry.ts > lastTs) lastTs = entry.ts;
    }

    if (typeof entry.dir === "string") {
      byDirection[entry.dir] = (byDirection[entry.dir] ?? 0) + 1;
    }

    const action = typeof entry.action === "string" ? entry.action : "allow";
    byAction[action] = (byAction[action] ?? 0) + 1;

    if (Array.isArray(entry.rules)) {
      for (const ruleId of entry.rules) {
        if (typeof ruleId === "string" && ruleId.length > 0) {
          ruleCounts.set(ruleId, (ruleCounts.get(ruleId) ?? 0) + 1);
        }
      }
    }

    if (Array.isArray(entry.secretHashes)) {
      for (const h of entry.secretHashes) {
        if (typeof h === "string" && h.length > 0) {
          uniqueSecretHashes.add(h);
        }
      }
    }

    if (typeof entry.tool === "string" && entry.tool.length > 0) {
      let stat = toolStats.get(entry.tool);
      if (!stat) {
        stat = { tool: entry.tool, events: 0, redacted: 0, tainted: 0, blocked: 0, dropped: 0 };
        toolStats.set(entry.tool, stat);
      }
      stat.events++;
      if (action === "redacted") stat.redacted++;
      else if (action === "tainted") stat.tainted++;
      else if (action === "blocked") stat.blocked++;
      else if (action === "dropped") stat.dropped++;
    }

    if (typeof entry.latencyMs === "number" && Number.isFinite(entry.latencyMs)) {
      latencies.push(entry.latencyMs);
    }
  }

  latencies.sort((a, b) => a - b);

  const topRules = [...ruleCounts.entries()]
    .map(([ruleId, count]) => ({ ruleId, count }))
    .sort((a, b) => b.count - a.count || a.ruleId.localeCompare(b.ruleId));

  const topTools = [...toolStats.values()].sort(
    (a, b) => b.events - a.events || a.tool.localeCompare(b.tool)
  );

  return {
    totalEvents,
    malformedLines,
    timeRange: { firstTs, lastTs },
    byDirection,
    byAction,
    blockedOrDropped: (byAction.blocked ?? 0) + (byAction.dropped ?? 0),
    uniqueSecretHashes: uniqueSecretHashes.size,
    topRules,
    topTools,
    latencyMs: {
      p50: percentile(latencies, 0.5),
      p95: percentile(latencies, 0.95),
      p99: percentile(latencies, 0.99),
      max: latencies.length > 0 ? Number(latencies[latencies.length - 1].toFixed(3)) : 0,
    },
  };
}

/**
 * Formats an audit log summary for clean terminal output.
 */
export function formatAuditSummary(summary, options = {}) {
  const { limit = 10 } = options;
  const lines = [];

  lines.push("=== mcp-guard Audit Log Summary ===");
  lines.push(
    `Events: ${summary.totalEvents} (agent->mcp: ${summary.byDirection["agent->mcp"] ?? 0}, mcp->agent: ${summary.byDirection["mcp->agent"] ?? 0})`
  );
  if (summary.timeRange.firstTs) {
    lines.push(`Window: ${summary.timeRange.firstTs} -> ${summary.timeRange.lastTs}`);
  }
  lines.push(
    `Actions: allow=${summary.byAction.allow ?? 0} redacted=${summary.byAction.redacted ?? 0} tainted=${summary.byAction.tainted ?? 0} blocked=${summary.byAction.blocked ?? 0} dropped=${summary.byAction.dropped ?? 0}`
  );
  lines.push(`Unique secret/PII hashes: ${summary.uniqueSecretHashes}`);
  lines.push(
    `Latency (ms): p50=${summary.latencyMs.p50} p95=${summary.latencyMs.p95} p99=${summary.latencyMs.p99} max=${summary.latencyMs.max}`
  );
  if (summary.malformedLines > 0) {
    lines.push(`Malformed lines skipped: ${summary.malformedLines}`);
  }

  lines.push("");
  lines.push("Top Triggered Rules:");
  if (summary.topRules.length === 0) {
    lines.push("  (none)");
  } else {
    for (const r of summary.topRules.slice(0, limit)) {
      lines.push(`  - ${r.ruleId}: ${r.count}`);
    }
  }

  lines.push("");
  lines.push("Top MCP Tools:");
  if (summary.topTools.length === 0) {
    lines.push("  (none)");
  } else {
    for (const t of summary.topTools.slice(0, limit)) {
      lines.push(
        `  - ${t.tool}: events=${t.events} redacted=${t.redacted} tainted=${t.tainted} blocked=${t.blocked} dropped=${t.dropped}`
      );
    }
  }

  return `${lines.join("\n")}\n`;
}
