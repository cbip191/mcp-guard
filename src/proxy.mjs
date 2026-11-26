import { spawn } from "node:child_process";
import { redactPayload, redactText } from "./redact.mjs";
import {
  detectPromptInjection,
  taintUntrustedPayload,
  wrapUntrustedField,
} from "./injection.mjs";

const MAX_HEADER_BYTES = 8192;
const SIGNAL_EXIT_CODES = {
  SIGINT: 130,
  SIGTERM: 143,
  SIGHUP: 129,
};

const CONTENT_LENGTH_PREFIX = "content-length";

function isPartialContentLengthPrefix(str) {
  const lower = str.toLowerCase();
  return CONTENT_LENGTH_PREFIX.startsWith(lower);
}

/**
 * Byte-accurate incremental parser supporting both NDJSON (\n-delimited)
 * and LSP/MCP Content-Length framed JSON-RPC streams.
 */
export function createFrameParser(onFrame) {
  let buf = Buffer.alloc(0);
  let expectedBytes = null;

  function drain() {
    while (buf.length > 0) {
      if (expectedBytes !== null) {
        if (buf.length < expectedBytes) {
          return;
        }
        const raw = buf.subarray(0, expectedBytes).toString("utf8");
        buf = buf.subarray(expectedBytes);
        expectedBytes = null;
        onFrame({ framing: "content-length", raw });
        continue;
      }

      // Skip stray leading CR/LF between frames
      if (buf[0] === 0x0a || buf[0] === 0x0d) {
        let skip = 0;
        while (skip < buf.length && (buf[skip] === 0x0a || buf[skip] === 0x0d)) {
          skip++;
        }
        buf = buf.subarray(skip);
        continue;
      }

      // Detect Content-Length header framing (case-insensitive)
      const probeLen = Math.min(buf.length, CONTENT_LENGTH_PREFIX.length + 1);
      const probe = buf.subarray(0, probeLen).toString("ascii");
      const lowerProbe = probe.toLowerCase();

      if (lowerProbe.startsWith("content-length:")) {
        let sepIdx = buf.indexOf("\r\n\r\n");
        let sepLen = 4;
        if (sepIdx === -1) {
          sepIdx = buf.indexOf("\n\n");
          sepLen = 2;
        }

        if (sepIdx === -1) {
          if (buf.length > MAX_HEADER_BYTES) {
            // Malformed runaway header: fall back to line flush so we never stall or OOM
            const nlIdx = buf.indexOf(0x0a);
            const end = nlIdx === -1 ? buf.length : nlIdx;
            const raw = buf.subarray(0, end).toString("utf8").replace(/\r$/, "");
            buf = nlIdx === -1 ? Buffer.alloc(0) : buf.subarray(nlIdx + 1);
            onFrame({ framing: "ndjson", raw });
            continue;
          }
          return;
        }

        const headerText = buf.subarray(0, sepIdx).toString("ascii");
        const match = headerText.match(/content-length\s*:\s*(\d+)/i);
        if (!match) {
          // Malformed header without numeric length: treat header block as raw line
          const raw = headerText.replace(/\r/g, "");
          buf = buf.subarray(sepIdx + sepLen);
          onFrame({ framing: "ndjson", raw });
          continue;
        }

        const len = Number.parseInt(match[1], 10);
        if (!Number.isSafeInteger(len) || len < 0) {
          const raw = headerText.replace(/\r/g, "");
          buf = buf.subarray(sepIdx + sepLen);
          onFrame({ framing: "ndjson", raw });
          continue;
        }

        buf = buf.subarray(sepIdx + sepLen);
        expectedBytes = len;
        continue;
      }

      // Wait if buffer could still become "Content-Length:" (no newline yet)
      if (buf.length <= CONTENT_LENGTH_PREFIX.length && isPartialContentLengthPrefix(probe)) {
        return;
      }

      // Standard NDJSON framing (\n-delimited)
      const nlIdx = buf.indexOf(0x0a);
      if (nlIdx === -1) {
        return;
      }
      const raw = buf.subarray(0, nlIdx).toString("utf8").replace(/\r$/, "");
      buf = buf.subarray(nlIdx + 1);
      onFrame({ framing: "ndjson", raw });
    }
  }

  return {
    push(chunk) {
      const incoming = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8");
      if (incoming.length === 0) return;
      buf = buf.length === 0 ? incoming : Buffer.concat([buf, incoming]);
      drain();
    },
    end() {
      drain();
      if (buf.length > 0) {
        const raw = buf.toString("utf8").replace(/\r$/, "");
        buf = Buffer.alloc(0);
        expectedBytes = null;
        if (raw.length > 0) {
          onFrame({ framing: "ndjson", raw });
        }
      }
    },
  };
}

/**
 * Encodes a serialized frame string using either NDJSON or Content-Length framing.
 */
export function encodeFrame(payloadStr, framing = "ndjson") {
  if (framing === "content-length") {
    const byteLen = Buffer.byteLength(payloadStr, "utf8");
    return `Content-Length: ${byteLen}\r\n\r\n${payloadStr}`;
  }
  return `${payloadStr}\n`;
}

function sanitizeAlertMetadata(alerts) {
  return alerts.map(({ ruleId, severity, path }) => ({
    ruleId,
    severity,
    path,
  }));
}

function buildBlockedError(id, message, alerts) {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: -32001,
      message,
      data: {
        blockedBy: "mcp-guard",
        alertCount: alerts.length,
        alerts: sanitizeAlertMetadata(alerts),
      },
    },
  };
}

function inspectSingleJsonRpcMessage(parsed, direction, options) {
  const {
    redactPii = true,
    redactOutboundPii = false,
    allowEmailDomains = [],
    blockInjections = false,
    taintUntrusted = false,
    injectionThreshold = "medium",
  } = options;

  const shouldRedactPii = direction === "agent->mcp" ? redactOutboundPii : redactPii;

  const { sanitized, findings } = redactPayload(parsed, {
    redactPii: shouldRedactPii,
    allowEmailDomains,
  });

  if (direction === "agent->mcp") {
    return {
      action: "forward",
      message: sanitized,
      replyToUpstream: null,
      findings,
      injectionAlerts: [],
      taintedPaths: [],
    };
  }

  const injectionAlerts = detectPromptInjection(sanitized, {
    threshold: injectionThreshold,
  });

  if (blockInjections && injectionAlerts.length > 0 && sanitized && typeof sanitized === "object") {
    const hasId = sanitized.id !== undefined && sanitized.id !== null;
    const hasMethod = typeof sanitized.method === "string";

    if (hasMethod && hasId) {
      // Server-to-client request (e.g. sampling/createMessage): drop toward agent and reply with error to server
      return {
        action: "drop_and_reply",
        message: null,
        replyToUpstream: buildBlockedError(
          sanitized.id,
          "Blocked by mcp-guard: server-to-client request blocked due to indirect prompt injection.",
          injectionAlerts
        ),
        findings,
        injectionAlerts,
        taintedPaths: [],
      };
    }

    if (hasMethod && !hasId) {
      // Server-to-client notification: drop silently toward agent
      return {
        action: "drop",
        message: null,
        replyToUpstream: null,
        findings,
        injectionAlerts,
        taintedPaths: [],
      };
    }

    if (hasId) {
      // Standard response to a client request: return sanitized JSON-RPC error without raw injection snippets
      return {
        action: "replace",
        message: buildBlockedError(
          sanitized.id,
          "Blocked by mcp-guard: potential indirect prompt injection detected in upstream MCP response.",
          injectionAlerts
        ),
        replyToUpstream: null,
        findings,
        injectionAlerts,
        taintedPaths: [],
      };
    }

    // Malformed object with neither id nor method: fail closed and drop
    return {
      action: "drop",
      message: null,
      replyToUpstream: null,
      findings,
      injectionAlerts,
      taintedPaths: [],
    };
  }

  if (taintUntrusted && injectionAlerts.length > 0) {
    const { tainted, taintedPaths } = taintUntrustedPayload(sanitized, {
      threshold: injectionThreshold,
    });
    return {
      action: "tainted",
      message: tainted,
      replyToUpstream: null,
      findings,
      injectionAlerts,
      taintedPaths,
    };
  }

  return {
    action: "forward",
    message: sanitized,
    replyToUpstream: null,
    findings,
    injectionAlerts,
    taintedPaths: [],
  };
}

/**
 * Inspects a single framed JSON-RPC payload (or unparseable raw frame) in either direction.
 * Never fails open on unparseable frames: raw text is always scrubbed with redactText.
 */
export function inspectFrame(raw, direction, options = {}) {
  const {
    redactPii = true,
    redactOutboundPii = false,
    allowEmailDomains = [],
    blockInjections = false,
    taintUntrusted = false,
    injectionThreshold = "medium",
  } = options;

  if (typeof raw !== "string" || raw.trim().length === 0) {
    return {
      action: "ignore",
      output: null,
      repliesToUpstream: [],
      findings: [],
      injectionAlerts: [],
      taintedPaths: [],
      unparseable: false,
      method: null,
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Fail-closed redaction: NEVER forward unparseable lines unredacted
    const shouldRedactPii = direction === "agent->mcp" ? redactOutboundPii : redactPii;
    const { text: redacted, findings } = redactText(raw, {
      redactPii: shouldRedactPii,
      allowEmailDomains,
    });
    const injectionAlerts =
      direction === "mcp->agent"
        ? detectPromptInjection(redacted, { threshold: injectionThreshold })
        : [];

    if (direction === "mcp->agent" && blockInjections && injectionAlerts.length > 0) {
      return {
        action: "drop",
        output: null,
        repliesToUpstream: [],
        findings,
        injectionAlerts,
        taintedPaths: [],
        unparseable: true,
        method: null,
      };
    }

    if (direction === "mcp->agent" && taintUntrusted && injectionAlerts.length > 0) {
      return {
        action: "tainted",
        output: wrapUntrustedField(redacted, injectionAlerts),
        repliesToUpstream: [],
        findings,
        injectionAlerts,
        taintedPaths: [""],
        unparseable: true,
        method: null,
      };
    }

    return {
      action: "forward",
      output: redacted,
      repliesToUpstream: [],
      findings,
      injectionAlerts,
      taintedPaths: [],
      unparseable: true,
      method: null,
    };
  }

  // Handle JSON-RPC batch arrays
  if (Array.isArray(parsed)) {
    const outBatch = [];
    const repliesToUpstream = [];
    const allFindings = [];
    const allAlerts = [];
    const allTaintedPaths = [];
    let blockedCount = 0;
    let taintedCount = 0;

    for (const item of parsed) {
      const res = inspectSingleJsonRpcMessage(item, direction, options);
      allFindings.push(...res.findings);
      allAlerts.push(...res.injectionAlerts);
      allTaintedPaths.push(...res.taintedPaths);
      if (res.replyToUpstream) {
        repliesToUpstream.push(JSON.stringify(res.replyToUpstream));
      }
      if (res.action === "tainted") taintedCount++;
      if (res.message !== null) {
        outBatch.push(res.message);
      } else {
        blockedCount++;
      }
    }

    let action = "forward";
    if (outBatch.length === 0) action = "drop";
    else if (blockedCount > 0) action = "replace";
    else if (taintedCount > 0) action = "tainted";

    return {
      action,
      output: outBatch.length > 0 ? JSON.stringify(outBatch) : null,
      repliesToUpstream,
      findings: allFindings,
      injectionAlerts: allAlerts,
      taintedPaths: allTaintedPaths,
      unparseable: false,
      method: null,
    };
  }

  const res = inspectSingleJsonRpcMessage(parsed, direction, options);
  return {
    action: res.action,
    output: res.message !== null ? JSON.stringify(res.message) : null,
    repliesToUpstream: res.replyToUpstream ? [JSON.stringify(res.replyToUpstream)] : [],
    findings: res.findings,
    injectionAlerts: res.injectionAlerts,
    taintedPaths: res.taintedPaths,
    unparseable: false,
    method: parsed && typeof parsed === "object" && typeof parsed.method === "string"
      ? parsed.method
      : null,
  };
}

function safeWrite(stream, data) {
  if (!stream || stream.destroyed || !stream.writable) return false;
  try {
    stream.write(data);
    return true;
  } catch (err) {
    if (err && (err.code === "EPIPE" || err.code === "ERR_STREAM_DESTROYED")) {
      return false;
    }
    throw err;
  }
}

/**
 * Wraps any stdio MCP server process as a bidirectional JSON-RPC firewall:
 * - Inspects stdin (agent -> MCP) to block outbound secret/PII leaks.
 * - Inspects stdout (MCP -> agent) to scrub secrets/PII and detect/block indirect prompt injections.
 * - Supports both NDJSON and Content-Length framing and never fails open on unparseable frames.
 * - Drains child stdout completely before exiting and forwards SIGINT/SIGTERM cleanly.
 * - Audit telemetry is written strictly to stderr so stdout stays valid MCP JSON-RPC.
 */
export function runStdioProxy(command, args = [], options = {}) {
  const {
    redactPii = true,
    redactOutboundPii = false,
    blockInjections = false,
    taintUntrusted = false,
    injectionThreshold = "medium",
    allowEmailDomains = [],
    input = process.stdin,
    output = process.stdout,
    stderr = process.stderr,
    exit = (code) => process.exit(code),
    forwardSignals = true,
  } = options;

  const inspectOpts = {
    redactPii,
    redactOutboundPii,
    blockInjections,
    taintUntrusted,
    injectionThreshold,
    allowEmailDomains,
  };

  function logAudit(line) {
    safeWrite(stderr, `[mcp-guard] ${line}\n`);
  }

  let child;
  try {
    child = spawn(command, args, {
      stdio: ["pipe", "pipe", "inherit"],
      env: process.env,
    });
  } catch (err) {
    const code = err?.code === "ENOENT" ? 127 : err?.code === "EACCES" || err?.code === "EPERM" ? 126 : 1;
    logAudit(`spawn_error command=${command} code=${err?.code || "UNKNOWN"} message=${err?.message}`);
    exit(code);
    return null;
  }

  let finished = false;
  let stdoutEnded = false;
  let childClosed = false;
  let exitCode = 0;

  function onSignal(signal) {
    if (!child.killed && child.exitCode === null && child.signalCode === null) {
      try {
        child.kill(signal);
      } catch {
        // Child already gone
      }
    }
  }

  function cleanupSignals() {
    if (forwardSignals) {
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
    }
  }

  function finish(code) {
    if (finished) return;
    finished = true;
    cleanupSignals();
    exit(code);
  }

  function maybeFinish() {
    if (stdoutEnded && childClosed) {
      finish(exitCode);
    }
  }

  if (forwardSignals) {
    process.on("SIGINT", onSignal);
    process.on("SIGTERM", onSignal);
  }

  // Handle EPIPE gracefully on both downstream output and upstream child stdin
  child.stdin.on("error", (err) => {
    if (err && (err.code === "EPIPE" || err.code === "ERR_STREAM_DESTROYED")) {
      return;
    }
    logAudit(`upstream_stdin_error=${err?.code || err?.message}`);
  });

  const onOutputError = (err) => {
    if (err && (err.code === "EPIPE" || err.code === "ERR_STREAM_DESTROYED")) {
      onSignal("SIGTERM");
      finish(0);
      return;
    }
    logAudit(`downstream_stdout_error=${err?.code || err?.message}`);
  };
  output.on("error", onOutputError);

  // Direction 1: agent -> MCP (stdin -> child.stdin)
  const inboundParser = createFrameParser(({ framing, raw }) => {
    const res = inspectFrame(raw, "agent->mcp", inspectOpts);
    if (res.findings.length > 0 || res.unparseable) {
      const parts = [
        "dir=agent->mcp",
        res.method ? `method=${res.method}` : null,
        res.unparseable ? "unparseable_frame=true" : null,
        `scrubbed=${res.findings.length}`,
      ].filter(Boolean);
      logAudit(parts.join(" "));
    }
    if (res.output !== null) {
      safeWrite(child.stdin, encodeFrame(res.output, framing));
    }
  });

  const onInputData = (chunk) => inboundParser.push(chunk);
  const onInputEnd = () => {
    inboundParser.end();
    if (!child.stdin.destroyed && child.stdin.writable) {
      child.stdin.end();
    }
  };
  input.on("data", onInputData);
  input.on("end", onInputEnd);

  // Direction 2: MCP -> agent (child.stdout -> output)
  const outboundParser = createFrameParser(({ framing, raw }) => {
    const res = inspectFrame(raw, "mcp->agent", inspectOpts);

    if (res.findings.length > 0 || res.injectionAlerts.length > 0 || res.unparseable) {
      const parts = [
        "dir=mcp->agent",
        res.method ? `method=${res.method}` : null,
        res.action !== "forward" ? `action=${res.action}` : null,
        res.unparseable ? "unparseable_frame=true" : null,
        `scrubbed=${res.findings.length}`,
        `injection_alerts=${res.injectionAlerts.length}`,
      ].filter(Boolean);
      logAudit(parts.join(" "));
    }

    for (const reply of res.repliesToUpstream) {
      safeWrite(child.stdin, encodeFrame(reply, framing));
    }

    if (res.output !== null) {
      safeWrite(output, encodeFrame(res.output, framing));
    }
  });

  child.stdout.on("data", (chunk) => outboundParser.push(chunk));
  child.stdout.on("end", () => {
    outboundParser.end();
    stdoutEnded = true;
    maybeFinish();
  });

  child.on("error", (err) => {
    input.off("data", onInputData);
    input.off("end", onInputEnd);
    output.off("error", onOutputError);
    logAudit(`spawn_error command=${command} code=${err?.code || "UNKNOWN"} message=${err?.message}`);
    const code = err?.code === "ENOENT" ? 127 : err?.code === "EACCES" || err?.code === "EPERM" ? 126 : 1;
    finish(code);
  });

  // Wait for "close" (not "exit") + stdout drain so buffered JSON-RPC frames are never truncated
  child.on("close", (code, signal) => {
    input.off("data", onInputData);
    input.off("end", onInputEnd);
    output.off("error", onOutputError);
    if (code !== null) {
      exitCode = code;
    } else if (signal) {
      exitCode = SIGNAL_EXIT_CODES[signal] ?? 1;
    } else {
      exitCode = 0;
    }
    childClosed = true;
    maybeFinish();
  });

  return child;
}
