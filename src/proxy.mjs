import { spawn } from "node:child_process";
import { performance } from "node:perf_hooks";
import { redactPayload, redactText } from "./redact.mjs";
import { createPiiPseudonymizer } from "./pseudonymize.mjs";
import {
  detectPromptInjection,
  taintUntrustedPayload,
  wrapUntrustedField,
} from "./injection.mjs";
import { buildAuditEntry, createAuditLogger } from "./audit.mjs";
import { evaluateToolCallPolicy, getOutboundSecretSkipPaths } from "./policy.mjs";

const MAX_HEADER_BYTES = 8192;
export const DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024; // 16 MiB DoS cap
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
 * and LSP/MCP Content-Length framed JSON-RPC streams with bounded memory (maxFrameBytes).
 */
export function createFrameParser(onFrame, options = {}) {
  const { maxFrameBytes = DEFAULT_MAX_FRAME_BYTES, onError = null } = options;
  let buf = Buffer.alloc(0);
  let expectedBytes = null;
  let discardingUntilNewline = false;
  let discardingBytesRemaining = 0;

  function emitError(err) {
    if (onError) onError(err);
  }

  function drain() {
    while (buf.length > 0) {
      if (discardingBytesRemaining > 0) {
        if (buf.length <= discardingBytesRemaining) {
          discardingBytesRemaining -= buf.length;
          buf = Buffer.alloc(0);
          return;
        }
        buf = buf.subarray(discardingBytesRemaining);
        discardingBytesRemaining = 0;
        continue;
      }

      if (discardingUntilNewline) {
        const nlIdx = buf.indexOf(0x0a);
        if (nlIdx === -1) {
          buf = Buffer.alloc(0);
          return;
        }
        buf = buf.subarray(nlIdx + 1);
        discardingUntilNewline = false;
        continue;
      }

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
            // Malformed runaway header: drop and discard until next newline to prevent unbounded buffering
            emitError({ code: "HEADER_TOO_LARGE", bytes: buf.length, maxBytes: MAX_HEADER_BYTES });
            buf = Buffer.alloc(0);
            discardingUntilNewline = true;
            return;
          }
          return;
        }

        const headerText = buf.subarray(0, sepIdx).toString("ascii");
        const match = headerText.match(/content-length\s*:\s*(\d+)/i);
        if (!match) {
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
        if (len > maxFrameBytes) {
          emitError({ code: "FRAME_TOO_LARGE", bytes: len, maxBytes: maxFrameBytes });
          discardingBytesRemaining = len;
          continue;
        }

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
        if (buf.length > maxFrameBytes) {
          emitError({ code: "FRAME_TOO_LARGE", bytes: buf.length, maxBytes: maxFrameBytes });
          buf = Buffer.alloc(0);
          discardingUntilNewline = true;
        }
        return;
      }
      if (nlIdx > maxFrameBytes) {
        emitError({ code: "FRAME_TOO_LARGE", bytes: nlIdx, maxBytes: maxFrameBytes });
        buf = buf.subarray(nlIdx + 1);
        continue;
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

      // Fast path while discarding an already-rejected oversized frame (O(1) memory)
      if (discardingBytesRemaining > 0) {
        if (incoming.length <= discardingBytesRemaining) {
          discardingBytesRemaining -= incoming.length;
          return;
        }
        buf = incoming.subarray(discardingBytesRemaining);
        discardingBytesRemaining = 0;
        drain();
        return;
      }
      if (discardingUntilNewline) {
        const nlIdx = incoming.indexOf(0x0a);
        if (nlIdx === -1) return;
        discardingUntilNewline = false;
        buf = incoming.subarray(nlIdx + 1);
        drain();
        return;
      }

      buf = buf.length === 0 ? incoming : Buffer.concat([buf, incoming]);
      drain();
    },
    end() {
      drain();
      if (discardingUntilNewline || discardingBytesRemaining > 0) {
        buf = Buffer.alloc(0);
        discardingUntilNewline = false;
        discardingBytesRemaining = 0;
        expectedBytes = null;
        return;
      }
      if (buf.length > 0) {
        if (buf.length > maxFrameBytes) {
          emitError({ code: "FRAME_TOO_LARGE", bytes: buf.length, maxBytes: maxFrameBytes });
          buf = Buffer.alloc(0);
          expectedBytes = null;
          return;
        }
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

function buildPolicyDeniedError(id, tool, ruleId, reason) {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: -32002,
      message: `Blocked by mcp-guard policy: ${reason}`,
      data: {
        blockedBy: "mcp-guard",
        ruleId,
        tool,
      },
    },
  };
}

function shouldBlockAlerts(alerts, blockMinRules) {
  if (alerts.length === 0) return false;
  if (alerts.some((a) => a.severity === "critical")) return true;
  const distinctRules = new Set(alerts.map((a) => a.ruleId)).size;
  return distinctRules >= blockMinRules;
}

function inspectSingleJsonRpcMessage(parsed, direction, options) {
  const {
    redactPii = true,
    redactOutboundPii = false,
    pseudonymizePii = false,
    pseudonymizer = null,
    allowEmailDomains = [],
    disabledRules = null,
    customRules = null,
    allowPatterns = null,
    blockInjections = false,
    blockMinRules = 2,
    taintUntrusted = true,
    injectionThreshold = "medium",
    policy = null,
  } = options;

  // Enforce declarative mcp-guard.json tool/argument policy BEFORE upstream execution
  if (
    direction === "agent->mcp" &&
    policy &&
    parsed &&
    typeof parsed === "object" &&
    parsed.method === "tools/call"
  ) {
    const toolName =
      parsed.params && typeof parsed.params === "object" && typeof parsed.params.name === "string"
        ? parsed.params.name
        : "";
    const toolArgs =
      parsed.params && typeof parsed.params === "object" && parsed.params.arguments && typeof parsed.params.arguments === "object"
        ? parsed.params.arguments
        : {};
    const decision = evaluateToolCallPolicy(toolName, toolArgs, policy);
    if (!decision.allowed) {
      const hasId = parsed.id !== undefined && parsed.id !== null;
      return {
        action: "policy_denied",
        message: null,
        replyToUpstream: null,
        replyToClient: hasId
          ? buildPolicyDeniedError(parsed.id, toolName || null, decision.ruleId, decision.reason)
          : null,
        findings: [],
        injectionAlerts: [],
        policyRules: [decision.ruleId],
        taintedPaths: [],
      };
    }
  }

  const shouldRedactPii = direction === "agent->mcp" ? redactOutboundPii : redactPii;
  const skipPaths =
    direction === "agent->mcp" &&
    policy &&
    parsed &&
    typeof parsed === "object" &&
    parsed.method === "tools/call" &&
    typeof parsed.params?.name === "string"
      ? getOutboundSecretSkipPaths(parsed.params.name, policy)
      : null;

  const { sanitized, findings } = redactPayload(parsed, {
    redactPii: shouldRedactPii,
    pseudonymizePii,
    pseudonymizer,
    allowEmailDomains,
    disabledRules,
    customRules,
    allowPatterns,
    skipPaths,
  });

  if (direction === "agent->mcp") {
    return {
      action: "forward",
      message: sanitized,
      replyToUpstream: null,
      replyToClient: null,
      findings,
      injectionAlerts: [],
      policyRules: [],
      taintedPaths: [],
    };
  }

  const injectionAlerts = detectPromptInjection(sanitized, {
    threshold: injectionThreshold,
  });

  if (
    blockInjections &&
    shouldBlockAlerts(injectionAlerts, blockMinRules) &&
    sanitized &&
    typeof sanitized === "object"
  ) {
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
        replyToClient: null,
        findings,
        injectionAlerts,
        policyRules: [],
        taintedPaths: [],
      };
    }

    if (hasMethod && !hasId) {
      // Server-to-client notification: drop silently toward agent
      return {
        action: "drop",
        message: null,
        replyToUpstream: null,
        replyToClient: null,
        findings,
        injectionAlerts,
        policyRules: [],
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
        replyToClient: null,
        findings,
        injectionAlerts,
        policyRules: [],
        taintedPaths: [],
      };
    }

    // Malformed object with neither id nor method: fail closed and drop
    return {
      action: "drop",
      message: null,
      replyToUpstream: null,
      replyToClient: null,
      findings,
      injectionAlerts,
      policyRules: [],
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
      replyToClient: null,
      findings,
      injectionAlerts,
      policyRules: [],
      taintedPaths,
    };
  }

  return {
    action: "forward",
    message: sanitized,
    replyToUpstream: null,
    replyToClient: null,
    findings,
    injectionAlerts,
    policyRules: [],
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
    pseudonymizePii = false,
    pseudonymizer = null,
    allowEmailDomains = [],
    disabledRules = null,
    customRules = null,
    allowPatterns = null,
    blockInjections = false,
    blockMinRules = 2,
    taintUntrusted = true,
    injectionThreshold = "medium",
  } = options;

  if (typeof raw !== "string" || raw.trim().length === 0) {
    return {
      action: "ignore",
      output: null,
      repliesToUpstream: [],
      repliesToClient: [],
      findings: [],
      injectionAlerts: [],
      policyRules: [],
      taintedPaths: [],
      unparseable: false,
      id: null,
      method: null,
      tool: null,
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
      pseudonymizePii,
      pseudonymizer,
      allowEmailDomains,
      disabledRules,
      customRules,
      allowPatterns,
    });
    const injectionAlerts =
      direction === "mcp->agent"
        ? detectPromptInjection(redacted, { threshold: injectionThreshold })
        : [];

    if (
      direction === "mcp->agent" &&
      blockInjections &&
      shouldBlockAlerts(injectionAlerts, blockMinRules)
    ) {
      return {
        action: "drop",
        output: null,
        repliesToUpstream: [],
        repliesToClient: [],
        findings,
        injectionAlerts,
        policyRules: [],
        taintedPaths: [],
        unparseable: true,
        id: null,
        method: null,
        tool: null,
      };
    }

    if (direction === "mcp->agent" && taintUntrusted && injectionAlerts.length > 0) {
      return {
        action: "tainted",
        output: wrapUntrustedField(redacted, injectionAlerts),
        repliesToUpstream: [],
        repliesToClient: [],
        findings,
        injectionAlerts,
        policyRules: [],
        taintedPaths: [""],
        unparseable: true,
        id: null,
        method: null,
        tool: null,
      };
    }

    return {
      action: "forward",
      output: redacted,
      repliesToUpstream: [],
      repliesToClient: [],
      findings,
      injectionAlerts,
      policyRules: [],
      taintedPaths: [],
      unparseable: true,
      id: null,
      method: null,
      tool: null,
    };
  }

  // Handle JSON-RPC batch arrays
  if (Array.isArray(parsed)) {
    const outBatch = [];
    const repliesToUpstream = [];
    const repliesToClient = [];
    const allFindings = [];
    const allAlerts = [];
    const allPolicyRules = [];
    const allTaintedPaths = [];
    let blockedCount = 0;
    let policyDeniedCount = 0;
    let taintedCount = 0;

    for (const item of parsed) {
      const res = inspectSingleJsonRpcMessage(item, direction, options);
      allFindings.push(...res.findings);
      allAlerts.push(...res.injectionAlerts);
      allPolicyRules.push(...res.policyRules);
      allTaintedPaths.push(...res.taintedPaths);
      if (res.replyToUpstream) {
        repliesToUpstream.push(JSON.stringify(res.replyToUpstream));
      }
      if (res.replyToClient) {
        repliesToClient.push(JSON.stringify(res.replyToClient));
      }
      if (res.action === "tainted") taintedCount++;
      if (res.action === "policy_denied") policyDeniedCount++;
      if (res.message !== null) {
        outBatch.push(res.message);
      } else {
        blockedCount++;
      }
    }

    let action = "forward";
    if (outBatch.length === 0 && policyDeniedCount > 0) action = "policy_denied";
    else if (outBatch.length === 0) action = "drop";
    else if (blockedCount > 0) action = "replace";
    else if (taintedCount > 0) action = "tainted";

    return {
      action,
      output: outBatch.length > 0 ? JSON.stringify(outBatch) : null,
      repliesToUpstream,
      repliesToClient,
      findings: allFindings,
      injectionAlerts: allAlerts,
      policyRules: allPolicyRules,
      taintedPaths: allTaintedPaths,
      unparseable: false,
      id: null,
      method: null,
      tool: null,
    };
  }

  const res = inspectSingleJsonRpcMessage(parsed, direction, options);
  const method =
    parsed && typeof parsed === "object" && typeof parsed.method === "string"
      ? parsed.method
      : null;
  const tool =
    method === "tools/call" &&
    parsed.params &&
    typeof parsed.params === "object" &&
    typeof parsed.params.name === "string"
      ? parsed.params.name
      : null;
  const id =
    parsed && typeof parsed === "object" && parsed.id !== undefined && parsed.id !== null
      ? parsed.id
      : null;

  return {
    action: res.action,
    output: res.message !== null ? JSON.stringify(res.message) : null,
    repliesToUpstream: res.replyToUpstream ? [JSON.stringify(res.replyToUpstream)] : [],
    repliesToClient: res.replyToClient ? [JSON.stringify(res.replyToClient)] : [],
    findings: res.findings,
    injectionAlerts: res.injectionAlerts,
    policyRules: res.policyRules,
    taintedPaths: res.taintedPaths,
    unparseable: false,
    id,
    method,
    tool,
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

function mapAuditAction(res) {
  if (
    res.action === "replace" ||
    res.action === "drop_and_reply" ||
    res.action === "policy_denied"
  ) {
    return "blocked";
  }
  if (res.action === "drop") return "dropped";
  if (res.action === "tainted") return "tainted";
  if (res.findings.length > 0) return "redacted";
  return "allow";
}

const MAX_PENDING_CALLS = 1000;
const WINDOWS_CMD_SHIMS = new Set(["npx", "npm", "pnpm", "yarn", "corepack"]);

function quoteWinCmdArg(arg) {
  const str = String(arg);
  if (str.length === 0) return '""';
  const escaped = str.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, "$1$1");
  return /[\s"&|<>()^%!]/.test(str) ? `"${escaped}"` : escaped;
}

/**
 * Resolves a safe cross-platform `child_process.spawn` spec.
 * On Windows, Node 20.12+/22+ refuses to spawn `.cmd`/`.bat` shims (like `npx`) directly
 * without `cmd.exe`. This helper routes only known Windows batch shims through
 * `ComSpec /d /s /c` with safely quoted arguments while leaving Unix and native binaries
 * untouched (`shell: false`).
 */
export function resolveSpawnSpec(command, args = [], platform = process.platform) {
  const safeArgs = Array.isArray(args) ? args.map(String) : [];
  if (platform !== "win32" || typeof command !== "string" || command.length === 0) {
    return { command, args: safeArgs, options: {} };
  }

  const base = command.replace(/^.*[\\/]/, "").toLowerCase();
  const isBatchShim =
    WINDOWS_CMD_SHIMS.has(base) || base.endsWith(".cmd") || base.endsWith(".bat");

  if (!isBatchShim) {
    return { command, args: safeArgs, options: {} };
  }

  const comSpec = process.env.ComSpec || "cmd.exe";
  const resolvedCmd = WINDOWS_CMD_SHIMS.has(base) ? `${command}.cmd` : command;
  const cmdLine = [quoteWinCmdArg(resolvedCmd), ...safeArgs.map(quoteWinCmdArg)].join(" ");

  return {
    command: comSpec,
    args: ["/d", "/s", "/c", `"${cmdLine}"`],
    options: {
      windowsVerbatimArguments: true,
      windowsHide: true,
    },
  };
}

/**
 * Wraps any stdio MCP server process as a bidirectional JSON-RPC firewall:
 * - Enforces declarative mcp-guard.json tool/argument policies before upstream execution.
 * - Inspects stdin (agent -> MCP) to block outbound secret leaks (opt-in PII via redactOutboundPii).
 * - Inspects stdout (MCP -> agent) to scrub secrets/PII and taint/block indirect prompt injections.
 * - Supports bounded NDJSON and Content-Length framing (maxFrameBytes) and never fails open.
 * - Optionally writes append-only structured JSONL audit logs (never raw secrets).
 * - Drains child stdout and audit log completely before exiting and forwards SIGINT/SIGTERM cleanly.
 * - Audit telemetry is written strictly to stderr so stdout stays valid MCP JSON-RPC.
 */
export function runStdioProxy(command, args = [], options = {}) {
  const policy = options.policy ?? null;
  const redactPii = options.redactPii ?? policy?.redaction?.redactPii ?? true;
  const redactOutboundPii =
    options.redactOutboundPii ?? policy?.redaction?.redactOutboundPii ?? false;
  const pseudonymizePii =
    options.pseudonymizePii ?? policy?.redaction?.pseudonymizePii ?? false;
  const pseudonymizer =
    options.pseudonymizer ?? (pseudonymizePii ? createPiiPseudonymizer() : null);
  const allowEmailDomains =
    options.allowEmailDomains && options.allowEmailDomains.length > 0
      ? options.allowEmailDomains
      : (policy?.redaction?.allowEmailDomains ?? []);
  const disabledRules = options.disabledRules ?? policy?.redaction?.disabledRules ?? null;
  const customRules = options.customRules ?? policy?.redaction?.customRules ?? null;
  const allowPatterns = options.allowPatterns ?? policy?.redaction?.allowPatterns ?? null;
  const blockInjections =
    options.blockInjections ?? policy?.injection?.blockInjections ?? false;
  const blockMinRules = options.blockMinRules ?? policy?.injection?.blockMinRules ?? 2;
  const taintUntrusted =
    options.taintUntrusted ?? policy?.injection?.taintUntrusted ?? true;
  const injectionThreshold =
    options.injectionThreshold ?? policy?.injection?.threshold ?? "medium";
  const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;

  const {
    auditLog = null,
    onAuditEntry = null,
    input = process.stdin,
    output = process.stdout,
    stderr = process.stderr,
    exit = (code) => process.exit(code),
    forwardSignals = true,
  } = options;

  const inspectOpts = {
    redactPii,
    redactOutboundPii,
    pseudonymizePii,
    pseudonymizer,
    disabledRules,
    customRules,
    allowPatterns,
    blockInjections,
    blockMinRules,
    taintUntrusted,
    injectionThreshold,
    allowEmailDomains,
    policy,
  };

  function logAudit(line) {
    safeWrite(stderr, `[mcp-guard] ${line}\n`);
  }

  let auditLogger = null;
  if (auditLog) {
    try {
      auditLogger = createAuditLogger(auditLog, {
        onError: (err) => logAudit(`audit_log_error=${err?.code || err?.message}`),
      });
    } catch (err) {
      logAudit(`audit_log_open_error path=${auditLog} message=${err?.message}`);
    }
  }

  let child;
  try {
    const spec = resolveSpawnSpec(command, args);
    child = spawn(spec.command, spec.args, {
      stdio: ["pipe", "pipe", "inherit"],
      env: process.env,
      ...spec.options,
    });
  } catch (err) {
    const code = err?.code === "ENOENT" ? 127 : err?.code === "EACCES" || err?.code === "EPERM" ? 126 : 1;
    logAudit(`spawn_error command=${command} code=${err?.code || "UNKNOWN"} message=${err?.message}`);
    if (auditLogger) {
      auditLogger.close().finally(() => exit(code));
    } else {
      exit(code);
    }
    return null;
  }

  let finished = false;
  let stdoutEnded = false;
  let childClosed = false;
  let exitCode = 0;
  const pendingCalls = new Map();

  function recordAudit(dir, res, method, tool, latencyMs) {
    if (!auditLogger && !onAuditEntry) return;
    if (res.action === "ignore") return;
    const entry = buildAuditEntry({
      dir,
      method,
      tool,
      action: mapAuditAction(res),
      findings: res.findings,
      injectionAlerts: res.injectionAlerts,
      extraRules: res.policyRules,
      latencyMs,
    });
    if (auditLogger) auditLogger.write(entry);
    if (onAuditEntry) onAuditEntry(entry);
  }

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
    if (auditLogger) {
      auditLogger.close().finally(() => exit(code));
    } else {
      exit(code);
    }
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
  const inboundParser = createFrameParser(
    ({ framing, raw }) => {
      const t0 = performance.now();
      const res = inspectFrame(raw, "agent->mcp", inspectOpts);
      const latencyMs = performance.now() - t0;

      if (res.action !== "policy_denied" && res.id !== null && res.method !== null) {
        if (pendingCalls.size >= MAX_PENDING_CALLS) {
          const oldestKey = pendingCalls.keys().next().value;
          pendingCalls.delete(oldestKey);
        }
        pendingCalls.set(String(res.id), { method: res.method, tool: res.tool });
      }

      recordAudit("agent->mcp", res, res.method, res.tool, latencyMs);

      if (res.findings.length > 0 || res.policyRules.length > 0 || res.unparseable) {
        const parts = [
          "dir=agent->mcp",
          res.method ? `method=${res.method}` : null,
          res.tool ? `tool=${res.tool}` : null,
          res.action !== "forward" ? `action=${res.action}` : null,
          res.policyRules.length > 0 ? `policy=${res.policyRules.join(",")}` : null,
          res.unparseable ? "unparseable_frame=true" : null,
          `scrubbed=${res.findings.length}`,
        ].filter(Boolean);
        logAudit(parts.join(" "));
      }

      for (const reply of res.repliesToClient) {
        safeWrite(output, encodeFrame(reply, framing));
      }

      if (res.output !== null) {
        safeWrite(child.stdin, encodeFrame(res.output, framing));
      }
    },
    {
      maxFrameBytes,
      onError: (err) =>
        logAudit(`dir=agent->mcp parser_error=${err.code} bytes=${err.bytes} max=${err.maxBytes}`),
    }
  );

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
  const outboundParser = createFrameParser(
    ({ framing, raw }) => {
      const t0 = performance.now();
      const res = inspectFrame(raw, "mcp->agent", inspectOpts);
      const latencyMs = performance.now() - t0;

      let correlatedMethod = res.method;
      let correlatedTool = res.tool;
      if (res.id !== null && correlatedMethod === null) {
        const key = String(res.id);
        const pending = pendingCalls.get(key);
        if (pending) {
          correlatedMethod = pending.method;
          correlatedTool = pending.tool;
          pendingCalls.delete(key);
        }
      }

      recordAudit("mcp->agent", res, correlatedMethod, correlatedTool, latencyMs);

      if (res.findings.length > 0 || res.injectionAlerts.length > 0 || res.unparseable) {
        const parts = [
          "dir=mcp->agent",
          correlatedMethod ? `method=${correlatedMethod}` : null,
          correlatedTool ? `tool=${correlatedTool}` : null,
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
    },
    {
      maxFrameBytes,
      onError: (err) =>
        logAudit(`dir=mcp->agent parser_error=${err.code} bytes=${err.bytes} max=${err.maxBytes}`),
    }
  );

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
