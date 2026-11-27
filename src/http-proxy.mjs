/**
 * Zero-dependency Streamable HTTP / SSE MCP transport proxy built with `node:http` and `fetch`.
 * Reuses the exact same bidirectional policy (`mcp-guard.json`), secret/PII redaction,
 * taint/block prompt-injection tripwire, and structured JSONL audit core as `src/proxy.mjs`.
 */
import http from "node:http";
import { performance } from "node:perf_hooks";
import { inspectFrame, DEFAULT_MAX_FRAME_BYTES } from "./proxy.mjs";
import { createPiiPseudonymizer } from "./pseudonymize.mjs";
import { buildAuditEntry, createAuditLogger } from "./audit.mjs";

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "accept-encoding",
]);

const MAX_PENDING_CALLS = 1000;

/**
 * Incremental Server-Sent Events (SSE) parser with bounded event size (`maxFrameBytes`).
 */
export function createSseParser(onEvent, options = {}) {
  const { maxFrameBytes = DEFAULT_MAX_FRAME_BYTES, onError = null } = options;
  let lineBuf = "";
  let current = { event: null, id: null, retry: null, dataLines: [] };
  let currentBytes = 0;
  let discarding = false;

  function resetEvent() {
    current = { event: null, id: null, retry: null, dataLines: [] };
    currentBytes = 0;
    discarding = false;
  }

  function flushEvent() {
    if (discarding) {
      resetEvent();
      return;
    }
    if (
      current.dataLines.length > 0 ||
      current.event !== null ||
      current.id !== null ||
      current.retry !== null
    ) {
      onEvent({
        event: current.event,
        id: current.id,
        retry: current.retry,
        data: current.dataLines.join("\n"),
      });
    }
    resetEvent();
  }

  function processLine(line) {
    if (line === "") {
      flushEvent();
      return;
    }
    if (discarding) return;
    if (line.startsWith(":")) return; // SSE comment / keepalive

    currentBytes += Buffer.byteLength(line, "utf8") + 1;
    if (currentBytes > maxFrameBytes) {
      discarding = true;
      if (onError) {
        onError({ code: "FRAME_TOO_LARGE", bytes: currentBytes, maxBytes: maxFrameBytes });
      }
      return;
    }

    const colonIdx = line.indexOf(":");
    const field = colonIdx === -1 ? line : line.slice(0, colonIdx);
    let value = colonIdx === -1 ? "" : line.slice(colonIdx + 1);
    if (value.startsWith(" ")) value = value.slice(1);

    if (field === "data") {
      current.dataLines.push(value);
    } else if (field === "event") {
      current.event = value;
    } else if (field === "id") {
      current.id = value;
    } else if (field === "retry") {
      current.retry = value;
    }
  }

  return {
    push(chunk) {
      const text = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
      if (text.length === 0) return;
      lineBuf += text;
      if (lineBuf.length > maxFrameBytes) {
        const lastNl = lineBuf.lastIndexOf("\n");
        if (lastNl === -1) {
          discarding = true;
          if (onError) {
            onError({ code: "FRAME_TOO_LARGE", bytes: lineBuf.length, maxBytes: maxFrameBytes });
          }
          lineBuf = "";
          return;
        }
      }

      let nlIdx;
      while ((nlIdx = lineBuf.indexOf("\n")) !== -1) {
        const line = lineBuf.slice(0, nlIdx).replace(/\r$/, "");
        lineBuf = lineBuf.slice(nlIdx + 1);
        processLine(line);
      }
    },
    end() {
      if (lineBuf.length > 0) {
        const line = lineBuf.replace(/\r$/, "");
        lineBuf = "";
        processLine(line);
      }
      flushEvent();
    },
  };
}

/**
 * Encodes an SSE event object back into wire format (`\n\n`-terminated).
 */
export function encodeSseEvent(evt) {
  const lines = [];
  if (evt.event !== null && evt.event !== undefined) lines.push(`event: ${evt.event}`);
  if (evt.id !== null && evt.id !== undefined) lines.push(`id: ${evt.id}`);
  if (evt.retry !== null && evt.retry !== undefined) lines.push(`retry: ${evt.retry}`);
  if (typeof evt.data === "string") {
    for (const part of evt.data.split("\n")) {
      lines.push(`data: ${part}`);
    }
  }
  return `${lines.join("\n")}\n\n`;
}

function validateUpstreamUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid upstream URL: "${rawUrl}"`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported upstream protocol "${parsed.protocol}". Expected http: or https:.`);
  }
  return parsed;
}

function resolveTargetUrl(upstreamBase, reqUrl) {
  const incoming = new URL(reqUrl || "/", "http://localhost");
  const target = new URL(upstreamBase.toString());
  const basePath = upstreamBase.pathname.replace(/\/+$/, "");

  // RFC 8615 / RFC 9728 /.well-known/* discovery endpoints always live at the origin root
  if (incoming.pathname.startsWith("/.well-known/")) {
    target.pathname = incoming.pathname;
  } else if (incoming.pathname !== "/" && incoming.pathname !== upstreamBase.pathname) {
    if (basePath && incoming.pathname.startsWith(`${basePath}/`)) {
      target.pathname = incoming.pathname;
    } else {
      target.pathname = `${basePath}${incoming.pathname}`;
    }
  }
  if (incoming.search) {
    target.search = incoming.search;
  }
  return target;
}

function filterRequestHeaders(rawHeaders) {
  const out = {};
  for (const [k, v] of Object.entries(rawHeaders || {})) {
    const lower = k.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower) || v === undefined) continue;
    out[k] = Array.isArray(v) ? v.join(", ") : String(v);
  }
  return out;
}

function copySafeResponseHeaders(upstreamHeaders, targetRes, overrides = {}) {
  for (const [k, v] of upstreamHeaders.entries()) {
    const lower = k.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower) || lower === "content-encoding") continue;
    targetRes.setHeader(k, v);
  }
  for (const [k, v] of Object.entries(overrides)) {
    targetRes.setHeader(k, v);
  }
}

function readBoundedBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;

    req.on("data", (chunk) => {
      if (settled) return;
      total += chunk.length;
      if (total > maxBytes) {
        settled = true;
        const err = new Error(`Request body exceeded maxFrameBytes (${maxBytes})`);
        err.code = "FRAME_TOO_LARGE";
        reject(err);
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    req.on("error", (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
  });
}

async function readBoundedFetchText(fetchRes, maxBytes) {
  if (!fetchRes.body) return "";
  const reader = fetchRes.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        const err = new Error(`Upstream body exceeded maxFrameBytes (${maxBytes})`);
        err.code = "FRAME_TOO_LARGE";
        throw err;
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString("utf8");
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

/**
 * Starts a local Streamable HTTP / SSE MCP proxy server forwarding traffic to `options.upstream`.
 * Returns `{ server, host, port, url, close() }`.
 */
export async function startHttpProxy(options = {}) {
  if (!options.upstream) {
    throw new Error("startHttpProxy requires an `upstream` URL (e.g. https://mcp.example.com/mcp).");
  }
  const upstreamBase = validateUpstreamUrl(options.upstream);
  const policy = options.policy ?? null;

  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 8787;
  const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;
  const stderr = options.stderr ?? process.stderr;
  const auditLog = options.auditLog ?? null;
  const onAuditEntry = options.onAuditEntry ?? null;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;

  const rehydrateOutboundPii =
    options.rehydrateOutboundPii ?? policy?.redaction?.rehydrateOutboundPii ?? false;
  const pseudonymizePii =
    options.pseudonymizePii ??
    policy?.redaction?.pseudonymizePii ??
    Boolean(rehydrateOutboundPii);
  const pseudonymizer =
    options.pseudonymizer ?? (pseudonymizePii ? createPiiPseudonymizer() : null);

  const inspectOpts = {
    redactPii: options.redactPii ?? policy?.redaction?.redactPii ?? true,
    redactOutboundPii: options.redactOutboundPii ?? policy?.redaction?.redactOutboundPii ?? false,
    pseudonymizePii,
    pseudonymizer,
    rehydrateOutboundPii,
    allowEmailDomains:
      options.allowEmailDomains && options.allowEmailDomains.length > 0
        ? options.allowEmailDomains
        : (policy?.redaction?.allowEmailDomains ?? []),
    disabledRules: options.disabledRules ?? policy?.redaction?.disabledRules ?? null,
    customRules: options.customRules ?? policy?.redaction?.customRules ?? null,
    allowPatterns: options.allowPatterns ?? policy?.redaction?.allowPatterns ?? null,
    blockInjections: options.blockInjections ?? policy?.injection?.blockInjections ?? false,
    blockMinRules: options.blockMinRules ?? policy?.injection?.blockMinRules ?? 2,
    taintUntrusted: options.taintUntrusted ?? policy?.injection?.taintUntrusted ?? true,
    injectionThreshold: options.injectionThreshold ?? policy?.injection?.threshold ?? "medium",
    policy,
  };

  function logStderr(msg) {
    if (stderr && !stderr.destroyed && stderr.writable) {
      stderr.write(`[mcp-guard:http] ${msg}\n`);
    }
  }

  let auditLogger = null;
  if (auditLog) {
    auditLogger = createAuditLogger(auditLog, {
      onError: (err) => logStderr(`audit_log_error=${err?.code || err?.message}`),
    });
  }

  const pendingCalls = new Map();

  function rememberPending(id, method, tool) {
    if (id === null || method === null) return;
    if (pendingCalls.size >= MAX_PENDING_CALLS) {
      const oldest = pendingCalls.keys().next().value;
      pendingCalls.delete(oldest);
    }
    pendingCalls.set(String(id), { method, tool });
  }

  function correlatePending(id, fallbackMethod, fallbackTool) {
    if (id !== null) {
      const key = String(id);
      const hit = pendingCalls.get(key);
      if (hit) {
        pendingCalls.delete(key);
        return hit;
      }
    }
    return { method: fallbackMethod, tool: fallbackTool };
  }

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

  async function sendUpstreamReply(targetUrl, headers, bodyStr) {
    try {
      await fetchImpl(targetUrl, {
        method: "POST",
        headers: { ...headers, "content-type": "application/json" },
        body: bodyStr,
      });
    } catch (err) {
      logStderr(`upstream_reply_error=${err?.message || err}`);
    }
  }

  async function pipeSseResponse(upstreamRes, clientRes, targetUrl, reqHeaders, fallbackCall) {
    copySafeResponseHeaders(upstreamRes.headers, clientRes, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache",
      connection: "keep-alive",
    });
    clientRes.writeHead(upstreamRes.status);

    if (!upstreamRes.body) {
      clientRes.end();
      return;
    }

    const parser = createSseParser(
      (evt) => {
        if (clientRes.destroyed || clientRes.writableEnded) return;

        // Preserve legacy SSE `endpoint` control events untouched (rewriting full upstream origin if present)
        if (evt.event === "endpoint") {
          let rewritten = evt.data;
          if (rewritten.startsWith(upstreamBase.origin)) {
            rewritten = rewritten.slice(upstreamBase.origin.length) || "/";
          }
          clientRes.write(encodeSseEvent({ ...evt, data: rewritten }));
          return;
        }

        if (!evt.data || evt.data.trim().length === 0) {
          clientRes.write(encodeSseEvent(evt));
          return;
        }

        const t0 = performance.now();
        const inspected = inspectFrame(evt.data, "mcp->agent", inspectOpts);
        const latencyMs = performance.now() - t0;

        const correlated =
          inspected.method === null
            ? correlatePending(inspected.id, fallbackCall?.method ?? null, fallbackCall?.tool ?? null)
            : { method: inspected.method, tool: inspected.tool };

        recordAudit("mcp->agent", inspected, correlated.method, correlated.tool, latencyMs);

        if (inspected.findings.length > 0 || inspected.injectionAlerts.length > 0) {
          logStderr(
            `dir=mcp->agent transport=sse action=${inspected.action} scrubbed=${inspected.findings.length} injection_alerts=${inspected.injectionAlerts.length}`
          );
        }

        for (const reply of inspected.repliesToUpstream) {
          void sendUpstreamReply(targetUrl, reqHeaders, reply);
        }

        if (inspected.output !== null) {
          clientRes.write(encodeSseEvent({ ...evt, data: inspected.output }));
        }
      },
      {
        maxFrameBytes,
        onError: (err) =>
          logStderr(`dir=mcp->agent transport=sse parser_error=${err.code} bytes=${err.bytes}`),
      }
    );

    const reader = upstreamRes.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        parser.push(Buffer.from(value));
      }
      parser.end();
    } catch (err) {
      if (err?.name !== "AbortError") {
        logStderr(`sse_stream_error=${err?.message || err}`);
      }
    } finally {
      reader.releaseLock();
      if (!clientRes.writableEnded && !clientRes.destroyed) {
        clientRes.end();
      }
    }
  }

  const server = http.createServer(async (req, res) => {
    const reqUrl = req.url || "/";

    // Built-in readiness endpoint (never exposes query strings or auth headers)
    if (req.method === "GET" && reqUrl === "/_mcp-guard/health") {
      const body = JSON.stringify({
        status: "ok",
        upstream: `${upstreamBase.origin}${upstreamBase.pathname}`,
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
      return;
    }

    const targetUrl = resolveTargetUrl(upstreamBase, reqUrl);
    const forwardHeaders = filterRequestHeaders(req.headers);
    const ac = new AbortController();
    res.on("close", () => {
      if (!res.writableEnded) ac.abort();
    });

    try {
      if (req.method === "POST") {
        let rawBody;
        try {
          rawBody = await readBoundedBody(req, maxFrameBytes);
        } catch (err) {
          if (err?.code === "FRAME_TOO_LARGE") {
            logStderr(`dir=agent->mcp error=FRAME_TOO_LARGE max=${maxFrameBytes}`);
            res.writeHead(413, { "content-type": "application/json" });
            res.end(
              JSON.stringify({
                jsonrpc: "2.0",
                id: null,
                error: { code: -32600, message: "Request body exceeds mcp-guard maxFrameBytes limit." },
              })
            );
            return;
          }
          throw err;
        }

        const t0 = performance.now();
        const inbound = inspectFrame(rawBody, "agent->mcp", inspectOpts);
        const latencyMs = performance.now() - t0;

        recordAudit("agent->mcp", inbound, inbound.method, inbound.tool, latencyMs);

        if (inbound.findings.length > 0 || inbound.policyRules.length > 0 || inbound.unparseable) {
          logStderr(
            `dir=agent->mcp method=${inbound.method || "-"} tool=${inbound.tool || "-"} action=${inbound.action} scrubbed=${inbound.findings.length}`
          );
        }

        // Pre-execution policy block: reply directly to client without touching upstream
        if (inbound.action === "policy_denied") {
          if (inbound.repliesToClient.length > 0) {
            const payload = inbound.repliesToClient[0];
            res.writeHead(200, { "content-type": "application/json" });
            res.end(payload);
          } else {
            res.writeHead(204);
            res.end();
          }
          return;
        }

        if (inbound.id !== null && inbound.method !== null) {
          rememberPending(inbound.id, inbound.method, inbound.tool);
        }

        const bodyToSend = inbound.output ?? "";
        const upstreamRes = await fetchImpl(targetUrl, {
          method: "POST",
          headers: forwardHeaders,
          body: bodyToSend,
          signal: ac.signal,
        });

        const contentType = (upstreamRes.headers.get("content-type") || "").toLowerCase();
        const fallbackCall = { method: inbound.method, tool: inbound.tool };

        if (contentType.includes("text/event-stream")) {
          await pipeSseResponse(upstreamRes, res, targetUrl, forwardHeaders, fallbackCall);
          return;
        }

        if (upstreamRes.status === 202 || upstreamRes.status === 204) {
          copySafeResponseHeaders(upstreamRes.headers, res);
          res.writeHead(upstreamRes.status);
          res.end();
          return;
        }

        const upstreamBody = await readBoundedFetchText(upstreamRes, maxFrameBytes);
        const t1 = performance.now();
        const outbound = inspectFrame(upstreamBody, "mcp->agent", inspectOpts);
        const outLatencyMs = performance.now() - t1;

        const correlated =
          outbound.method === null
            ? correlatePending(outbound.id, fallbackCall.method, fallbackCall.tool)
            : { method: outbound.method, tool: outbound.tool };

        recordAudit("mcp->agent", outbound, correlated.method, correlated.tool, outLatencyMs);

        if (outbound.findings.length > 0 || outbound.injectionAlerts.length > 0) {
          logStderr(
            `dir=mcp->agent method=${correlated.method || "-"} tool=${correlated.tool || "-"} action=${outbound.action} scrubbed=${outbound.findings.length} injection_alerts=${outbound.injectionAlerts.length}`
          );
        }

        for (const reply of outbound.repliesToUpstream) {
          void sendUpstreamReply(targetUrl, forwardHeaders, reply);
        }

        copySafeResponseHeaders(upstreamRes.headers, res);
        if (outbound.output === null) {
          // Preserve error/auth status codes (e.g. 401 Unauthorized + WWW-Authenticate with empty body);
          // only convert intentionally dropped 2xx responses/notifications to 204 No Content.
          const status =
            outbound.action === "drop" && upstreamRes.status >= 200 && upstreamRes.status < 300
              ? 204
              : upstreamRes.status;
          res.writeHead(status);
          res.end();
          return;
        }

        res.writeHead(upstreamRes.status);
        res.end(outbound.output);
        return;
      }

      if (req.method === "GET") {
        const upstreamRes = await fetchImpl(targetUrl, {
          method: "GET",
          headers: forwardHeaders,
          signal: ac.signal,
        });
        const contentType = (upstreamRes.headers.get("content-type") || "").toLowerCase();
        if (contentType.includes("text/event-stream")) {
          await pipeSseResponse(upstreamRes, res, targetUrl, forwardHeaders, null);
          return;
        }
        const upstreamBody = await readBoundedFetchText(upstreamRes, maxFrameBytes);
        const outbound = inspectFrame(upstreamBody, "mcp->agent", inspectOpts);
        copySafeResponseHeaders(upstreamRes.headers, res);
        res.writeHead(upstreamRes.status);
        res.end(outbound.output ?? "");
        return;
      }

      if (req.method === "DELETE" || req.method === "OPTIONS") {
        const upstreamRes = await fetchImpl(targetUrl, {
          method: req.method,
          headers: forwardHeaders,
          signal: ac.signal,
        });
        const text = await readBoundedFetchText(upstreamRes, maxFrameBytes);
        copySafeResponseHeaders(upstreamRes.headers, res);
        res.writeHead(upstreamRes.status);
        res.end(text);
        return;
      }

      res.writeHead(405, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: `Method ${req.method} not allowed` }));
    } catch (err) {
      if (err?.name === "AbortError") return;
      if (err?.code === "FRAME_TOO_LARGE") {
        logStderr(`dir=mcp->agent error=FRAME_TOO_LARGE max=${maxFrameBytes}`);
        if (!res.headersSent) {
          res.writeHead(502, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              jsonrpc: "2.0",
              id: null,
              error: { code: -32003, message: "Upstream response exceeded mcp-guard maxFrameBytes limit." },
            })
          );
        }
        return;
      }
      logStderr(`upstream_error=${err?.message || err}`);
      if (!res.headersSent) {
        res.writeHead(502, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: { code: -32003, message: "mcp-guard upstream proxy error." },
          })
        );
      } else if (!res.writableEnded) {
        res.end();
      }
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });

  const addr = server.address();
  const actualPort = typeof addr === "object" && addr ? addr.port : port;
  const url = `http://${host}:${actualPort}`;
  logStderr(`listening=${url} upstream=${upstreamBase.origin}${upstreamBase.pathname}`);

  return {
    server,
    host,
    port: actualPort,
    url,
    async close() {
      await new Promise((resolve) => server.close(() => resolve()));
      if (auditLogger) {
        await auditLogger.close();
      }
    },
  };
}
