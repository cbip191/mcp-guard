import {
  redactPayload,
  redactText,
  shannonEntropy,
  SECRET_RULES,
  PII_RULES,
} from "./redact.mjs";
import { filterFactsForPrincipal } from "./acl.mjs";
import {
  detectPromptInjection,
  taintUntrustedPayload,
  normalizeForInjectionScan,
  INJECTION_PATTERNS,
  SEVERITY_RANK,
} from "./injection.mjs";
import {
  runStdioProxy,
  createFrameParser,
  encodeFrame,
  inspectFrame,
} from "./proxy.mjs";

export {
  redactText,
  redactPayload,
  shannonEntropy,
  SECRET_RULES,
  PII_RULES,
  filterFactsForPrincipal,
  detectPromptInjection,
  taintUntrustedPayload,
  normalizeForInjectionScan,
  INJECTION_PATTERNS,
  SEVERITY_RANK,
  runStdioProxy,
  createFrameParser,
  encodeFrame,
  inspectFrame,
};

/**
 * End-to-end B2B MCP response guard:
 * 1. Enforces fail-closed inherited ACLs (if callerScopes & facts are provided)
 * 2. Deterministically strips secrets & PII
 * 3. Flags (or non-destructively quarantines) indirect prompt-injection attempts
 */
export function guardMcpResponse(payload, options = {}) {
  const {
    callerScopes = null,
    redactPii = true,
    allowEmailDomains = [],
    injectionThreshold = "medium",
    taintUntrusted = false,
  } = options;

  let working = payload;
  let aclReport = null;

  if (callerScopes && working && Array.isArray(working.facts)) {
    const filtered = filterFactsForPrincipal(working.facts, callerScopes);
    working = { ...working, facts: filtered.allowed };
    aclReport = {
      allowedCount: filtered.allowed.length,
      droppedCount: filtered.dropped.length,
      droppedFactIds: filtered.dropped.map((d) => d.factId),
      strippedCitations: filtered.strippedCitations,
    };
  }

  const { sanitized: redacted, findings } = redactPayload(working, {
    redactPii,
    allowEmailDomains,
  });

  let sanitized = redacted;
  let injectionAlerts;
  let taintedPaths = [];

  if (taintUntrusted) {
    const taintRes = taintUntrustedPayload(redacted, { threshold: injectionThreshold });
    sanitized = taintRes.tainted;
    injectionAlerts = taintRes.alerts;
    taintedPaths = taintRes.taintedPaths;
  } else {
    injectionAlerts = detectPromptInjection(redacted, { threshold: injectionThreshold });
  }

  return {
    sanitized,
    report: {
      secretsAndPiiRedacted: findings.length,
      findings,
      injectionAlerts,
      taintedPaths,
      acl: aclReport,
      safe: findings.length === 0 && injectionAlerts.length === 0,
    },
  };
}
