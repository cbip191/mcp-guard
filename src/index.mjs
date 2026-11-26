import {
  redactPayload,
  redactText,
  shannonEntropy,
  SECRET_RULES,
  PII_RULES,
} from "./redact.mjs";
import { filterFactsForPrincipal } from "./acl.mjs";
import { detectPromptInjection, INJECTION_PATTERNS } from "./injection.mjs";
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
  INJECTION_PATTERNS,
  runStdioProxy,
  createFrameParser,
  encodeFrame,
  inspectFrame,
};

/**
 * End-to-end B2B MCP response guard:
 * 1. Enforces fail-closed inherited ACLs (if callerScopes & facts are provided)
 * 2. Deterministically strips secrets & PII
 * 3. Flags indirect prompt-injection attempts
 */
export function guardMcpResponse(payload, options = {}) {
  const {
    callerScopes = null,
    redactPii = true,
    allowEmailDomains = [],
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

  const { sanitized, findings } = redactPayload(working, {
    redactPii,
    allowEmailDomains,
  });

  const injectionAlerts = detectPromptInjection(sanitized);

  return {
    sanitized,
    report: {
      secretsAndPiiRedacted: findings.length,
      findings,
      injectionAlerts,
      acl: aclReport,
      safe: findings.length === 0 && injectionAlerts.length === 0,
    },
  };
}
