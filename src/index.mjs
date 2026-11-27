import {
  redactPayload,
  redactText,
  shannonEntropy,
  hashSecret,
  isValidLuhn,
  isValidIban,
  compileSafeRegex,
  SECRET_RULES,
  PII_RULES,
} from "./redact.mjs";
import {
  createPiiPseudonymizer,
  PII_PSEUDONYM_PREFIX,
} from "./pseudonymize.mjs";
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
  resolveSpawnSpec,
  DEFAULT_MAX_FRAME_BYTES,
} from "./proxy.mjs";
import {
  buildAuditEntry,
  createAuditLogger,
  summarizeAuditLog,
  formatAuditSummary,
} from "./audit.mjs";
import {
  matchGlob,
  validatePolicy,
  loadPolicyFile,
  evaluateToolCallPolicy,
  getOutboundSecretSkipPaths,
} from "./policy.mjs";
import {
  createSseParser,
  encodeSseEvent,
  startHttpProxy,
} from "./http-proxy.mjs";
import {
  isWrappedServer,
  wrapMcpConfig,
  unwrapMcpConfig,
  formatJsonDiff,
  applyMcpConfigTransform,
} from "./wrap.mjs";

export {
  redactText,
  redactPayload,
  shannonEntropy,
  hashSecret,
  isValidLuhn,
  isValidIban,
  compileSafeRegex,
  createPiiPseudonymizer,
  PII_PSEUDONYM_PREFIX,
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
  resolveSpawnSpec,
  DEFAULT_MAX_FRAME_BYTES,
  buildAuditEntry,
  createAuditLogger,
  summarizeAuditLog,
  formatAuditSummary,
  matchGlob,
  validatePolicy,
  loadPolicyFile,
  evaluateToolCallPolicy,
  getOutboundSecretSkipPaths,
  createSseParser,
  encodeSseEvent,
  startHttpProxy,
  isWrappedServer,
  wrapMcpConfig,
  unwrapMcpConfig,
  formatJsonDiff,
  applyMcpConfigTransform,
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
    pseudonymizePii = false,
    pseudonymizer = null,
    allowEmailDomains = [],
    disabledRules = null,
    customRules = null,
    allowPatterns = null,
    injectionThreshold = "medium",
    taintUntrusted = false,
  } = options;

  let working = payload;
  let aclReport = null;

  if (callerScopes !== null && callerScopes !== undefined) {
    if (!working || typeof working !== "object" || !Array.isArray(working.facts)) {
      return {
        sanitized: null,
        report: {
          secretsAndPiiRedacted: 0,
          findings: [],
          injectionAlerts: [],
          taintedPaths: [],
          acl: {
            enforced: false,
            blocked: true,
            reason: "unsupported_payload_shape_for_acl",
            allowedCount: 0,
            droppedCount: 0,
            droppedFactIds: [],
            strippedCitations: 0,
          },
          safe: false,
        },
      };
    }

    const filtered = filterFactsForPrincipal(working.facts, callerScopes);
    working = { ...working, facts: filtered.allowed };
    aclReport = {
      enforced: true,
      blocked: false,
      allowedCount: filtered.allowed.length,
      droppedCount: filtered.dropped.length,
      droppedFactIds: filtered.dropped.map((d) => d.factId),
      strippedCitations: filtered.strippedCitations,
    };
  }

  const { sanitized: redacted, findings } = redactPayload(working, {
    redactPii,
    pseudonymizePii,
    pseudonymizer,
    allowEmailDomains,
    disabledRules,
    customRules,
    allowPatterns,
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
