import {
  redactText,
  redactPayload,
  shannonEntropy,
  hashSecret,
  SECRET_RULES,
  PII_RULES,
  filterFactsForPrincipal,
  detectPromptInjection,
  taintUntrustedPayload,
  normalizeForInjectionScan,
  INJECTION_PATTERNS,
  SEVERITY_RANK,
  createFrameParser,
  encodeFrame,
  inspectFrame,
  runStdioProxy,
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
  guardMcpResponse,
  type AuditSummary,
  type GuardMcpResult,
  type GuardPolicy,
  type Severity,
} from "@4sails/mcp-guard";

const entropy: number = shannonEntropy("abc123");
const textRes = redactText("hello", {
  redactPii: true,
  allowEmailDomains: ["agency.dev"],
  detectHighEntropy: true,
});
const payloadRes = redactPayload({ ok: true }, { skipEnvelope: true });

const aclRes = filterFactsForPrincipal(
  [{ id: "f1", citations: [{ scopeId: "jira:HBR" }] }],
  ["jira:HBR"]
);

const threshold: Severity = "high";
const norm: string = normalizeForInjectionScan("test");
const alerts = detectPromptInjection({ a: "b" }, { threshold });
const tainted = taintUntrustedPayload({ a: "b" }, { threshold });

const parser = createFrameParser((frame) => {
  const encoded: string = encodeFrame(frame.raw, frame.framing);
  void encoded;
});
parser.push("hello\n");
parser.end();

const inspected = inspectFrame("{}", "agent->mcp", {
  redactPii: true,
  redactOutboundPii: false,
  blockInjections: true,
  blockMinRules: 2,
  taintUntrusted: true,
  injectionThreshold: "high",
});

const guarded: GuardMcpResult<{ facts: Array<{ id: string }> }> = guardMcpResponse(
  { facts: [{ id: "1" }] },
  {
    callerScopes: ["jira:HBR"],
    allowEmailDomains: ["agency.dev"],
    injectionThreshold: "medium",
    taintUntrusted: true,
  }
);

const hash: string = hashSecret("secret");
const auditEntry = buildAuditEntry({
  dir: "agent->mcp",
  method: "tools/call",
  tool: "jira_search",
  action: "redacted",
  findings: textRes.findings,
  latencyMs: 0.12,
});
const auditSummary: AuditSummary = summarizeAuditLog(`${JSON.stringify(auditEntry)}\n`);
const formattedAudit: string = formatAuditSummary(auditSummary, { limit: 5 });

const policy: GuardPolicy = validatePolicy({
  tools: {
    allow: ["jira_*"],
    deny: ["*_delete*"],
    argConstraints: { "jira_*": { project_key: ["HBR"] } },
    allowSecretFields: { vault_write_secret: ["value"] },
  },
});
const globOk: boolean = matchGlob("jira_*", "jira_get_issue");
const decision = evaluateToolCallPolicy("jira_get_issue", { project_key: "HBR" }, policy);
const skipPaths: Set<string> = getOutboundSecretSkipPaths("vault_write_secret", policy);

void [
  entropy,
  hash,
  auditEntry,
  auditSummary,
  formattedAudit,
  createAuditLogger,
  policy,
  globOk,
  decision,
  skipPaths,
  loadPolicyFile,
  DEFAULT_MAX_FRAME_BYTES,
  textRes,
  payloadRes,
  aclRes,
  norm,
  alerts,
  tainted,
  inspected,
  guarded,
  SECRET_RULES,
  PII_RULES,
  INJECTION_PATTERNS,
  SEVERITY_RANK,
  runStdioProxy,
];
