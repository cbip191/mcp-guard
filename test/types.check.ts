import {
  redactText,
  redactPayload,
  shannonEntropy,
  hashSecret,
  isValidLuhn,
  isValidIban,
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
  createSseParser,
  encodeSseEvent,
  startHttpProxy,
  isWrappedServer,
  wrapMcpConfig,
  unwrapMcpConfig,
  formatJsonDiff,
  applyMcpConfigTransform,
  guardMcpResponse,
  type AuditSummary,
  type GuardMcpResult,
  type GuardPolicy,
  type HttpProxyHandle,
  type PiiPseudonymizer,
  type Severity,
} from "@4sails/mcp-guard";

const entropy: number = shannonEntropy("abc123");
const luhnOk: boolean = isValidLuhn("4242424242424242");
const ibanOk: boolean = isValidIban("DE89 3704 0044 0532 0130 00");
const pseudo: PiiPseudonymizer = createPiiPseudonymizer({ maxEntries: 500 });
const pseudoToken: string = pseudo.pseudonymize("EMAIL_ADDRESS", "maria@client.com");
const pseudoStats = pseudo.stats();
const textRes = redactText("hello", {
  redactPii: true,
  pseudonymizePii: true,
  pseudonymizer: pseudo,
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

const sseParser = createSseParser((evt) => {
  const wire: string = encodeSseEvent(evt);
  void wire;
});
sseParser.push("data: {}\n\n");
sseParser.end();
const startFn: (opts: { upstream: string }) => Promise<HttpProxyHandle> = startHttpProxy;

const wrappedCfg = wrapMcpConfig({ mcpServers: { gh: { command: "npx", args: ["-y", "srv"] } } });
const unwrappedCfg = unwrapMcpConfig(wrappedCfg.config);
const wrappedCheck: boolean = isWrappedServer({ command: "npx", args: ["-y", "@4sails/mcp-guard", "proxy", "--", "srv"] });
const diffText: string = formatJsonDiff("a\n", "b\n");

void [
  entropy,
  luhnOk,
  ibanOk,
  pseudoToken,
  pseudoStats,
  PII_PSEUDONYM_PREFIX,
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
  startFn,
  wrappedCfg,
  unwrappedCfg,
  wrappedCheck,
  diffText,
  applyMcpConfigTransform,
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
