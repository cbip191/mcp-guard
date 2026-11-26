import {
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
  createFrameParser,
  encodeFrame,
  inspectFrame,
  runStdioProxy,
  guardMcpResponse,
  type GuardMcpResult,
  type Severity,
} from "../src/index.mjs";

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
  taintUntrusted: false,
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

void [
  entropy,
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
