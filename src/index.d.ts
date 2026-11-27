import type { ChildProcess } from "node:child_process";
import type { Server } from "node:http";
import type { Readable, Writable } from "node:stream";

export type Severity = "low" | "medium" | "high" | "critical";
export type RuleTier = "high-confidence" | "heuristic";
export type FrameFraming = "ndjson" | "content-length";
export type ProxyDirection = "agent->mcp" | "mcp->agent";

export interface SecretRule {
  id: string;
  severity: Severity;
  pattern: RegExp;
  pii?: boolean;
  valueGroup?: number;
  prefixGroup?: number;
  entropy?: boolean;
  validate?: (value: string) => boolean;
}

export interface RedactionFinding {
  ruleId: string;
  severity: Severity;
  preview: string;
  hash: string;
  token?: string;
  path?: string;
  inKey?: boolean;
}

export interface PiiPseudonymizerOptions {
  maxEntries?: number;
}

export interface PiiPseudonymizerStats {
  totalUnique: number;
  byType: Record<string, number>;
}

export interface PiiPseudonymizer {
  pseudonymize(ruleId: string, rawValue: string): string;
  stats(): PiiPseudonymizerStats;
  reset(): void;
}

export interface CustomRedactionRuleInput {
  id: string;
  pattern: string | RegExp;
  flags?: string;
  severity?: Severity;
}

export interface CompiledCustomRedactionRule {
  id: string;
  pattern: RegExp;
  source: string;
  flags: string;
  severity: Severity;
}

export interface CompileSafeRegexOptions {
  requireGlobal?: boolean;
  maxProbeMs?: number;
}

export interface RedactTextOptions {
  redactPii?: boolean;
  pseudonymizePii?: boolean;
  pseudonymizer?: PiiPseudonymizer | null;
  allowEmailDomains?: string[];
  detectHighEntropy?: boolean;
  disabledRules?: Iterable<string> | null;
  customRules?: CustomRedactionRuleInput[] | null;
  allowPatterns?: Array<string | RegExp> | null;
}

export interface RedactPayloadOptions extends RedactTextOptions {
  skipEnvelope?: boolean;
  skipPaths?: Iterable<string> | null;
}

export interface RedactTextResult {
  text: string;
  findings: RedactionFinding[];
}

export interface RedactPayloadResult<T = unknown> {
  sanitized: T;
  findings: RedactionFinding[];
}

export interface FactCitation {
  scopeId: string;
  itemRef?: string;
  [key: string]: unknown;
}

export interface ScopedFact {
  id: string;
  citations?: FactCitation[];
  [key: string]: unknown;
}

export interface DroppedFact {
  factId: string;
  reason: string;
}

export interface AclFilterResult<T extends ScopedFact = ScopedFact> {
  allowed: T[];
  dropped: DroppedFact[];
  strippedCitations: number;
  enforcedScopeCount: number;
}

export interface InjectionRule {
  id: string;
  severity: Severity;
  tier: RuleTier;
  rawOnly?: boolean;
  pattern: RegExp;
}

export interface InjectionAlert {
  ruleId: string;
  severity: Severity;
  tier: RuleTier;
  path: string;
  snippet: string;
}

export interface DetectInjectionOptions {
  threshold?: Severity;
}

export interface TaintResult<T = unknown> {
  tainted: T;
  alerts: InjectionAlert[];
  taintedPaths: string[];
}

export interface ParsedFrame {
  framing: FrameFraming;
  raw: string;
}

export interface FrameParser {
  push(chunk: Buffer | string): void;
  end(): void;
}

export interface FrameParserError {
  code: "FRAME_TOO_LARGE" | "HEADER_TOO_LARGE";
  bytes: number;
  maxBytes: number;
}

export interface FrameParserOptions {
  maxFrameBytes?: number;
  onError?: ((err: FrameParserError) => void) | null;
}

export interface PolicyToolsConfig {
  allow?: string[];
  deny?: string[];
  argConstraints?: Record<
    string,
    Record<string, string | number | boolean | Array<string | number | boolean>>
  >;
  allowSecretFields?: Record<string, string[]>;
}

export interface PolicyRedactionConfig {
  redactPii?: boolean;
  redactOutboundPii?: boolean;
  pseudonymizePii?: boolean;
  allowEmailDomains?: string[];
  disabledRules?: string[];
  customRules?: CompiledCustomRedactionRule[];
  allowPatterns?: RegExp[];
}

export interface RawPolicyRedactionConfig {
  redactPii?: boolean;
  redactOutboundPii?: boolean;
  pseudonymizePii?: boolean;
  allowEmailDomains?: string[];
  disabledRules?: string[];
  customRules?: Array<{
    id: string;
    pattern: string;
    flags?: string;
    severity?: Severity;
  }>;
  allowPatterns?: string[];
}

export interface PolicyInjectionConfig {
  taintUntrusted?: boolean;
  blockInjections?: boolean;
  blockMinRules?: number;
  threshold?: Severity;
}

export interface GuardPolicy {
  tools: {
    allow: string[];
    deny: string[];
    argConstraints: Record<string, Record<string, Array<string | number | boolean>>>;
    allowSecretFields: Record<string, string[]>;
  };
  redaction: PolicyRedactionConfig;
  injection: PolicyInjectionConfig;
}

export interface RawGuardPolicy {
  tools?: PolicyToolsConfig;
  redaction?: RawPolicyRedactionConfig;
  injection?: PolicyInjectionConfig;
}

export interface PolicyDecision {
  allowed: boolean;
  ruleId: "POLICY_TOOL_DENIED" | "POLICY_TOOL_NOT_ALLOWED" | "POLICY_ARG_CONSTRAINT" | null;
  reason: string | null;
}

export interface InspectFrameOptions {
  redactPii?: boolean;
  redactOutboundPii?: boolean;
  pseudonymizePii?: boolean;
  pseudonymizer?: PiiPseudonymizer | null;
  allowEmailDomains?: string[];
  disabledRules?: Iterable<string> | null;
  customRules?: CustomRedactionRuleInput[] | null;
  allowPatterns?: Array<string | RegExp> | null;
  blockInjections?: boolean;
  blockMinRules?: number;
  taintUntrusted?: boolean;
  injectionThreshold?: Severity;
  policy?: GuardPolicy | null;
}

export interface InspectFrameResult {
  action: "ignore" | "forward" | "replace" | "drop" | "drop_and_reply" | "tainted" | "policy_denied";
  output: string | null;
  repliesToUpstream: string[];
  repliesToClient: string[];
  findings: RedactionFinding[];
  injectionAlerts: InjectionAlert[];
  policyRules: string[];
  taintedPaths: string[];
  unparseable: boolean;
  id: string | number | null;
  method: string | null;
  tool: string | null;
}

export type AuditAction = "allow" | "redacted" | "tainted" | "blocked" | "dropped";

export interface AuditEntry {
  ts: string;
  dir: ProxyDirection;
  method: string | null;
  tool: string | null;
  action: AuditAction;
  rules: string[];
  secretHashes: string[];
  latencyMs: number;
}

export interface BuildAuditEntryInput {
  ts?: string;
  dir: ProxyDirection;
  method?: string | null;
  tool?: string | null;
  action?: AuditAction;
  findings?: RedactionFinding[];
  injectionAlerts?: InjectionAlert[];
  extraRules?: string[];
  latencyMs?: number;
}

export interface AuditLogger {
  write(entry: AuditEntry): boolean;
  close(): Promise<void>;
}

export interface AuditLoggerOptions {
  onError?: ((err: Error) => void) | null;
}

export interface AuditToolSummary {
  tool: string;
  events: number;
  redacted: number;
  tainted: number;
  blocked: number;
  dropped: number;
}

export interface AuditSummary {
  totalEvents: number;
  malformedLines: number;
  timeRange: { firstTs: string | null; lastTs: string | null };
  byDirection: Record<string, number>;
  byAction: Record<string, number>;
  blockedOrDropped: number;
  uniqueSecretHashes: number;
  topRules: Array<{ ruleId: string; count: number }>;
  topTools: AuditToolSummary[];
  latencyMs: { p50: number; p95: number; p99: number; max: number };
}

export interface SseEvent {
  event: string | null;
  id: string | null;
  retry: string | null;
  data: string;
}

export interface SseParser {
  push(chunk: Buffer | string): void;
  end(): void;
}

export interface HttpProxyOptions extends InspectFrameOptions {
  upstream: string;
  host?: string;
  port?: number;
  maxFrameBytes?: number;
  auditLog?: string | null;
  onAuditEntry?: ((entry: AuditEntry) => void) | null;
  stderr?: Writable;
  fetchImpl?: typeof fetch;
}

export interface HttpProxyHandle {
  server: Server;
  host: string;
  port: number;
  url: string;
  close(): Promise<void>;
}

export interface WrapConfigOptions {
  wrapperCommand?: string;
  wrapperArgs?: string[];
  proxyFlags?: string[];
  servers?: string[] | null;
}

export interface UnwrapConfigOptions {
  servers?: string[] | null;
}

export interface WrapSkippedServer {
  name: string;
  reason: string;
}

export interface WrapConfigResult {
  config: Record<string, unknown>;
  serversKey: "mcpServers" | "servers";
  wrapped: string[];
  alreadyWrapped: string[];
  skipped: WrapSkippedServer[];
  changed: boolean;
}

export interface UnwrapConfigResult {
  config: Record<string, unknown>;
  serversKey: "mcpServers" | "servers";
  unwrapped: string[];
  notWrapped: string[];
  skipped: WrapSkippedServer[];
  changed: boolean;
}

export interface ApplyWrapOptions extends WrapConfigOptions {
  apply?: boolean;
}

export interface ApplyWrapResult {
  config: Record<string, unknown>;
  serversKey: "mcpServers" | "servers";
  wrapped?: string[];
  alreadyWrapped?: string[];
  unwrapped?: string[];
  notWrapped?: string[];
  skipped: WrapSkippedServer[];
  changed: boolean;
  applied: boolean;
  backupPath: string | null;
  diff: string;
}

export interface StdioProxyOptions extends InspectFrameOptions {
  auditLog?: string | null;
  onAuditEntry?: ((entry: AuditEntry) => void) | null;
  maxFrameBytes?: number;
  input?: Readable;
  output?: Writable;
  stderr?: Writable;
  exit?: (code: number) => void;
  forwardSignals?: boolean;
}

export interface GuardMcpOptions {
  callerScopes?: Iterable<string> | null;
  redactPii?: boolean;
  pseudonymizePii?: boolean;
  pseudonymizer?: PiiPseudonymizer | null;
  allowEmailDomains?: string[];
  disabledRules?: Iterable<string> | null;
  customRules?: CustomRedactionRuleInput[] | null;
  allowPatterns?: Array<string | RegExp> | null;
  injectionThreshold?: Severity;
  taintUntrusted?: boolean;
}

export interface GuardAclReport {
  enforced: boolean;
  blocked: boolean;
  reason?: string;
  allowedCount: number;
  droppedCount: number;
  droppedFactIds: string[];
  strippedCitations: number;
}

export interface GuardMcpReport {
  secretsAndPiiRedacted: number;
  findings: RedactionFinding[];
  injectionAlerts: InjectionAlert[];
  taintedPaths: string[];
  acl: GuardAclReport | null;
  safe: boolean;
}

export interface GuardMcpResult<T = unknown> {
  sanitized: T | null;
  report: GuardMcpReport;
}

export declare const SECRET_RULES: SecretRule[];
export declare const PII_RULES: SecretRule[];
export declare const PII_PSEUDONYM_PREFIX: Readonly<Record<string, string>>;
export declare const INJECTION_PATTERNS: InjectionRule[];
export declare const SEVERITY_RANK: Readonly<Record<Severity, number>>;

export declare function shannonEntropy(str: string): number;
export declare function hashSecret(value: string): string;
export declare function isValidLuhn(value: string): boolean;
export declare function isValidIban(value: string): boolean;
export declare function compileSafeRegex(
  pattern: string,
  flags?: string,
  options?: CompileSafeRegexOptions
): RegExp;
export declare function createPiiPseudonymizer(options?: PiiPseudonymizerOptions): PiiPseudonymizer;
export declare function redactText(text: string, options?: RedactTextOptions): RedactTextResult;
export declare function redactPayload<T = unknown>(
  value: T,
  options?: RedactPayloadOptions
): RedactPayloadResult<T>;

export declare function filterFactsForPrincipal<T extends ScopedFact = ScopedFact>(
  facts: T[],
  callerScopes: Iterable<string>
): AclFilterResult<T>;

export declare function normalizeForInjectionScan(text: string): string;
export declare function detectPromptInjection(
  value: unknown,
  options?: DetectInjectionOptions
): InjectionAlert[];
export declare function taintUntrustedPayload<T = unknown>(
  value: T,
  options?: DetectInjectionOptions
): TaintResult<T>;

export declare const DEFAULT_MAX_FRAME_BYTES: number;

export declare function createFrameParser(
  onFrame: (frame: ParsedFrame) => void,
  options?: FrameParserOptions
): FrameParser;
export declare function encodeFrame(payloadStr: string, framing?: FrameFraming): string;
export declare function inspectFrame(
  raw: string,
  direction: ProxyDirection,
  options?: InspectFrameOptions
): InspectFrameResult;
export declare function runStdioProxy(
  command: string,
  args?: string[],
  options?: StdioProxyOptions
): ChildProcess | null;

export declare function matchGlob(pattern: string, value: string): boolean;
export declare function validatePolicy(raw: RawGuardPolicy): GuardPolicy;
export declare function loadPolicyFile(filePath: string): GuardPolicy;
export declare function evaluateToolCallPolicy(
  toolName: string,
  toolArgs: Record<string, unknown>,
  policy: GuardPolicy | null | undefined
): PolicyDecision;
export declare function getOutboundSecretSkipPaths(
  toolName: string,
  policy: GuardPolicy | null | undefined
): Set<string>;

export declare function buildAuditEntry(input: BuildAuditEntryInput): AuditEntry;
export declare function createAuditLogger(
  filePath: string,
  options?: AuditLoggerOptions
): AuditLogger;
export declare function summarizeAuditLog(jsonlText: string): AuditSummary;
export declare function formatAuditSummary(
  summary: AuditSummary,
  options?: { limit?: number }
): string;

export declare function createSseParser(
  onEvent: (event: SseEvent) => void,
  options?: FrameParserOptions
): SseParser;
export declare function encodeSseEvent(event: Partial<SseEvent>): string;
export declare function startHttpProxy(options: HttpProxyOptions): Promise<HttpProxyHandle>;

export declare function isWrappedServer(entry: unknown): boolean;
export declare function wrapMcpConfig(
  config: Record<string, unknown>,
  options?: WrapConfigOptions
): WrapConfigResult;
export declare function unwrapMcpConfig(
  config: Record<string, unknown>,
  options?: UnwrapConfigOptions
): UnwrapConfigResult;
export declare function formatJsonDiff(
  beforeText: string,
  afterText: string,
  label?: string
): string;
export declare function applyMcpConfigTransform(
  filePath: string,
  mode: "wrap" | "unwrap",
  options?: ApplyWrapOptions
): ApplyWrapResult;

export declare function guardMcpResponse<T = unknown>(
  payload: T,
  options?: GuardMcpOptions
): GuardMcpResult<T>;
