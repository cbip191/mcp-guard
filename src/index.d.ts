import type { ChildProcess } from "node:child_process";
import type { Readable, Writable } from "node:stream";

export type Severity = "low" | "medium" | "high" | "critical";
export type RuleTier = "high-confidence" | "heuristic";
export type FrameFraming = "ndjson" | "content-length";
export type ProxyDirection = "agent->mcp" | "mcp->agent";

export interface SecretRule {
  id: string;
  severity: Severity;
  pattern: RegExp;
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
  path?: string;
  inKey?: boolean;
}

export interface RedactTextOptions {
  redactPii?: boolean;
  allowEmailDomains?: string[];
  detectHighEntropy?: boolean;
}

export interface RedactPayloadOptions extends RedactTextOptions {
  skipEnvelope?: boolean;
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

export interface InspectFrameOptions {
  redactPii?: boolean;
  redactOutboundPii?: boolean;
  allowEmailDomains?: string[];
  blockInjections?: boolean;
  blockMinRules?: number;
  taintUntrusted?: boolean;
  injectionThreshold?: Severity;
}

export interface InspectFrameResult {
  action: "ignore" | "forward" | "replace" | "drop" | "drop_and_reply" | "tainted";
  output: string | null;
  repliesToUpstream: string[];
  findings: RedactionFinding[];
  injectionAlerts: InjectionAlert[];
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

export interface StdioProxyOptions extends InspectFrameOptions {
  auditLog?: string | null;
  onAuditEntry?: ((entry: AuditEntry) => void) | null;
  input?: Readable;
  output?: Writable;
  stderr?: Writable;
  exit?: (code: number) => void;
  forwardSignals?: boolean;
}

export interface GuardMcpOptions {
  callerScopes?: Iterable<string> | null;
  redactPii?: boolean;
  allowEmailDomains?: string[];
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
export declare const INJECTION_PATTERNS: InjectionRule[];
export declare const SEVERITY_RANK: Readonly<Record<Severity, number>>;

export declare function shannonEntropy(str: string): number;
export declare function hashSecret(value: string): string;
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

export declare function createFrameParser(onFrame: (frame: ParsedFrame) => void): FrameParser;
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

export declare function guardMcpResponse<T = unknown>(
  payload: T,
  options?: GuardMcpOptions
): GuardMcpResult<T>;
