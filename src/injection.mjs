/**
 * Indirect prompt-injection detector for untrusted external text (Jira comments,
 * Slack Connect messages, PR descriptions) entering coding-agent contexts.
 */

export const INJECTION_PATTERNS = [
  {
    id: "OVERRIDE_INSTRUCTIONS",
    severity: "high",
    pattern: /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)\b/i,
  },
  {
    id: "ROLE_HIJACK",
    severity: "high",
    pattern: /\b(?:you are now|act as|enter developer mode|system prompt override)\b/i,
  },
  {
    id: "SHELL_EXFILTRATION",
    severity: "critical",
    pattern: /\b(?:curl|wget|nc|bash|sh)\b[^\n]*(?:\.ssh|\.env|id_rsa|aws\/credentials|\/etc\/passwd|process\.env)/i,
  },
  {
    id: "SECRET_EXTRACTION",
    severity: "high",
    pattern: /\b(?:print|output|send|post|exfiltrate|reveal)\b[^\n]{0,60}\b(?:api[_ -]?key|secret|token|password|credentials|env vars?)\b/i,
  },
  {
    id: "HIDDEN_XML_TAG_INJECTION",
    severity: "medium",
    pattern: /<\s*(?:system|assistant|instruction|tool_call)\s*>/i,
  },
];

export function detectPromptInjection(value) {
  const alerts = [];

  function walk(node, path) {
    if (typeof node === "string") {
      for (const rule of INJECTION_PATTERNS) {
        const match = node.match(rule.pattern);
        if (match) {
          alerts.push({
            ruleId: rule.id,
            severity: rule.severity,
            path,
            snippet: match[0].slice(0, 120),
          });
        }
      }
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((item, idx) => walk(item, `${path}[${idx}]`));
      return;
    }
    if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) {
        walk(v, path ? `${path}.${k}` : k);
      }
    }
  }

  walk(value, "");
  return alerts;
}
