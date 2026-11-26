/**
 * Deterministic secret & PII redactor for Jira, Slack, Git, and MCP tool payloads.
 * Runs synchronously with zero external dependencies before any text hits an LLM context.
 */

export const SECRET_RULES = [
  {
    id: "AWS_ACCESS_KEY",
    severity: "critical",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    id: "GITHUB_TOKEN",
    severity: "critical",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,255}\b/g,
  },
  {
    id: "GITHUB_FINE_GRAINED_PAT",
    severity: "critical",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
  },
  {
    id: "SLACK_TOKEN",
    severity: "critical",
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,200}\b/g,
  },
  {
    id: "SLACK_WEBHOOK",
    severity: "high",
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
  },
  {
    id: "STRIPE_SECRET_KEY",
    severity: "critical",
    pattern: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,120}\b/g,
  },
  {
    id: "OPENAI_API_KEY",
    severity: "critical",
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,160}\b/g,
  },
  {
    id: "ANTHROPIC_API_KEY",
    severity: "critical",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,160}\b/g,
  },
  {
    id: "PRIVATE_KEY_BLOCK",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
  },
  {
    id: "DATABASE_URI_CREDENTIALS",
    severity: "critical",
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s"']+:[^@\s"']+@[^\s"']+/gi,
  },
  {
    id: "JWT_TOKEN",
    severity: "high",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
  {
    id: "BEARER_TOKEN",
    severity: "high",
    pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/g,
  },
];

export const PII_RULES = [
  {
    id: "EMAIL_ADDRESS",
    severity: "medium",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    id: "PHONE_NUMBER",
    severity: "medium",
    pattern: /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]\d{3}[\s.-]\d{3,4}\b/g,
  },
];

/**
 * Redacts secrets (and optionally PII) from a string, returning sanitized text and findings.
 */
export function redactText(text, options = {}) {
  const { redactPii = true, allowEmailDomains = [] } = options;
  if (typeof text !== "string" || text.length === 0) {
    return { text, findings: [] };
  }

  const findings = [];
  let output = text;

  const rules = redactPii ? [...SECRET_RULES, ...PII_RULES] : SECRET_RULES;

  for (const rule of rules) {
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    output = output.replace(regex, (match) => {
      if (rule.id === "EMAIL_ADDRESS" && allowEmailDomains.length > 0) {
        const domain = match.split("@")[1]?.toLowerCase();
        if (domain && allowEmailDomains.includes(domain)) {
          return match;
        }
      }
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        preview: match.length > 10 ? `${match.slice(0, 4)}…${match.slice(-3)}` : "***",
      });
      return `[REDACTED:${rule.id}]`;
    });
  }

  return { text: output, findings };
}

/**
 * Recursively sanitizes any JSON-serializable payload (objects, arrays, strings).
 */
export function redactPayload(value, options = {}) {
  const findings = [];

  function walk(node, path) {
    if (typeof node === "string") {
      const res = redactText(node, options);
      for (const f of res.findings) {
        findings.push({ ...f, path });
      }
      return res.text;
    }
    if (Array.isArray(node)) {
      return node.map((item, idx) => walk(item, `${path}[${idx}]`));
    }
    if (node && typeof node === "object") {
      const out = {};
      for (const [k, v] of Object.entries(node)) {
        out[k] = walk(v, path ? `${path}.${k}` : k);
      }
      return out;
    }
    return node;
  }

  const sanitized = walk(value, "");
  return { sanitized, findings };
}
