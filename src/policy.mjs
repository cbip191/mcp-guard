/**
 * Declarative `mcp-guard.json` policy engine for stdio/HTTP MCP servers.
 * Enforces tool allow/deny globs, argument constraints (e.g. Jira project_key,
 * Slack channel_id, GitHub repo), and per-tool secret-redaction field exceptions
 * deterministically before any upstream tool call executes.
 */
import { readFileSync } from "node:fs";
import { SEVERITY_RANK } from "./injection.mjs";
import { SECRET_RULES, PII_RULES, compileSafeRegex } from "./redact.mjs";

const BUILT_IN_RULE_IDS = new Set([
  ...SECRET_RULES.map((r) => r.id),
  ...PII_RULES.map((r) => r.id),
]);
const CUSTOM_RULE_ID_RE = /^[A-Z][A-Z0-9_]{1,63}$/;

const ALLOWED_TOP_KEYS = new Set(["tools", "redaction", "injection"]);
const ALLOWED_TOOLS_KEYS = new Set(["allow", "deny", "argConstraints", "allowSecretFields"]);
const ALLOWED_REDACTION_KEYS = new Set([
  "redactPii",
  "redactOutboundPii",
  "pseudonymizePii",
  "allowEmailDomains",
  "disabledRules",
  "customRules",
  "allowPatterns",
]);
const ALLOWED_CUSTOM_RULE_KEYS = new Set(["id", "pattern", "flags", "severity"]);
const ALLOWED_INJECTION_KEYS = new Set([
  "taintUntrusted",
  "blockInjections",
  "blockMinRules",
  "threshold",
]);

/**
 * Iterative linear-time glob matcher supporting `*` (0+ chars) and `?` (1 char).
 * Zero regex compilation, immune to ReDoS.
 */
export function matchGlob(pattern, value) {
  if (typeof pattern !== "string" || typeof value !== "string") return false;
  let p = 0;
  let s = 0;
  let starIdx = -1;
  let matchIdx = 0;

  while (s < value.length) {
    if (p < pattern.length && (pattern[p] === "?" || pattern[p] === value[s])) {
      p++;
      s++;
    } else if (p < pattern.length && pattern[p] === "*") {
      starIdx = p;
      matchIdx = s;
      p++;
    } else if (starIdx !== -1) {
      p = starIdx + 1;
      matchIdx++;
      s = matchIdx;
    } else {
      return false;
    }
  }

  while (p < pattern.length && pattern[p] === "*") {
    p++;
  }
  return p === pattern.length;
}

function assertPlainObject(val, label) {
  if (!val || typeof val !== "object" || Array.isArray(val)) {
    throw new Error(`Invalid policy: "${label}" must be a JSON object.`);
  }
}

function assertAllowedKeys(obj, allowed, label) {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      throw new Error(`Invalid policy: unknown key "${key}" in ${label}.`);
    }
  }
}

function assertStringArray(val, label) {
  if (!Array.isArray(val) || !val.every((x) => typeof x === "string" && x.length > 0)) {
    throw new Error(`Invalid policy: "${label}" must be an array of non-empty strings.`);
  }
}

/**
 * Strictly validates and normalizes a declarative `mcp-guard.json` policy object.
 * Fails closed on unknown keys or invalid types so typos never silently disable enforcement.
 */
export function validatePolicy(raw) {
  assertPlainObject(raw, "root");
  assertAllowedKeys(raw, ALLOWED_TOP_KEYS, "root");

  const normalized = {
    tools: {
      allow: [],
      deny: [],
      argConstraints: {},
      allowSecretFields: {},
    },
    redaction: {},
    injection: {},
  };

  if (raw.tools !== undefined) {
    assertPlainObject(raw.tools, "tools");
    assertAllowedKeys(raw.tools, ALLOWED_TOOLS_KEYS, "tools");

    if (raw.tools.allow !== undefined) {
      assertStringArray(raw.tools.allow, "tools.allow");
      normalized.tools.allow = [...raw.tools.allow];
    }
    if (raw.tools.deny !== undefined) {
      assertStringArray(raw.tools.deny, "tools.deny");
      normalized.tools.deny = [...raw.tools.deny];
    }
    if (raw.tools.argConstraints !== undefined) {
      assertPlainObject(raw.tools.argConstraints, "tools.argConstraints");
      for (const [toolPattern, rules] of Object.entries(raw.tools.argConstraints)) {
        assertPlainObject(rules, `tools.argConstraints.${toolPattern}`);
        const cleanedRules = {};
        for (const [argPath, allowedValues] of Object.entries(rules)) {
          if (Array.isArray(allowedValues)) {
            if (
              allowedValues.length === 0 ||
              !allowedValues.every(
                (v) => typeof v === "string" || typeof v === "number" || typeof v === "boolean"
              )
            ) {
              throw new Error(
                `Invalid policy: "tools.argConstraints.${toolPattern}.${argPath}" must be a non-empty array of strings, numbers, or booleans.`
              );
            }
            cleanedRules[argPath] = [...allowedValues];
          } else if (
            typeof allowedValues === "string" ||
            typeof allowedValues === "number" ||
            typeof allowedValues === "boolean"
          ) {
            cleanedRules[argPath] = [allowedValues];
          } else {
            throw new Error(
              `Invalid policy: "tools.argConstraints.${toolPattern}.${argPath}" must be a primitive or array of primitives.`
            );
          }
        }
        normalized.tools.argConstraints[toolPattern] = cleanedRules;
      }
    }
    if (raw.tools.allowSecretFields !== undefined) {
      assertPlainObject(raw.tools.allowSecretFields, "tools.allowSecretFields");
      for (const [toolPattern, fields] of Object.entries(raw.tools.allowSecretFields)) {
        assertStringArray(fields, `tools.allowSecretFields.${toolPattern}`);
        normalized.tools.allowSecretFields[toolPattern] = [...fields];
      }
    }
  }

  if (raw.redaction !== undefined) {
    assertPlainObject(raw.redaction, "redaction");
    assertAllowedKeys(raw.redaction, ALLOWED_REDACTION_KEYS, "redaction");
    if (raw.redaction.redactPii !== undefined) {
      if (typeof raw.redaction.redactPii !== "boolean") {
        throw new Error('Invalid policy: "redaction.redactPii" must be a boolean.');
      }
      normalized.redaction.redactPii = raw.redaction.redactPii;
    }
    if (raw.redaction.redactOutboundPii !== undefined) {
      if (typeof raw.redaction.redactOutboundPii !== "boolean") {
        throw new Error('Invalid policy: "redaction.redactOutboundPii" must be a boolean.');
      }
      normalized.redaction.redactOutboundPii = raw.redaction.redactOutboundPii;
    }
    if (raw.redaction.pseudonymizePii !== undefined) {
      if (typeof raw.redaction.pseudonymizePii !== "boolean") {
        throw new Error('Invalid policy: "redaction.pseudonymizePii" must be a boolean.');
      }
      normalized.redaction.pseudonymizePii = raw.redaction.pseudonymizePii;
    }
    if (raw.redaction.allowEmailDomains !== undefined) {
      assertStringArray(raw.redaction.allowEmailDomains, "redaction.allowEmailDomains");
      normalized.redaction.allowEmailDomains = raw.redaction.allowEmailDomains.map((d) =>
        d.trim().toLowerCase()
      );
    }
    if (raw.redaction.disabledRules !== undefined) {
      assertStringArray(raw.redaction.disabledRules, "redaction.disabledRules");
      for (const id of raw.redaction.disabledRules) {
        if (!BUILT_IN_RULE_IDS.has(id)) {
          throw new Error(`Invalid policy: unknown built-in rule "${id}" in redaction.disabledRules.`);
        }
      }
      normalized.redaction.disabledRules = [...new Set(raw.redaction.disabledRules)];
    }
    if (raw.redaction.customRules !== undefined) {
      if (!Array.isArray(raw.redaction.customRules)) {
        throw new Error('Invalid policy: "redaction.customRules" must be an array.');
      }
      const seenCustom = new Set();
      const compiledRules = [];
      for (let i = 0; i < raw.redaction.customRules.length; i++) {
        const entry = raw.redaction.customRules[i];
        const label = `redaction.customRules[${i}]`;
        assertPlainObject(entry, label);
        assertAllowedKeys(entry, ALLOWED_CUSTOM_RULE_KEYS, label);

        if (typeof entry.id !== "string" || !CUSTOM_RULE_ID_RE.test(entry.id)) {
          throw new Error(
            `Invalid policy: "${label}.id" must match /^[A-Z][A-Z0-9_]{1,63}$/.`
          );
        }
        if (BUILT_IN_RULE_IDS.has(entry.id) || seenCustom.has(entry.id)) {
          throw new Error(
            `Invalid policy: duplicate or built-in colliding rule id "${entry.id}" in ${label}.`
          );
        }
        seenCustom.add(entry.id);

        const severity =
          entry.severity !== undefined ? String(entry.severity).trim().toLowerCase() : "high";
        if (!Object.prototype.hasOwnProperty.call(SEVERITY_RANK, severity)) {
          throw new Error(
            `Invalid policy: "${label}.severity" must be one of: low, medium, high, critical.`
          );
        }

        let compiled;
        try {
          compiled = compileSafeRegex(entry.pattern, entry.flags ?? "", { requireGlobal: true });
        } catch (err) {
          throw new Error(`Invalid policy: "${label}.pattern": ${err.message}`);
        }

        compiledRules.push({
          id: entry.id,
          pattern: compiled,
          source: entry.pattern,
          flags: compiled.flags,
          severity,
        });
      }
      normalized.redaction.customRules = compiledRules;
    }
    if (raw.redaction.allowPatterns !== undefined) {
      assertStringArray(raw.redaction.allowPatterns, "redaction.allowPatterns");
      const compiledAllow = [];
      for (let i = 0; i < raw.redaction.allowPatterns.length; i++) {
        try {
          compiledAllow.push(
            compileSafeRegex(raw.redaction.allowPatterns[i], "", { requireGlobal: false })
          );
        } catch (err) {
          throw new Error(`Invalid policy: "redaction.allowPatterns[${i}]": ${err.message}`);
        }
      }
      normalized.redaction.allowPatterns = compiledAllow;
    }
  }

  if (raw.injection !== undefined) {
    assertPlainObject(raw.injection, "injection");
    assertAllowedKeys(raw.injection, ALLOWED_INJECTION_KEYS, "injection");
    if (raw.injection.taintUntrusted !== undefined) {
      if (typeof raw.injection.taintUntrusted !== "boolean") {
        throw new Error('Invalid policy: "injection.taintUntrusted" must be a boolean.');
      }
      normalized.injection.taintUntrusted = raw.injection.taintUntrusted;
    }
    if (raw.injection.blockInjections !== undefined) {
      if (typeof raw.injection.blockInjections !== "boolean") {
        throw new Error('Invalid policy: "injection.blockInjections" must be a boolean.');
      }
      normalized.injection.blockInjections = raw.injection.blockInjections;
    }
    if (raw.injection.blockMinRules !== undefined) {
      if (!Number.isInteger(raw.injection.blockMinRules) || raw.injection.blockMinRules < 1) {
        throw new Error('Invalid policy: "injection.blockMinRules" must be a positive integer.');
      }
      normalized.injection.blockMinRules = raw.injection.blockMinRules;
    }
    if (raw.injection.threshold !== undefined) {
      const t = String(raw.injection.threshold).trim().toLowerCase();
      if (!Object.prototype.hasOwnProperty.call(SEVERITY_RANK, t)) {
        throw new Error(
          `Invalid policy: "injection.threshold" must be one of: low, medium, high, critical.`
        );
      }
      normalized.injection.threshold = t;
    }
  }

  return normalized;
}

/**
 * Loads and strictly validates a declarative `mcp-guard.json` policy file.
 */
export function loadPolicyFile(filePath) {
  const rawText = readFileSync(filePath, "utf8");
  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    throw new Error(`Invalid JSON in policy file ${filePath}: ${err.message}`);
  }
  return validatePolicy(parsed);
}

function readDotPath(obj, dotPath) {
  if (!obj || typeof obj !== "object") return undefined;
  const parts = dotPath.split(".");
  let cursor = obj;
  for (let i = 0; i < parts.length; i++) {
    const key = parts[i];
    if (
      !cursor ||
      typeof cursor !== "object" ||
      !Object.prototype.hasOwnProperty.call(cursor, key)
    ) {
      return undefined;
    }
    cursor = cursor[key];
  }
  return cursor;
}

function matchesConstraintValue(actual, allowedList) {
  if (Array.isArray(actual)) {
    if (actual.length === 0) return false;
    return actual.every((item) => matchesConstraintValue(item, allowedList));
  }
  for (let i = 0; i < allowedList.length; i++) {
    const allowed = allowedList[i];
    if (typeof allowed === "string" && typeof actual === "string") {
      if (matchGlob(allowed, actual)) return true;
    } else if (actual === allowed) {
      return true;
    }
  }
  return false;
}

/**
 * Evaluates a `tools/call` invocation against a validated policy.
 * Order of precedence:
 * 1. `tools.deny` globs (explicit deny always wins)
 * 2. `tools.allow` globs (when non-empty, default-deny anything not listed)
 * 3. `tools.argConstraints` for every matching tool glob (fail-closed on missing or mismatched args)
 */
export function evaluateToolCallPolicy(toolName, toolArgs, policy) {
  if (!policy || !policy.tools) {
    return { allowed: true, ruleId: null, reason: null };
  }
  if (typeof toolName !== "string" || toolName.length === 0) {
    return {
      allowed: false,
      ruleId: "POLICY_TOOL_DENIED",
      reason: "Missing or invalid tool name in tools/call request.",
    };
  }

  const { allow = [], deny = [], argConstraints = {} } = policy.tools;

  for (let i = 0; i < deny.length; i++) {
    if (matchGlob(deny[i], toolName)) {
      return {
        allowed: false,
        ruleId: "POLICY_TOOL_DENIED",
        reason: `Tool "${toolName}" is denied by policy pattern "${deny[i]}".`,
      };
    }
  }

  if (allow.length > 0 && !allow.some((pattern) => matchGlob(pattern, toolName))) {
    return {
      allowed: false,
      ruleId: "POLICY_TOOL_NOT_ALLOWED",
      reason: `Tool "${toolName}" is not permitted by tools.allow policy.`,
    };
  }

  for (const [toolPattern, constraints] of Object.entries(argConstraints)) {
    if (!matchGlob(toolPattern, toolName)) continue;

    for (const [argPath, allowedValues] of Object.entries(constraints)) {
      const actual = readDotPath(toolArgs, argPath);
      if (actual === undefined || actual === null) {
        return {
          allowed: false,
          ruleId: "POLICY_ARG_CONSTRAINT",
          reason: `Tool "${toolName}" missing required constrained argument "${argPath}".`,
        };
      }
      if (!matchesConstraintValue(actual, allowedValues)) {
        return {
          allowed: false,
          ruleId: "POLICY_ARG_CONSTRAINT",
          reason: `Tool "${toolName}" argument "${argPath}" violates policy constraint.`,
        };
      }
    }
  }

  return { allowed: true, ruleId: null, reason: null };
}

/**
 * Returns payload dot-paths exempt from outbound secret redaction for a given tool
 * (e.g. `tools.allowSecretFields: { "vault_write_secret": ["value"] }` -> `params.arguments.value`).
 */
export function getOutboundSecretSkipPaths(toolName, policy) {
  const skip = new Set();
  const map = policy?.tools?.allowSecretFields;
  if (!map || typeof toolName !== "string" || toolName.length === 0) {
    return skip;
  }

  for (const [toolPattern, fields] of Object.entries(map)) {
    if (!matchGlob(toolPattern, toolName)) continue;
    for (const field of fields) {
      const cleaned = field.replace(/^\.+/, "");
      if (!cleaned) continue;
      if (cleaned.startsWith("params.")) {
        skip.add(cleaned);
      } else if (cleaned.startsWith("arguments.")) {
        skip.add(`params.${cleaned}`);
      } else {
        skip.add(`params.arguments.${cleaned}`);
      }
    }
  }
  return skip;
}
