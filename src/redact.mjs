/**
 * Deterministic secret & PII redactor for Jira, Slack, Git, and MCP tool payloads.
 * Runs synchronously with zero external dependencies before any text hits an LLM context.
 */
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { createPiiPseudonymizer } from "./pseudonymize.mjs";

const ALLOWED_REGEX_FLAGS = new Set(["g", "i", "m", "s", "u"]);
const NESTED_QUANTIFIER_RE = /\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*]/;
const REDOS_PROBES = [
  `${"a".repeat(22)}!`,
  `${"0".repeat(22)}!`,
  `${"a-".repeat(12)}!`,
  `${"ab".repeat(12)}!`,
];
const MAX_SAFE_REGEX_LEN = 2048;
const MAX_SAFE_PROBE_MS = 20;

/**
 * Compiles a user-supplied regex string with strict syntax, flag, and ReDoS safety checks.
 * Rejects invalid patterns, unsupported flags, nested unbounded quantifiers, and patterns
 * exhibiting super-linear backtracking on adversarial probes.
 */
export function compileSafeRegex(pattern, flags = "", options = {}) {
  const { requireGlobal = false, maxProbeMs = MAX_SAFE_PROBE_MS } = options;

  if (typeof pattern !== "string" || pattern.length === 0) {
    throw new Error("Invalid regex: pattern must be a non-empty string.");
  }
  if (pattern.length > MAX_SAFE_REGEX_LEN) {
    throw new Error(`Invalid regex: pattern exceeds maximum length of ${MAX_SAFE_REGEX_LEN} characters.`);
  }
  if (typeof flags !== "string") {
    throw new Error("Invalid regex: flags must be a string.");
  }

  const flagSet = new Set();
  for (const ch of flags) {
    if (!ALLOWED_REGEX_FLAGS.has(ch)) {
      throw new Error(`Invalid regex: unsupported flag "${ch}" (allowed: g, i, m, s, u).`);
    }
    flagSet.add(ch);
  }
  if (requireGlobal) flagSet.add("g");
  else flagSet.delete("g");

  if (NESTED_QUANTIFIER_RE.test(pattern)) {
    throw new Error("Unsafe regex rejected: nested unbounded quantifiers risk ReDoS backtracking.");
  }

  const normalizedFlags = [...flagSet].sort().join("");
  let compiled;
  try {
    compiled = new RegExp(pattern, normalizedFlags);
  } catch (err) {
    throw new Error(`Invalid regex syntax: ${err.message}`);
  }

  // Probe compiled regex on short adversarial inputs to catch overlapping alternations like (a|a)+
  const probeRe = new RegExp(compiled.source, compiled.flags.replace(/g/g, ""));
  for (let i = 0; i < REDOS_PROBES.length; i++) {
    const t0 = performance.now();
    probeRe.test(REDOS_PROBES[i]);
    const elapsed = performance.now() - t0;
    if (elapsed > maxProbeMs) {
      throw new Error(
        `Unsafe regex rejected: adversarial ReDoS probe took ${elapsed.toFixed(1)}ms (limit ${maxProbeMs}ms).`
      );
    }
  }

  return compiled;
}

const IBAN_LENGTHS = Object.freeze({
  AL: 28, AD: 24, AT: 20, AZ: 28, BH: 22, BY: 28, BE: 16, BA: 20, BR: 29, BG: 22,
  CR: 22, HR: 21, CY: 28, CZ: 24, DK: 18, DO: 28, EE: 20, FO: 18, FI: 18, FR: 27,
  GE: 22, DE: 22, GI: 23, GR: 27, GL: 18, GT: 28, HU: 28, IS: 26, IQ: 23, IE: 22,
  IL: 23, IT: 27, JO: 30, KZ: 20, XK: 20, KW: 30, LV: 21, LB: 28, LI: 21, LT: 20,
  LU: 20, MK: 19, MT: 31, MR: 27, MU: 30, MC: 27, MD: 24, ME: 22, NL: 18, NO: 15,
  PK: 24, PS: 29, PL: 28, PT: 25, QA: 29, RO: 24, LC: 32, SM: 27, ST: 25, SA: 24,
  RS: 22, SC: 31, SK: 24, SI: 19, ES: 24, SE: 24, CH: 21, TL: 23, TN: 24, TR: 26,
  UA: 29, AE: 23, GB: 22, VA: 22, VG: 24,
});

/**
 * Validates a numeric string with the standard Luhn (mod-10) checksum.
 */
export function isValidLuhn(value) {
  if (typeof value !== "string") return false;
  const digits = value.replace(/[\s-]/g, "");
  if (digits.length < 13 || digits.length > 19 || !/^\d+$/.test(digits)) {
    return false;
  }
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

function isValidCreditCard(value) {
  const digits = String(value).replace(/[\s-]/g, "");
  const len = digits.length;
  if (digits.startsWith("34") || digits.startsWith("37")) {
    if (len !== 15) return false;
  } else if (digits.startsWith("4")) {
    if (len !== 13 && len !== 16 && len !== 19) return false;
  } else if (digits.startsWith("5") || digits.startsWith("2")) {
    if (len !== 16) return false;
  } else if (digits.startsWith("6")) {
    if (len !== 16 && len !== 19) return false;
  } else {
    return false;
  }
  return isValidLuhn(digits);
}

/**
 * Validates an IBAN against ISO 13616 country lengths and the MOD-97 checksum.
 */
export function isValidIban(value) {
  if (typeof value !== "string") return false;
  const cleaned = value.replace(/\s+/g, "").toUpperCase();
  if (cleaned.length < 15 || cleaned.length > 34 || !/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(cleaned)) {
    return false;
  }
  const country = cleaned.slice(0, 2);
  const expectedLen = Object.prototype.hasOwnProperty.call(IBAN_LENGTHS, country)
    ? IBAN_LENGTHS[country]
    : null;
  if (!expectedLen || cleaned.length !== expectedLen) {
    return false;
  }

  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);
  let remainder = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    if (code >= 48 && code <= 57) {
      remainder = (remainder * 10 + (code - 48)) % 97;
    } else if (code >= 65 && code <= 90) {
      const val = code - 55; // A=10 .. Z=35
      remainder = (remainder * 10 + Math.floor(val / 10)) % 97;
      remainder = (remainder * 10 + (val % 10)) % 97;
    } else {
      return false;
    }
  }
  return remainder === 1;
}

const JSON_RPC_ENVELOPE_KEYS = new Set(["jsonrpc", "id", "method"]);
const SCHEMA_METADATA_KEYS = new Set(["$schema", "$id", "$ref"]);

const SENSITIVE_KEY_NAME_RE =
  /(?:^|[_\-.])(?:api[_-]?key|apikey|api[_-]?secret|client[_-]?secret|secret[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?token|signing[_-]?secret|signing[_-]?key|webhook[_-]?secret|encryption[_-]?key|master[_-]?key|private[_-]?key|password|passwd|pwd|db[_-]?pass(?:word)?|secret|token|credential)(?:$|[_\-.])/i;

const SENSITIVE_CAMEL_KEY_RE =
  /(?:apiKey|apiSecret|clientSecret|secretKey|accessKey|accessToken|authToken|refreshToken|privateToken|signingSecret|signingKey|webhookSecret|encryptionKey|masterKey|privateKey|dbPassword|secretAccessKey)$/;

const NON_SECRET_KEY_NAME_RE =
  /(?:count|max|min|limit|len|length|type|kind|name|path|file|dir|url|uri|host|port|region|header|prefix|suffix|hint|policy|ttl|exp|expiry|expires|algo|algorithm|version|status|enabled|disabled|required|format|schema|ref|arn|id|ids|scope|scopes)$/i;

const AWS_SECRET_KEY_NAME_RE =
  /^(?:aws[_-]?secret(?:[_-]?access)?[_-]?key|secret[_-]?access[_-]?key|secretAccessKey)$/i;

const GEMINI_KEY_NAME_RE =
  /^(?:gemini[_-]?(?:api[_-]?)?key|google[_-]?ai[_-]?(?:api[_-]?)?key|geminiApiKey)$/i;

const MISTRAL_KEY_NAME_RE =
  /^(?:mistral[_-]?(?:api[_-]?)?key|mistralApiKey)$/i;

const PLACEHOLDER_VALUE_RE =
  /^(?:your[_-]|replace[_-]|placeholder|changeme|example[_-]|dummy[_-]|sample[_-]|fake[_-]|redacted|xxx+|000+|\*+)/i;

const ENV_REF_RE = /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/;
const URL_RE = /^https?:\/\//i;
const PATH_RE = /^(?:\/|\.{1,2}\/|~\/)/;
const HEX_RE = /^[0-9a-fA-F]{32,}$/;

/**
 * Computes Shannon entropy (bits per character) of a string.
 */
export function shannonEntropy(str) {
  if (typeof str !== "string" || str.length === 0) return 0;
  const counts = new Map();
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isSensitiveKeyName(key) {
  if (typeof key !== "string" || key.length === 0) return false;
  if (NON_SECRET_KEY_NAME_RE.test(key)) return false;
  return SENSITIVE_KEY_NAME_RE.test(key) || SENSITIVE_CAMEL_KEY_RE.test(key);
}

function isHighEntropySecretValue(val) {
  if (typeof val !== "string" || val.length < 16 || val.length > 512) return false;
  if (/\s/.test(val)) return false;
  if (val.startsWith("[REDACTED:")) return false;
  if (URL_RE.test(val) || PATH_RE.test(val) || ENV_REF_RE.test(val)) return false;
  if (PLACEHOLDER_VALUE_RE.test(val)) return false;

  const entropy = shannonEntropy(val);
  if (HEX_RE.test(val)) {
    return entropy >= 3.3;
  }

  let classes = 0;
  if (/[a-z]/.test(val)) classes++;
  if (/[A-Z]/.test(val)) classes++;
  if (/[0-9]/.test(val)) classes++;

  return classes >= 2 && entropy >= 3.6;
}

/**
 * Computes a one-way truncated SHA-256 fingerprint for audit correlation
 * without ever storing or logging raw secrets.
 */
export function hashSecret(value) {
  const digest = createHash("sha256").update(String(value)).digest("hex").slice(0, 16);
  return `sha256:${digest}`;
}

function makePreview(secret) {
  return secret.length > 10 ? `${secret.slice(0, 4)}…${secret.slice(-3)}` : "***";
}

export const SECRET_RULES = [
  {
    id: "AWS_ACCESS_KEY",
    severity: "critical",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    id: "AWS_SECRET_ACCESS_KEY",
    severity: "critical",
    pattern:
      /(\b(?:aws[_-]?secret(?:[_-]?access)?[_-]?key|secret[_-]?access[_-]?key|secretAccessKey)\b\\?["']?\s*[:=]\s*\\?["']?)([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
    valueGroup: 2,
    prefixGroup: 1,
    validate: (val) => shannonEntropy(val) >= 3.3,
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
    id: "GITLAB_PAT",
    severity: "critical",
    pattern: /\bgl(?:pat|oas|dt|rt|cbt)-[A-Za-z0-9_-]{20,100}\b/g,
  },
  {
    id: "ATLASSIAN_API_TOKEN",
    severity: "critical",
    pattern: /\bAT[A-Z]TT3x[A-Za-z0-9_=-]{20,256}\b/g,
  },
  {
    id: "GEMINI_API_KEY",
    severity: "critical",
    pattern:
      /(\b(?:gemini[_-]?(?:api[_-]?)?key|google[_-]?ai[_-]?(?:api[_-]?)?key|geminiApiKey)\b\\?["']?\s*[:=]\s*\\?["']?)(AIza[0-9A-Za-z_-]{35})\b/gi,
    valueGroup: 2,
    prefixGroup: 1,
  },
  {
    id: "GCP_API_KEY",
    severity: "critical",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    id: "MISTRAL_API_KEY",
    severity: "critical",
    pattern:
      /(\b(?:mistral[_-]?(?:api[_-]?)?key|mistralApiKey)\b\\?["']?\s*[:=]\s*\\?["']?)([A-Za-z0-9]{32})(?![A-Za-z0-9])/gi,
    valueGroup: 2,
    prefixGroup: 1,
    validate: (val) => isHighEntropySecretValue(val),
  },
  {
    id: "NPM_TOKEN",
    severity: "critical",
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
  },
  {
    id: "PYPI_TOKEN",
    severity: "critical",
    pattern: /\bpypi-AgE[A-Za-z0-9_-]{40,250}\b/g,
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
    id: "ANTHROPIC_API_KEY",
    severity: "critical",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,160}\b/g,
  },
  {
    id: "OPENROUTER_API_KEY",
    severity: "critical",
    pattern: /\bsk-or-v1-[0-9a-fA-F]{64}\b/g,
  },
  {
    id: "OPENAI_API_KEY",
    severity: "critical",
    pattern: /\bsk-(?!ant-|or-v1-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,160}\b/g,
  },
  {
    id: "GROQ_API_KEY",
    severity: "critical",
    pattern: /\bgsk_[A-Za-z0-9]{48,64}\b/g,
  },
  {
    id: "HUGGINGFACE_TOKEN",
    severity: "critical",
    pattern: /\bhf_[A-Za-z0-9]{30,64}\b/g,
  },
  {
    id: "PERPLEXITY_API_KEY",
    severity: "critical",
    pattern: /\bpplx-[A-Za-z0-9]{40,64}\b/g,
  },
  {
    id: "XAI_API_KEY",
    severity: "critical",
    pattern: /\bxai-[A-Za-z0-9]{40,128}\b/g,
  },
  {
    id: "PRIVATE_KEY_BLOCK",
    severity: "critical",
    pattern:
      /-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP|PKCS8)\s+)*PRIVATE KEY(?:\s+BLOCK)?-----(?:(?:[\r\n]+(?:Proc-Type:[^\r\n]*|DEK-Info:[^\r\n]*|Version:[^\r\n]*|[\t ]*[A-Za-z0-9+/=]{16,}[\t ]*))+(?:[\r\n]+-----END (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP|PKCS8)\s+)*PRIVATE KEY(?:\s+BLOCK)?-----)?|[\t ]+[A-Za-z0-9+/=]{24,})/g,
  },
  {
    id: "DATABASE_URI_CREDENTIALS",
    severity: "critical",
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver):\/\/[^:\s"'\\]*:[^@\s"'\\]+@[^\s"'\\<>)\]},;]+/gi,
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
  {
    id: "HIGH_ENTROPY_SECRET",
    severity: "high",
    entropy: true,
    pattern:
      /((?:(?<=^|[\s"'\\,;{}()[\]._-])(?:api[_-]?key|apikey|api[_-]?secret|client[_-]?secret|secret[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?token|signing[_-]?secret|signing[_-]?key|webhook[_-]?secret|encryption[_-]?key|master[_-]?key|password|passwd|pwd|db[_-]?pass(?:word)?|secret|token|credential)|(?<=^|[\s"'\\,;{}()[\]._-]|[a-z])(?:ApiKey|ApiSecret|ClientSecret|SecretKey|AccessKey|AccessToken|AuthToken|RefreshToken|PrivateToken|SigningSecret|SigningKey|WebhookSecret|EncryptionKey|MasterKey|DbPassword))\b\\?["']?\s*[:=]\s*\\?["']?)([^\s"'\\,;{}()[\]]{16,256})/gi,
    valueGroup: 2,
    prefixGroup: 1,
    validate: (val) => isHighEntropySecretValue(val),
  },
];

export const PII_RULES = [
  {
    id: "EMAIL_ADDRESS",
    severity: "medium",
    pii: true,
    pattern: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g,
  },
  {
    id: "CREDIT_CARD",
    severity: "high",
    pii: true,
    pattern:
      /(?<![A-Za-z0-9._/-])(?:(?:4\d{12}(?:\d{3}(?:\d{3})?)?|5[1-5]\d{14}|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12}|3[47]\d{13}|6(?:011\d{12}(?:\d{3})?|5\d{14}))|(?:4\d{3}|5[1-5]\d{2}|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720)|6(?:011|5\d{2}))([ -])\d{4}\1\d{4}\1\d{1,4}(?:\1\d{1,3})?|3[47]\d{2}([ -])(?:\d{6}\2\d{5}|\d{4}\2\d{4}\2\d{3}))(?![A-Za-z0-9._/-])/g,
    validate: isValidCreditCard,
  },
  {
    id: "US_SSN",
    severity: "high",
    pii: true,
    pattern:
      /(?<![A-Za-z0-9._/-])(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![A-Za-z0-9._/-])/g,
  },
  {
    id: "IBAN",
    severity: "high",
    pii: true,
    pattern:
      /(?<![A-Za-z0-9._/-])[A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?)(?![A-Za-z0-9._/-])/g,
    validate: isValidIban,
  },
  {
    id: "PHONE_NUMBER",
    severity: "medium",
    pii: true,
    pattern:
      /(?<![A-Za-z0-9._/+-])(?:\+[1-9]\d{0,2}[\s-]+(?:\(\d{1,4}\)|\d{1,4})(?:[\s-]+\d{2,8}){1,3}|\(\d{3}\)[\s.-]?\d{3}[\s.-]\d{4}|(?:1([\s-]))?\d{3}([\s.-])\d{3}\2\d{4})(?![A-Za-z0-9._/-])/g,
    validate: (match) => {
      const digits = match.replace(/\D/g, "");
      return digits.length >= 10 && digits.length <= 15;
    },
  },
];

const SECRET_RULES_NO_ENTROPY = SECRET_RULES.filter((r) => !r.entropy);
const ALL_RULES = [...SECRET_RULES, ...PII_RULES];
const ALL_RULES_NO_ENTROPY = [...SECRET_RULES_NO_ENTROPY, ...PII_RULES];

function normalizeCustomRules(customRules) {
  if (!Array.isArray(customRules) || customRules.length === 0) return [];
  const out = [];
  for (let i = 0; i < customRules.length; i++) {
    const r = customRules[i];
    if (!r || typeof r !== "object" || typeof r.id !== "string" || !r.id) continue;
    let compiled;
    if (r.pattern instanceof RegExp) {
      compiled = r.pattern.global
        ? r.pattern
        : new RegExp(r.pattern.source, `${r.pattern.flags}g`);
    } else if (typeof r.pattern === "string") {
      compiled = compileSafeRegex(r.pattern, r.flags ?? "", { requireGlobal: true });
    } else {
      continue;
    }
    out.push({
      id: r.id,
      severity: r.severity || "high",
      pattern: compiled,
      pii: false,
    });
  }
  return out;
}

function normalizeAllowPatterns(allowPatterns) {
  if (!Array.isArray(allowPatterns) || allowPatterns.length === 0) return null;
  const out = [];
  for (let i = 0; i < allowPatterns.length; i++) {
    const entry = allowPatterns[i];
    if (entry instanceof RegExp) {
      out.push(entry.global ? new RegExp(entry.source, entry.flags.replace(/g/g, "")) : entry);
    } else if (typeof entry === "string" && entry.length > 0) {
      out.push(compileSafeRegex(entry, "", { requireGlobal: false }));
    }
  }
  return out.length > 0 ? out : null;
}

function isAllowedValue(val, allowRegexes) {
  if (!allowRegexes) return false;
  for (let i = 0; i < allowRegexes.length; i++) {
    if (allowRegexes[i].test(val)) return true;
  }
  return false;
}

function normalizeOptions(options = {}) {
  const {
    redactPii = true,
    pseudonymizePii = false,
    pseudonymizer = null,
    allowEmailDomains = [],
    detectHighEntropy = true,
    skipEnvelope = true,
    skipPaths = null,
    disabledRules = null,
    customRules = null,
    allowPatterns = null,
  } = options;

  let allowedDomains = null;
  if (allowEmailDomains && allowEmailDomains.length > 0) {
    allowedDomains = new Set();
    for (const d of allowEmailDomains) {
      const cleaned = String(d).trim().toLowerCase().replace(/^@/, "");
      if (cleaned) allowedDomains.add(cleaned);
    }
    if (allowedDomains.size === 0) allowedDomains = null;
  }

  let skipPathSet = null;
  if (skipPaths) {
    skipPathSet = skipPaths instanceof Set ? skipPaths : new Set(skipPaths);
    if (skipPathSet.size === 0) skipPathSet = null;
  }

  let disabledSet = null;
  if (disabledRules) {
    disabledSet = disabledRules instanceof Set ? disabledRules : new Set(disabledRules);
    if (disabledSet.size === 0) disabledSet = null;
  }

  let baseRules;
  if (redactPii) {
    baseRules = detectHighEntropy ? ALL_RULES : ALL_RULES_NO_ENTROPY;
  } else {
    baseRules = detectHighEntropy ? SECRET_RULES : SECRET_RULES_NO_ENTROPY;
  }

  const compiledCustom = normalizeCustomRules(customRules);
  let rules = baseRules;
  if (disabledSet || compiledCustom.length > 0) {
    rules = disabledSet ? baseRules.filter((r) => !disabledSet.has(r.id)) : [...baseRules];
    for (let i = 0; i < compiledCustom.length; i++) {
      if (!disabledSet || !disabledSet.has(compiledCustom[i].id)) {
        rules.push(compiledCustom[i]);
      }
    }
  }

  const allowRegexes = normalizeAllowPatterns(allowPatterns);

  const activePseudonymizer =
    redactPii && pseudonymizer && typeof pseudonymizer.pseudonymize === "function"
      ? pseudonymizer
      : redactPii && pseudonymizePii
        ? createPiiPseudonymizer()
        : null;

  return {
    rules,
    allowedDomains,
    detectHighEntropy,
    skipEnvelope,
    skipPathSet,
    disabledSet,
    allowRegexes,
    pseudonymizer: activePseudonymizer,
  };
}

function redactStringInternal(text, normalized, contextKey = null) {
  if (typeof text !== "string" || text.length === 0) {
    return { text, findings: [] };
  }

  const { rules, allowedDomains, detectHighEntropy, disabledSet, allowRegexes, pseudonymizer } =
    normalized;
  const findings = [];
  let output = text;

  // Specific structured-field attribution before generic pattern matching (e.g. { gemini_api_key: "AIza..." })
  if (contextKey && !isAllowedValue(output, allowRegexes)) {
    if (
      (!disabledSet || !disabledSet.has("GEMINI_API_KEY")) &&
      GEMINI_KEY_NAME_RE.test(contextKey) &&
      /^AIza[0-9A-Za-z_-]{35}$/.test(output)
    ) {
      findings.push({
        ruleId: "GEMINI_API_KEY",
        severity: "critical",
        preview: makePreview(output),
        hash: hashSecret(output),
      });
      return { text: "[REDACTED:GEMINI_API_KEY]", findings };
    }
    if (
      (!disabledSet || !disabledSet.has("MISTRAL_API_KEY")) &&
      MISTRAL_KEY_NAME_RE.test(contextKey) &&
      /^[A-Za-z0-9]{32}$/.test(output) &&
      isHighEntropySecretValue(output)
    ) {
      findings.push({
        ruleId: "MISTRAL_API_KEY",
        severity: "critical",
        preview: makePreview(output),
        hash: hashSecret(output),
      });
      return { text: "[REDACTED:MISTRAL_API_KEY]", findings };
    }
  }

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i];
    const regex = rule.pattern;
    regex.lastIndex = 0;

    output = output.replace(regex, (match, ...args) => {
      const secretVal = rule.valueGroup ? args[rule.valueGroup - 1] : match;
      const prefix = rule.prefixGroup ? args[rule.prefixGroup - 1] : "";

      if (rule.id === "EMAIL_ADDRESS" && allowedDomains) {
        const domain = match.split("@")[1]?.toLowerCase();
        if (domain && allowedDomains.has(domain)) {
          return match;
        }
      }

      if (rule.validate && !rule.validate(secretVal)) {
        return match;
      }

      if (isAllowedValue(secretVal, allowRegexes)) {
        return match;
      }

      const replacement =
        rule.pii && pseudonymizer
          ? pseudonymizer.pseudonymize(rule.id, secretVal)
          : `[REDACTED:${rule.id}]`;

      const finding = {
        ruleId: rule.id,
        severity: rule.severity,
        preview: makePreview(secretVal),
        hash: hashSecret(secretVal),
      };
      if (rule.pii && pseudonymizer) {
        finding.token = replacement;
      }
      findings.push(finding);
      return `${prefix}${replacement}`;
    });
  }

  // Context-aware structured field checks (e.g. { "aws_secret_access_key": "<40-char>" })
  if (contextKey && !output.includes("[REDACTED:") && !isAllowedValue(output, allowRegexes)) {
    if (
      (!disabledSet || !disabledSet.has("AWS_SECRET_ACCESS_KEY")) &&
      AWS_SECRET_KEY_NAME_RE.test(contextKey) &&
      /^[A-Za-z0-9/+=]{40}$/.test(output) &&
      shannonEntropy(output) >= 3.3
    ) {
      findings.push({
        ruleId: "AWS_SECRET_ACCESS_KEY",
        severity: "critical",
        preview: makePreview(output),
        hash: hashSecret(output),
      });
      output = "[REDACTED:AWS_SECRET_ACCESS_KEY]";
    } else if (
      detectHighEntropy &&
      (!disabledSet || !disabledSet.has("HIGH_ENTROPY_SECRET")) &&
      isSensitiveKeyName(contextKey) &&
      isHighEntropySecretValue(output)
    ) {
      findings.push({
        ruleId: "HIGH_ENTROPY_SECRET",
        severity: "high",
        preview: makePreview(output),
        hash: hashSecret(output),
      });
      output = "[REDACTED:HIGH_ENTROPY_SECRET]";
    }
  }

  return { text: output, findings };
}

/**
 * Redacts secrets (and optionally PII) from a string, returning sanitized text and findings.
 */
export function redactText(text, options = {}) {
  if (typeof text !== "string" || text.length === 0) {
    return { text, findings: [] };
  }
  const normalized = normalizeOptions(options);
  return redactStringInternal(text, normalized);
}

/**
 * Recursively sanitizes any JSON-serializable payload (objects, arrays, strings),
 * including object keys, with circular-reference protection and JSON-RPC envelope awareness.
 */
export function redactPayload(value, options = {}) {
  const normalized = normalizeOptions(options);
  const findings = [];
  const ancestors = new WeakSet();
  const isJsonRpcEnvelope =
    normalized.skipEnvelope &&
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    value.jsonrpc === "2.0";

  function walk(node, path, depth, contextKey) {
    if (normalized.skipPathSet && path && normalized.skipPathSet.has(path)) {
      return node;
    }

    if (typeof node === "string") {
      const res = redactStringInternal(node, normalized, contextKey);
      for (let i = 0; i < res.findings.length; i++) {
        findings.push({ ...res.findings[i], path });
      }
      return res.text;
    }

    if (node === null || typeof node !== "object") {
      return node;
    }

    if (ancestors.has(node)) {
      return "[Circular]";
    }

    ancestors.add(node);
    try {
      if (Array.isArray(node)) {
        return node.map((item, idx) => walk(item, `${path}[${idx}]`, depth + 1, null));
      }

      const out = {};
      for (const [k, v] of Object.entries(node)) {
        // Preserve JSON-RPC 2.0 top-level envelope metadata (jsonrpc, id, method)
        if (depth === 0 && isJsonRpcEnvelope && JSON_RPC_ENVELOPE_KEYS.has(k)) {
          out[k] = v;
          continue;
        }

        // Preserve JSON Schema structural URI/ref metadata ($schema, $id, $ref)
        if (normalized.skipEnvelope && SCHEMA_METADATA_KEYS.has(k) && typeof v === "string") {
          out[k] = v;
          continue;
        }

        // Redact object keys safely (disambiguating collisions if two keys redact identically)
        const keyRes = redactStringInternal(k, normalized, null);
        let outKey = keyRes.text;
        if (keyRes.findings.length > 0) {
          if (Object.prototype.hasOwnProperty.call(out, outKey)) {
            let suffix = 2;
            while (Object.prototype.hasOwnProperty.call(out, `${outKey}#${suffix}`)) {
              suffix++;
            }
            outKey = `${outKey}#${suffix}`;
          }
          const keyPath = path ? `${path}.${outKey}` : outKey;
          for (let i = 0; i < keyRes.findings.length; i++) {
            findings.push({ ...keyRes.findings[i], path: keyPath, inKey: true });
          }
        }

        const childPath = path ? `${path}.${outKey}` : outKey;
        const sanitizedVal = walk(v, childPath, depth + 1, k);

        if (outKey === "__proto__") {
          Object.defineProperty(out, outKey, {
            value: sanitizedVal,
            enumerable: true,
            configurable: true,
            writable: true,
          });
        } else {
          out[outKey] = sanitizedVal;
        }
      }
      return out;
    } finally {
      ancestors.delete(node);
    }
  }

  const sanitized = walk(value, "", 0, null);
  return { sanitized, findings };
}
