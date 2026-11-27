/**
 * Session-scoped deterministic PII pseudonymization (`[EMAIL_1]`, `[PHONE_1]`, `[CARD_1]`, `[SSN_1]`, `[IBAN_1]`)
 * with optional outbound PII re-hydration for read+write agent workflows.
 *
 * Security invariant: ONLY PII rules listed in `PII_PSEUDONYM_PREFIX` may be pseudonymized
 * or re-hydrated. Secrets (`SECRET_RULES`) are NEVER accepted or stored by this module
 * and always remain strictly one-way redacted (`[REDACTED:<RULE_ID>]`).
 */

export const PII_PSEUDONYM_PREFIX = Object.freeze({
  EMAIL_ADDRESS: "EMAIL",
  PHONE_NUMBER: "PHONE",
  CREDIT_CARD: "CARD",
  US_SSN: "SSN",
  IBAN: "IBAN",
});

const DEFAULT_MAX_ENTRIES = 10000;
const PII_TOKEN_RE = /\[(?:EMAIL|PHONE|CARD|SSN|IBAN)_[1-9]\d*\]/g;
const JSON_RPC_ENVELOPE_KEYS = new Set(["jsonrpc", "id", "method"]);

function canonicalizePii(ruleId, rawValue) {
  const str = String(rawValue);
  switch (ruleId) {
    case "EMAIL_ADDRESS":
      return str.trim().toLowerCase();
    case "PHONE_NUMBER":
    case "CREDIT_CARD":
    case "US_SSN":
      return str.replace(/\D/g, "");
    case "IBAN":
      return str.replace(/\s+/g, "").toUpperCase();
    default:
      return str.trim();
  }
}

/**
 * Creates a session-scoped deterministic PII pseudonymizer.
 * Identical PII values (after type-specific normalization) always map to the same token
 * within a session so LLMs can reason across distinct people/accounts without seeing raw PII.
 *
 * When outbound re-hydration is explicitly opted into, `rehydrateText` / `rehydratePayload`
 * restore known session PII tokens back to their original values for upstream tools while
 * keeping secrets strictly one-way redacted.
 *
 * `stats()` returns counts only and never exposes raw PII values.
 */
export function createPiiPseudonymizer(options = {}) {
  const maxEntries =
    Number.isInteger(options.maxEntries) && options.maxEntries > 0
      ? options.maxEntries
      : DEFAULT_MAX_ENTRIES;

  const mapsByType = new Map();
  const countersByType = new Map();
  const tokenToRaw = new Map();
  let totalUnique = 0;

  function rehydrateText(text) {
    if (typeof text !== "string" || text.length === 0 || tokenToRaw.size === 0) {
      return { text, rehydratedCount: 0, tokens: [] };
    }
    PII_TOKEN_RE.lastIndex = 0;
    let rehydratedCount = 0;
    const tokens = [];
    const output = text.replace(PII_TOKEN_RE, (token) => {
      const original = tokenToRaw.get(token);
      if (original === undefined) return token;
      rehydratedCount++;
      tokens.push(token);
      return original;
    });
    return { text: output, rehydratedCount, tokens };
  }

  function rehydratePayload(value, opts = {}) {
    const { skipEnvelope = true } = opts;
    if (tokenToRaw.size === 0) {
      return { payload: value, rehydratedCount: 0, tokens: [] };
    }

    let totalRehydrated = 0;
    const allTokens = [];
    const ancestors = new WeakSet();
    const isJsonRpcEnvelope =
      skipEnvelope &&
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      value.jsonrpc === "2.0";

    function walk(node, depth) {
      if (typeof node === "string") {
        const res = rehydrateText(node);
        totalRehydrated += res.rehydratedCount;
        for (let i = 0; i < res.tokens.length; i++) {
          allTokens.push(res.tokens[i]);
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
          return node.map((item) => walk(item, depth + 1));
        }
        const out = {};
        for (const [k, v] of Object.entries(node)) {
          if (depth === 0 && isJsonRpcEnvelope && JSON_RPC_ENVELOPE_KEYS.has(k)) {
            out[k] = v;
            continue;
          }
          out[k] = walk(v, depth + 1);
        }
        return out;
      } finally {
        ancestors.delete(node);
      }
    }

    const payload = walk(value, 0);
    return { payload, rehydratedCount: totalRehydrated, tokens: allTokens };
  }

  return {
    pseudonymize(ruleId, rawValue) {
      const prefix = Object.prototype.hasOwnProperty.call(PII_PSEUDONYM_PREFIX, ruleId)
        ? PII_PSEUDONYM_PREFIX[ruleId]
        : null;

      // Fail-safe: refuse to store or pseudonymize any non-PII rule (e.g. secrets)
      if (!prefix) {
        return `[REDACTED:${ruleId}]`;
      }

      let typeMap = mapsByType.get(prefix);
      if (!typeMap) {
        typeMap = new Map();
        mapsByType.set(prefix, typeMap);
      }

      const key = canonicalizePii(ruleId, rawValue);
      const existing = typeMap.get(key);
      if (existing !== undefined) {
        return existing;
      }

      if (totalUnique >= maxEntries) {
        return `[REDACTED:${ruleId}]`;
      }

      const nextNum = (countersByType.get(prefix) ?? 0) + 1;
      countersByType.set(prefix, nextNum);
      totalUnique++;

      const token = `[${prefix}_${nextNum}]`;
      typeMap.set(key, token);
      tokenToRaw.set(token, String(rawValue).trim());
      return token;
    },

    rehydrateText,
    rehydratePayload,

    stats() {
      const byType = {};
      for (const [prefix, count] of countersByType.entries()) {
        byType[prefix] = count;
      }
      return { totalUnique, byType };
    },

    reset() {
      mapsByType.clear();
      countersByType.clear();
      tokenToRaw.clear();
      totalUnique = 0;
    },
  };
}
