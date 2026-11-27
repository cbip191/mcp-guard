/**
 * Session-scoped deterministic PII pseudonymization (`[EMAIL_1]`, `[PHONE_1]`, `[CARD_1]`, `[SSN_1]`, `[IBAN_1]`).
 *
 * Security invariant: ONLY PII rules listed in `PII_PSEUDONYM_PREFIX` may be pseudonymized.
 * Secrets (`SECRET_RULES`) are NEVER accepted or stored by this module and always remain
 * strictly one-way redacted (`[REDACTED:<RULE_ID>]`).
 */

export const PII_PSEUDONYM_PREFIX = Object.freeze({
  EMAIL_ADDRESS: "EMAIL",
  PHONE_NUMBER: "PHONE",
  CREDIT_CARD: "CARD",
  US_SSN: "SSN",
  IBAN: "IBAN",
});

const DEFAULT_MAX_ENTRIES = 10000;

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
 * `stats()` returns counts only and never exposes raw PII values.
 */
export function createPiiPseudonymizer(options = {}) {
  const maxEntries =
    Number.isInteger(options.maxEntries) && options.maxEntries > 0
      ? options.maxEntries
      : DEFAULT_MAX_ENTRIES;

  const mapsByType = new Map();
  const countersByType = new Map();
  let totalUnique = 0;

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
      return token;
    },

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
      totalUnique = 0;
    },
  };
}
