import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { filterFactsForPrincipal, guardMcpResponse } from "../src/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTOR_FILE = resolve(__dirname, "./fixtures/acl-vectors.json");

test("Shared JSON ACL test vectors match fail-closed expectations on every case", () => {
  const suite = JSON.parse(readFileSync(VECTOR_FILE, "utf8"));
  assert.ok(Array.isArray(suite.vectors) && suite.vectors.length >= 4);

  for (const vec of suite.vectors) {
    const { sanitized, report } = guardMcpResponse(vec.payload, {
      callerScopes: vec.callerScopes,
    });

    if (vec.expected.blocked) {
      assert.equal(sanitized, null, `${vec.id}: expected sanitized === null`);
      assert.equal(report.safe, false, `${vec.id}: expected safe === false`);
      assert.equal(report.acl.blocked, true, `${vec.id}: expected acl.blocked === true`);
      assert.equal(report.acl.reason, vec.expected.reason, `${vec.id}: reason mismatch`);
      continue;
    }

    assert.equal(report.acl.blocked, false, `${vec.id}: unexpected block`);
    assert.deepEqual(
      sanitized.facts.map((f) => f.id),
      vec.expected.allowedFactIds,
      `${vec.id}: allowedFactIds mismatch`
    );
    assert.deepEqual(
      report.acl.droppedFactIds,
      vec.expected.droppedFactIds,
      `${vec.id}: droppedFactIds mismatch`
    );
    assert.equal(
      report.acl.strippedCitations,
      vec.expected.strippedCitations,
      `${vec.id}: strippedCitations mismatch`
    );

    const direct = filterFactsForPrincipal(vec.payload.facts, vec.callerScopes);
    assert.deepEqual(
      direct.allowed.map((f) => f.id),
      vec.expected.allowedFactIds,
      `${vec.id}: direct filterFactsForPrincipal mismatch`
    );
    for (const fact of direct.allowed) {
      assert.deepEqual(
        fact.citations.map((c) => c.scopeId),
        vec.expected.remainingCitationsByFact[fact.id],
        `${vec.id}: citations mismatch for ${fact.id}`
      );
    }
  }
});
