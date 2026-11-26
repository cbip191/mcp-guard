/**
 * Fail-closed inherited ACL gate for multi-client B2B MCP servers.
 * Ensures a caller (or their coding agent) only receives facts backed by
 * sources they can already access in Jira, Slack, or Git.
 */

/**
 * @param {Array<{ id: string, citations?: Array<{ scopeId: string, itemRef?: string }> }>} facts
 * @param {Iterable<string>} callerScopes
 */
export function filterFactsForPrincipal(facts, callerScopes) {
  const allowedSet = new Set(callerScopes);
  const allowed = [];
  const dropped = [];
  let strippedCitations = 0;

  for (const fact of facts) {
    const citations = Array.isArray(fact.citations) ? fact.citations : [];
    const permittedCitations = citations.filter((c) => allowedSet.has(c.scopeId));
    strippedCitations += citations.length - permittedCitations.length;

    if (permittedCitations.length === 0) {
      dropped.push({
        factId: fact.id,
        reason: "no_permitted_citations",
      });
      continue;
    }

    allowed.push({
      ...fact,
      citations: permittedCitations,
    });
  }

  return {
    allowed,
    dropped,
    strippedCitations,
    enforcedScopeCount: allowedSet.size,
  };
}
