// Usage-purpose survey: one dashboard question ("What do you use Paramant
// for?") stored on the account key record. Pure unit, dependency-injected
// (no redis, no http) so it is testable exactly like the sibling parasign
// libs in tests/.
//
// Policy (documented choice): a SECOND answer OVERWRITES the first. The
// dashboard only shows the question while the field is empty, so an
// overwrite can only happen through a deliberate API call; last-answer-wins
// keeps the record correctable without an admin round-trip. "skipped" is a
// first-class value so a skip also persists and the question never returns.

const VALID_PURPOSES = new Set([
  'personal',              // personal use
  'organisation',          // for my organisation
  'client_management',     // manages Paramant for clients (IT provider / MSP)
  'research_journalism',   // research or journalism
  'skipped',               // explicitly skipped the question
]);

// deps: { apiKeys: Map, mutateUsersJson: fn(mutator) -> Promise, now?: fn }
// Returns { status, body } shaped for the relay HTTP layer.
function setUsagePurpose(deps, userId, purpose) {
  const { apiKeys, mutateUsersJson, now } = deps;
  if (!userId || typeof userId !== 'string') {
    return { status: 400, body: { error: 'missing_user_id' } };
  }
  if (typeof purpose !== 'string' || !VALID_PURPOSES.has(purpose)) {
    return { status: 400, body: { error: 'invalid_purpose' } };
  }
  const rec = apiKeys.get(userId);
  if (!rec || rec.active === false) {
    return { status: 404, body: { error: 'key_not_found' } };
  }
  const at = new Date(now ? now() : Date.now()).toISOString();
  rec.usage_purpose = purpose;
  rec.usage_purpose_at = at;
  const persisted = mutateUsersJson((ud) => {
    const entry = (ud.api_keys || []).find((k) => k.key === userId);
    if (entry) {
      entry.usage_purpose = purpose;
      entry.usage_purpose_at = at;
    }
    ud.updated = new Date().toISOString();
  });
  return {
    status: 200,
    body: { ok: true, usage_purpose: purpose, usage_purpose_at: at },
    persisted,
  };
}

module.exports = { VALID_PURPOSES, setUsagePurpose };
