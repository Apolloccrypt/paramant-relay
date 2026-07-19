'use strict';
// GET /v2/user/history — per-account read-view over the caller's own send/link
// activity. A billing feature (ParaSend Pro + ParaSign Pro): "send history + link
// management". NO new storage: it is a pure projection over the per-key Merkle
// audit chain that relay.js already keeps (auditChain, populated on inbound /
// outbound / abort). Returns id, status, time, recipient-hash and bytes only —
// never a payload, never a download token, never the raw key.
//
// Driven the same way as lib/parasign-open-api.js: relay.js injects the live
// state + a fake-free `res`; the handler makes the decision and writes it. This
// keeps the tier gate unit-testable without a socket (test/user-history.test.js).
const tierGate = require('./tier-gate');

// Audit events that represent a send / link lifecycle (what "history + link
// management" means to a user). Signing-audit lives in the separate ParaSign
// export; DID/attestation are infrastructure, not user-facing history.
const HISTORY_EVENTS = new Map([
  ['inbound',         'sent'],
  ['inbound_aborted', 'aborted'],
  ['outbound_view',   'downloaded'],
  ['outbound_burn',   'downloaded_burned'],
]);

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1000;

// deps:
//   res, J                 — HTTP response + JSON stringifier (relay.js conventions)
//   keyData                — the authenticated key record (plan info + active)
//   memberKeys             — array of the account's api-keys (per-account rollup)
//   auditFor(key) -> []    — returns that key's audit-chain entries (may be [])
//   query                  — parsed querystring ({ limit })
function handle({ res, J, keyData, memberKeys, auditFor, query }) {
  // Auth: a live, active key is required (relay.js only routes here post-auth,
  // but fail closed regardless).
  if (!keyData || keyData.active === false) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(J({ error: 'API key required' }));
  }
  // Tier gate: Pro+ on ParaSend or ParaSign. Free/community -> 403.
  if (!tierGate.isHistoryAllowed(keyData)) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    return res.end(J({
      error: 'tier_upgrade_required',
      feature: 'history',
      message: 'Send history and link management require a Pro plan or higher.',
    }));
  }

  const limit = Math.max(1, Math.min(parseInt((query && query.limit) || String(DEFAULT_LIMIT), 10) || DEFAULT_LIMIT, MAX_LIMIT));

  const rows = [];
  for (const key of (memberKeys || [])) {
    for (const e of (auditFor(key) || [])) {
      const status = HISTORY_EVENTS.get(e.event);
      if (!status) continue;
      rows.push({
        id: e.hash || '',                 // truncated content hash (no payload)
        status,
        time: e.ts,
        recipient_hash: e.device || '',   // recipient device id (already opaque)
        bytes: e.bytes || 0,
      });
    }
  }
  // Newest first, then cap.
  rows.sort((a, b) => (Date.parse(b.time) || 0) - (Date.parse(a.time) || 0));
  const entries = rows.slice(0, limit);

  res.writeHead(200, { 'Content-Type': 'application/json' });
  return res.end(J({ ok: true, count: entries.length, entries }));
}

module.exports = { handle, HISTORY_EVENTS };
