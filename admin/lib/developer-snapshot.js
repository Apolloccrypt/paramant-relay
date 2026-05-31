'use strict';
// Builds the initial-render snapshot for the /developer operations dashboard.
// Dependencies (redis client, getAuditEvents, resolved plan) are injected so it
// unit-tests without booting the admin server.

const { DEVELOPER_TOOLS, toolsStatusFromAudit } = require('./developer-tools');

// Per-account monthly caps. Mirrors relay/lib/tiers.js — duplicated honestly
// here because the admin Docker image does not ship the relay package.
const TIER_CAPS = {
  community:  { transfers: 10,  signs: 2 },
  pro:        { transfers: 500, signs: 100 },
  enterprise: { transfers: Infinity, signs: Infinity },
};
function normalisePlan(p) {
  p = String(p || '').toLowerCase();
  if (p === 'free' || p === 'dev') return 'community';
  if (p === 'licensed') return 'enterprise';
  return (p === 'pro' || p === 'enterprise') ? p : 'community';
}
function ymKey(d) { return d.toISOString().slice(0, 7); }            // YYYY-MM
function maskKey(k) { k = String(k || ''); return k.length <= 12 ? k : k.slice(0, 8) + '…' + k.slice(-4); }
const capOut = (n) => (n === Infinity ? null : n);                   // null = unlimited (JSON-safe)

// deps: { redis: () => client, getAuditEvents, plan, now? }
async function buildSnapshot(deps, userSession) {
  const uid = userSession.user_id;        // == pgp_ key == account_id (1:1 today)
  const email = userSession.email;
  const r = deps.redis();
  const np = normalisePlan(deps.plan);
  const caps = TIER_CAPS[np];

  const ym = ymKey(deps.now || new Date());
  const num = async (k) => { try { return parseInt((await r.get(k)) || '0', 10) || 0; } catch { return 0; } };
  const transfers = await num(`paramant:quota:transfers:${uid}:${ym}`);
  const signs = await num(`paramant:quota:signs:${uid}:${ym}`);

  let audit = [];
  try { audit = await deps.getAuditEvents(uid, { limit: 50 }); } catch {}

  return {
    email,
    plan: np,
    key_masked: maskKey(uid),
    quota: {
      transfers, signs,
      caps: { transfers: capOut(caps.transfers), signs: capOut(caps.signs) },
    },
    audit,
    tools_status: toolsStatusFromAudit(DEVELOPER_TOOLS, audit),
  };
}

module.exports = { buildSnapshot, TIER_CAPS, normalisePlan, maskKey, ymKey };
