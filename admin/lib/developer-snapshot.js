'use strict';
// Builds the initial-render snapshot for the /developer operations dashboard
// and for GET /api/user/dashboard/overview.
//
// Dependencies (redis client, getAuditEvents, the account's entitlements) are
// injected so it unit-tests without booting the admin server.
//
// There is NO tier table in this file, and there must never be one again.
// It used to carry its own copy of relay/lib/tiers.js with three rows
// (community/pro/enterprise) and read them off the unified `plan` field. Both
// halves were wrong at once:
//   * the `business` row was missing, so a Business account fell through to the
//     community row and was shown 2 signatures a month where the relay grants
//     1000;
//   * the unified `plan` does not move when someone buys. The Mollie webhook
//     path calls entitlements.applyProductTier, which writes ONLY
//     plan_parasign / plan_parasend and by design never touches `plan`. So a
//     self-serve ParaSign Pro customer kept plan "community" and was told
//     "2 signatures left" on /dashboard while the relay was letting him sign
//     100. A number in the face of a paying customer that his own supplier
//     knows to be false.
// The relay owns the numbers (relay/lib/tiers.js -> relay/lib/entitlements.js)
// and enforces them. The admin only shows them, and it asks the relay for them
// per account: GET /v2/admin/entitlements/:account_id. Nothing here decides.

const { DEVELOPER_TOOLS, toolsStatusFromAudit } = require('./developer-tools');

function ymKey(d) { return d.toISOString().slice(0, 7); }            // YYYY-MM
function maskKey(k) { k = String(k || ''); return k.length <= 12 ? k : k.slice(0, 8) + '…' + k.slice(-4); }

// A cap as the API reports it. The relay's entitlement layer holds every
// metered monthly quota to a finite ceiling (ENTERPRISE_MONTHLY_CEILING), so a
// number is what normally arrives. Anything that is not a real number is
// reported as null ("not known"), never as a made-up figure.
function capOut(n) {
  return (typeof n === 'number' && Number.isFinite(n)) ? n : null;
}

// deps: { redis: () => client, getAuditEvents, entitlements, now? }
// `entitlements` is the relay's answer for THIS account:
//   { parasend: { tier, quotas: { transfers_month }, ... },
//     parasign: { tier, quotas: { signs_month }, ... } }
// It is required. Without it the caps are unknown, and a dashboard that guesses
// a cap is the bug this file exists to prevent, so we refuse instead.
async function buildSnapshot(deps, userSession) {
  const ent = deps.entitlements;
  if (!ent || !ent.parasend || !ent.parasign) {
    throw new Error('entitlements_required');
  }
  const uid = userSession.user_id;        // == pgp_ key == account_id (1:1 today)
  const email = userSession.email;
  const r = deps.redis();

  const ym = ymKey(deps.now || new Date());
  const num = async (k) => { try { return parseInt((await r.get(k)) || '0', 10) || 0; } catch { return 0; } };
  const transfers = await num(`paramant:quota:transfers:${uid}:${ym}`);
  const signs = await num(`paramant:quota:signs:${uid}:${ym}`);

  let audit = [];
  try { audit = await deps.getAuditEvents(uid, { limit: 50 }); } catch {}

  return {
    email,
    // Per product, because the two are bought and billed apart. There is no
    // single "plan" to print: an account can be ParaSign Pro and ParaSend
    // Community on the same day, and one word cannot say that.
    tiers: { parasend: ent.parasend.tier, parasign: ent.parasign.tier },
    key_masked: maskKey(uid),
    quota: {
      transfers, signs,
      caps: {
        // Transfers are a ParaSend capacity, signatures a ParaSign one. Each
        // reads its own product's quota, so neither can be decided by the other
        // product's tier or by the unified plan.
        transfers: capOut(ent.parasend.quotas.transfers_month),
        signs: capOut(ent.parasign.quotas.signs_month),
      },
    },
    audit,
    tools_status: toolsStatusFromAudit(DEVELOPER_TOOLS, audit),
  };
}

module.exports = { buildSnapshot, maskKey, ymKey };
