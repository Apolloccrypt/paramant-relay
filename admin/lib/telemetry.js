'use strict';
const { redis } = require('./redis');

async function countActiveSessions() {
  let count = 0;
  for await (const _ of redis().scanIterator({ MATCH: 'paramant:user:session:*', COUNT: 200 })) count++;
  return count;
}

async function getRecentAuditEvents(limit = 20) {
  const events = [];
  for await (const key of redis().scanIterator({ MATCH: 'paramant:user:audit:*', COUNT: 100 })) {
    const userId = key.split(':').pop();
    const entries = await redis().zRange(key, 0, -1, { REV: true }).catch(() => []);
    for (const entry of entries.slice(0, limit)) {
      try { events.push({ user_id: userId, ...JSON.parse(entry) }); } catch {}
    }
  }
  events.sort((a, b) => (b.ts || 0) - (a.ts || 0));
  return events.slice(0, limit);
}

async function getUsersWithTotp(relayFetch, ADMIN_TOKEN) {
  const r = await relayFetch('health', '/v2/admin/keys', 'GET', null, false, ADMIN_TOKEN);
  const keys = r.body?.keys || [];
  const users = await Promise.all(keys.map(async k => {
    if (!k?.key) return null;
    const [totpActive, totpSecret] = await Promise.all([
      redis().get(`paramant:user:totp_active:${k.key}`).catch(() => null),
      redis().get(`paramant:user:totp:${k.key}`).catch(() => null),
    ]);
    let totp_status = 'none';
    if (totpActive === 'true') totp_status = 'active';
    else if (totpSecret) totp_status = 'pending';
    return {
      key: k.key, email: k.email || null, label: k.label || null,
      plan: k.plan || 'community', sectors: k.sectors || [],
      active: k.active !== false, revoked_at: k.revoked_at || null,
      created: k.created || null, totp_status,
    };
  }));
  return users.filter(Boolean);
}

async function getPlanDistribution(relayFetch, ADMIN_TOKEN) {
  const r = await relayFetch('health', '/v2/admin/keys', 'GET', null, false, ADMIN_TOKEN);
  const keys = (r.body?.keys || []).filter(k => k?.active !== false);
  const dist = { community: 0, pro: 0, enterprise: 0, trial: 0 };
  keys.forEach(k => { const p = k.plan || 'community'; dist[p] = (dist[p] || 0) + 1; });
  return dist;
}

async function countSignupsToday(relayFetch, ADMIN_TOKEN) {
  const today = new Date().toISOString().split('T')[0];
  const r = await relayFetch('health', '/v2/admin/keys', 'GET', null, false, ADMIN_TOKEN);
  return (r.body?.keys || []).filter(k => k?.active !== false && (k.created || '').startsWith(today)).length;
}

module.exports = { countActiveSessions, getRecentAuditEvents, getUsersWithTotp, getPlanDistribution, countSignupsToday };
