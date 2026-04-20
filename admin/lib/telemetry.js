'use strict';
const { redis } = require('./redis');

async function countActiveSessions() {
  let count = 0;
  for await (const _ of redis().scanIterator({ MATCH: 'paramant:user:session:*', COUNT: 200 })) count++;
  return count;
}

async function getRecentAuditEvents(limit = 20) {
  // O(log n): read from global ZSET if available, fall back to SCAN
  const globalRaw = await redis().zRange('paramant:audit:global', -Math.max(limit, 20), -1).catch(() => null);
  if (globalRaw && globalRaw.length > 0) {
    const events = globalRaw.map(r => { try { return JSON.parse(r); } catch { return null; } }).filter(Boolean);
    events.sort((a, b) => (b.ts || 0) - (a.ts || 0));
    return events.slice(0, limit);
  }
  // Fallback: SCAN (first run before any events written to global ZSET)
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
    const [totpActive, totpSecret, metaRaw] = await Promise.all([
      redis().get(`paramant:user:totp_active:${k.key}`).catch(() => null),
      redis().get(`paramant:user:totp:${k.key}`).catch(() => null),
      redis().get(`paramant:user:meta:${k.key}`).catch(() => null),
    ]);
    let meta = {};
    try { if (metaRaw) meta = JSON.parse(metaRaw); } catch {}
    let totp_status = 'none';
    if (totpActive === 'true') totp_status = 'active';
    else if (totpSecret) totp_status = 'pending';
    const createdRaw = meta.created_at || k.created || null;
    const created = createdRaw
      ? (typeof createdRaw === 'number' ? new Date(createdRaw).toISOString() : createdRaw)
      : null;
    return {
      key: k.key.slice(0, 8) + '...' + k.key.slice(-4), // masked
      key_id: k.key, // internal id for actions (not exposed in list response)
      email: meta.email || k.email || null, label: k.label || null,
      plan: k.plan || 'community', sectors: k.sectors || [],
      active: k.active !== false, revoked_at: k.revoked_at || null,
      created, totp_status,
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
