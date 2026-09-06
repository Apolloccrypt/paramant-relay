'use strict';
const { redis } = require('./redis');

const AUDIT_KEY = uid => `paramant:user:audit:${uid}`;
const MAX_ENTRIES = 1000;
// Retention window: audit entries carry PII (the account email). The rank-trim
// alone (1000/user) keeps low-activity accounts' entries forever, so also drop
// anything older than this window. Configurable; default 400 days (covers a
// full year plus a dispute tail).
const RETENTION_MS = parseInt(process.env.AUDIT_RETENTION_DAYS || '400', 10) * 86400 * 1000;

// Mask an operator IP before it is persisted in an audit entry: keep the network
// prefix, drop the host part. Full operator IPs are not needed for traceability.
function _maskIp(ip) {
  const s = String(ip || '');
  if (!s || s === 'unknown') return s;
  if (s.includes('.')) { const p = s.split('.'); return `${p[0]}.${p[1]}.x.x`; }
  if (s.includes(':')) return s.split(':').slice(0, 2).join(':') + '::x';
  return '***';
}

async function logAuditEvent(user_id, event_type, metadata = {}) {
  // The first argument IS the redis key (AUDIT_KEY above), and every reader in
  // this codebase asks for the account's full user_id. An empty or non-string
  // key therefore writes an entry nobody can ever fetch. That is a programming
  // error, not an outage, so it throws and is NOT swallowed below: the review of
  // 2026-09-05 found six call sites that had slid the event name or a truncated
  // id into this slot, and a silent fallback would have hidden all six.
  if (!user_id || typeof user_id !== 'string') {
    throw new TypeError(`logAuditEvent: user_id must be a non-empty string (event_type=${event_type})`);
  }
  const ts = Date.now();
  // Mask any operator IP in the metadata before it is written.
  const meta = { ...metadata };
  if (meta.admin_ip) meta.admin_ip = _maskIp(meta.admin_ip);
  if (meta.ip) meta.ip = _maskIp(meta.ip);
  const entry = JSON.stringify({ user_id, event_type, metadata: meta, ts });
  const userKey = AUDIT_KEY(user_id);
  // Everything past this point is the store, and the store failing is an
  // availability event. The trail is a witness, never a gate: a redis hiccup
  // here may not turn a successful login into a 500, and (before the callers
  // were awaited) an unhandled rejection here ended the admin process. So the
  // infrastructure half is caught, logged loudly enough to be found in the
  // journal, and swallowed.
  try {
    const r = redis();
    await Promise.all([
      r.zAdd(userKey, { score: ts, value: entry }),
      r.zAdd('paramant:audit:global', { score: ts, value: entry }),
    ]);
    // Bound retention by BOTH count (rank) and age (score).
    const cutoff = ts - RETENTION_MS;
    await Promise.all([
      r.zRemRangeByRank(userKey, 0, -1001),
      r.zRemRangeByRank('paramant:audit:global', 0, -10001),
      r.zRemRangeByScore(userKey, 0, cutoff),
      r.zRemRangeByScore('paramant:audit:global', 0, cutoff),
    ]);
  } catch (err) {
    // No user_id and no metadata in the line: the key carries the account id and
    // the metadata carries the email. The event name and the reason are enough
    // to tell an outage from a bug.
    console.error(`[admin/audit] write failed, event lost: event_type=${event_type} reason=${err && err.message}`);
  }
}

async function getAuditEvents(user_id, { limit = 50, event_types = null } = {}) {
  const entries = await redis().zRange(AUDIT_KEY(user_id), '+inf', '-inf', {
    BY: 'SCORE',
    REV: true,
    LIMIT: { offset: 0, count: event_types ? MAX_ENTRIES : limit },
  });
  let events = entries.map(e => JSON.parse(e));
  if (event_types) {
    events = events.filter(e => event_types.includes(e.event_type)).slice(0, limit);
  }
  return events;
}

module.exports = { logAuditEvent, getAuditEvents };
