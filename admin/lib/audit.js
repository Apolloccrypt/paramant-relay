'use strict';
const { redis } = require('./redis');

const AUDIT_KEY = uid => `paramant:user:audit:${uid}`;
const MAX_ENTRIES = 1000;

async function logAuditEvent(user_id, event_type, metadata = {}) {
  const ts = Date.now();
  const entry = JSON.stringify({ user_id, event_type, metadata, ts });
  const userKey = AUDIT_KEY(user_id);
  const r = redis();
  await Promise.all([
    r.zAdd(userKey, { score: ts, value: entry }),
    r.zAdd('paramant:audit:global', { score: ts, value: entry }),
  ]);
  // Trim per-user to 1000, global to 10000
  await Promise.all([
    r.zRemRangeByRank(userKey, 0, -1001),
    r.zRemRangeByRank('paramant:audit:global', 0, -10001),
  ]);
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
