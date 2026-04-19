'use strict';
const { redis } = require('./redis');

const AUDIT_KEY = uid => `paramant:user:audit:${uid}`;
const MAX_ENTRIES = 1000;

async function logAuditEvent(user_id, event_type, metadata = {}) {
  const ts = Date.now();
  const entry = JSON.stringify({ event_type, metadata, ts });
  const key = AUDIT_KEY(user_id);
  const r = redis();
  await r.zAdd(key, { score: ts, value: entry });
  const count = await r.zCard(key);
  if (count > MAX_ENTRIES) {
    await r.zRemRangeByRank(key, 0, count - MAX_ENTRIES - 1);
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
