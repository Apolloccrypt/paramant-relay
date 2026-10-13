'use strict';
// "50 envelope creates per hour" is a sliding hour (matrix API-20-N). The
// limiter used a fixed clock-hour bucket (floor(now / 3600000)), so a key
// could create 50 at 10:59 and 50 more at 11:00: 100 in two minutes.
// Run: node --test relay/test/rate-limit-sliding.test.js
const { test } = require('node:test');
const assert = require('assert');
const rateLimit = require('../lib/rate-limit');
const { requireRedis } = require('./_requires');

const HOUR = 3_600_000;
// Two minutes before a clock hour.
const T0 = Math.floor(Date.now() / HOUR) * HOUR + HOUR - 120_000;

test('in memory: 50 just before the clock hour, and nothing more just after it', () => {
  assert.equal(typeof rateLimit.slidingWindowAllow, 'function', 'there is no sliding-window limiter');
  const m = new Map();
  for (let i = 0; i < 50; i++) assert.equal(rateLimit.slidingWindowAllow(m, 'k', 50, HOUR, T0 + i).ok, true);
  const after = rateLimit.slidingWindowAllow(m, 'k', 50, HOUR, T0 + 180_000); // one minute past the hour
  assert.equal(after.ok, false, 'the clock hour rolled over and handed out a fresh 50');
  assert.ok(after.retryAfterMs > HOUR - 200_000 && after.retryAfterMs <= HOUR - 180_000, `retry after ${after.retryAfterMs}`);
  // A refusal is not recorded, and once the oldest hits are an hour old there is room again.
  assert.equal(rateLimit.slidingWindowAllow(m, 'k', 50, HOUR, T0 + HOUR + 1).ok, true);
  // Another key has its own window.
  assert.equal(rateLimit.slidingWindowAllow(m, 'other', 50, HOUR, T0 + 180_000).ok, true);
});

test('in redis: the same window, shared, across the clock hour', async () => {
  assert.equal(typeof rateLimit.slidingWindowAllowRedis, 'function', 'there is no redis sliding-window limiter');
  const rc = await requireRedis(process.env.REDIS_URL || 'redis://127.0.0.1:6399');
  if (!rc) return;
  const key = `paramant:test:sw:${process.pid}:${Date.now()}`;
  try {
    for (let i = 0; i < 50; i++) assert.equal((await rateLimit.slidingWindowAllowRedis(rc, key, 50, HOUR, T0 + i, `m${i}`)).ok, true);
    const after = await rateLimit.slidingWindowAllowRedis(rc, key, 50, HOUR, T0 + 180_000, 'late');
    assert.equal(after.ok, false);
    assert.ok(after.retryAfterMs > 0 && after.retryAfterMs <= HOUR - 180_000);
    assert.equal(Number(await rc.zCard(key)), 50, 'a refusal is not recorded');
  } finally {
    await rc.del(key); try { await rc.disconnect(); } catch (_) {}
  }
});
