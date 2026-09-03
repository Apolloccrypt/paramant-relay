'use strict';
// `redis` is required lazily inside initRedis() so this module can be imported
// (e.g. for scanKeys in the unit tests) without the npm package installed —
// the admin test job runs `node --test` without `npm ci`.

const { guardRedisClient, redisClientBounds, RedisUnavailableError } = require('./redis-deadline');

let client = null;

async function initRedis() {
  if (!process.env.REDIS_URL) {
    console.error('[admin/redis] FATAL: REDIS_URL not set');
    process.exit(1);
  }
  const { createClient } = require('redis');
  // Two bounds, and both are needed. redisClientBounds sets disableOfflineQueue,
  // so a command issued while the socket is down is REFUSED instead of held on
  // an unbounded queue until the server comes back. guardRedisClient puts a
  // deadline on every command, which is the only thing that catches a black
  // hole: packets stop arriving, the socket stays open, isReady stays true and
  // the reply simply never comes. Measured on redis 6.2.1: without the guard
  // that command is still pending after five seconds and after any bound you
  // care to measure.
  //
  // The old reconnectStrategy gave up after ten retries, which turned a
  // recoverable outage into a dead admin until somebody restarted it. It can
  // keep retrying now, because retrying no longer parks a request.
  client = guardRedisClient(createClient({
    url: process.env.REDIS_URL,
    ...redisClientBounds(),
  }), { label: 'admin/redis' });
  client.on('error', (err) => console.error('[admin/redis] error:', err.message));
  client.on('ready',   () => console.log('[admin/redis] ready'));
  client.on('connect', () => console.log('[admin/redis] connecting'));
  client.on('end',     () => console.error('[admin/redis] disconnected'));
  await client.connect();
  const pong = await client.ping();
  if (pong !== 'PONG') { console.error('[admin/redis] ping failed:', pong); process.exit(1); }
  console.log('[admin/redis] connected to', process.env.REDIS_URL.replace(/:[^@]+@/, ':***@'));
}

function redis() {
  // RedisUnavailableError, not a bare Error: the express error handler answers
  // 503 for an outage and 500 for a bug, and "the store is not connected" is
  // the first kind. A plain Error here used to be reported as an internal
  // error, which reads as "we broke" rather than "come back in a moment".
  if (!client || !client.isReady) throw new RedisUnavailableError('client', 'not connected');
  return client;
}

// Is redis answering right now? Bounded by the same deadline as every other
// command, so a health check can never be the thing that hangs.
async function redisHealthy() {
  try {
    if (!client || !client.isReady) return { ok: false, detail: 'not connected' };
    const pong = await client.ping();
    return { ok: pong === 'PONG', detail: pong === 'PONG' ? 'reachable' : `unexpected ping reply: ${pong}` };
  } catch (e) {
    return { ok: false, detail: (e && e.message) || 'unreachable' };
  }
}

// node-redis v5+ laat scanIterator BATCHES (arrays) van keys yielden waar v4
// losse strings gaf. scanKeys vlakt beide vormen af naar één key per iteratie,
// zodat call-sites versie-agnostisch blijven.
async function* scanKeys(c, opts) {
  for await (const batch of c.scanIterator(opts)) {
    if (Array.isArray(batch)) { for (const key of batch) yield key; }
    else yield batch;
  }
}

module.exports = { initRedis, redis, redisHealthy, scanKeys };
