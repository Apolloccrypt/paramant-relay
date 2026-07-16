'use strict';
// `redis` is required lazily inside initRedis() so this module can be imported
// (e.g. for scanKeys in the unit tests) without the npm package installed —
// the admin test job runs `node --test` without `npm ci`.

let client = null;

async function initRedis() {
  if (!process.env.REDIS_URL) {
    console.error('[admin/redis] FATAL: REDIS_URL not set');
    process.exit(1);
  }
  const { createClient } = require('redis');
  client = createClient({
    url: process.env.REDIS_URL,
    socket: {
      reconnectStrategy: (retries) => {
        if (retries > 10) return new Error('redis unreachable');
        return Math.min(retries * 100, 3000);
      },
    },
  });
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
  if (!client || !client.isReady) throw new Error('Redis not ready');
  return client;
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

module.exports = { initRedis, redis, scanKeys };
