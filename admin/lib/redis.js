'use strict';
const { createClient } = require('redis');

let client = null;

async function initRedis() {
  if (!process.env.REDIS_URL) {
    console.error('[admin/redis] FATAL: REDIS_URL not set');
    process.exit(1);
  }
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

module.exports = { initRedis, redis };
