'use strict';
// Review #555, LAAG: the confirm page at /v2/dl/:token carried the "Download
// & Burn" button as a plain href to /v2/dl/:token/get, without a claim. Since
// python-requests and Go-http-client may call /get (SDKs), a generic crawler
// or link checker that followed that href burned the file. The page now has
// no href that burns: the button is a script that claims and acks, and
// without script a POST form, which crawlers do not submit.
// Needs a redis. Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-dl-crawler.test.js
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { requireRedis, summary } = require('./_requires');

let checks = 0; let rc = null;
after(async () => { await killAll(); if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } summary('route-dl-crawler', checks); });
const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');

test('a crawler that follows every link on the confirm page burns nothing; the POST form still downloads', async (t) => {
  rc = await requireRedis('redis://127.0.0.1:6399');
  if (!rc) return t.skip('no redis');
  const srv = await boot({ tag: 'dlcrawl', usersFile: true, env: { REDIS_URL: rc.options.url },
    users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'crawl@example.test', account_id: 'acct_crawl_' + crypto.randomBytes(4).toString('hex') }] } });
  const payload = crypto.randomBytes(200);
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  const up = await srv.post('/v2/inbound', { headers: { 'X-Api-Key': KEY }, body: { hash, payload: payload.toString('base64') } });
  assert.strictEqual(up.status, 200, up.text);
  const tk = up.json.download_token;
  const page = await fetch(`${srv.base}/v2/dl/${tk}`, { headers: { 'User-Agent': 'ExampleLinkChecker/1.0' } });
  const html = await page.text();
  const hrefs = [...html.matchAll(/href="([^"]+)"/g)].map((m) => m[1]).filter((h) => h.startsWith('/'));
  assert.ok(!hrefs.some((h) => /\/get(\?|$)/.test(h.split('#')[0])), 'no link on the page burns: ' + hrefs.join(' '));
  for (const h of hrefs) await fetch(srv.base + h.split('#')[0], { headers: { 'User-Agent': 'ExampleLinkChecker/1.0' } });
  const info = await srv.get(`/v2/dl/${tk}/info`);
  assert.strictEqual(info.status, 200, 'the link is still alive: ' + info.text);
  assert.strictEqual(info.json.used, false);
  // The no-script fallback: the form posts to /get and gets the bytes.
  assert.match(html, new RegExp(`<form method="post" action="/v2/dl/${tk}/get">`));
  const got = await fetch(`${srv.base}/v2/dl/${tk}/get`, { method: 'POST' });
  assert.strictEqual(got.status, 200);
  assert.strictEqual(Buffer.from(await got.arrayBuffer()).length, payload.length);
  await srv.stop();
  checks++;
});
