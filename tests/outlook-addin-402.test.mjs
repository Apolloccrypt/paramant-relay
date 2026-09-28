// The Outlook add-in and the browser extension, landed from feat/outlook-402.
// The extension's own vitest suite (extensions/chromium/test) runs in no CI
// job, so the two things that matter are pinned here too:
//   1. the add-in manifest keeps the schema shape Office validates
//   2. a 402 from the relay's monthly transfer gate reaches the user as an
//      upgrade notice, not as a bare "upload_failed"
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sealAndUploadChunk, quotaReachedMessage, UPGRADE_URL } from '../extensions/shared/paramant-core.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest = fs.readFileSync(path.join(ROOT, 'extensions/outlook-addin/manifest.xml'), 'utf8');
const relay = fs.readFileSync(path.join(ROOT, 'relay/relay.js'), 'utf8');

test('manifest: every bt:Image points with resid=, never resource=', () => {
  const images = [...manifest.matchAll(/<bt:Image\b[^>]*>/g)].map((m) => m[0]);
  const inIcons = images.filter((t) => /\bsize=/.test(t));
  assert.ok(inIcons.length >= 3, 'the button icon lost its images');
  for (const t of inIcons) {
    assert.doesNotMatch(t, /\bresource=/, `schema wants resid=: ${t}`);
    assert.match(t, /\bresid="Icon\.\d+"/, t);
  }
});

test('manifest: no Icon directly under a Group, read height within 450', () => {
  for (const g of manifest.matchAll(/<Group\b[^>]*>([\s\S]*?)<\/Group>/g)) {
    const beforeFirstControl = g[1].split(/<Control\b/)[0];
    assert.doesNotMatch(beforeFirstControl, /<Icon>/, 'Group allows Label, Control and Tooltip only');
  }
  for (const h of manifest.matchAll(/<RequestedHeight>(\d+)<\/RequestedHeight>/g)) {
    assert.ok(Number(h[1]) <= 450, `RequestedHeight ${h[1]} is above the 450 maximum`);
  }
});

test('the relay still sends the 402 body the extension reads', () => {
  assert.match(relay, /error: 'monthly_transfer_quota_reached', dimension: 'transfers_month', plan: [^,]+, limit: /);
});

async function uploadAgainst(status, body) {
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls++; return new Response(JSON.stringify(body), { status }); };
  try {
    await sealAndUploadChunk({ relay: 'https://r.invalid', apiKey: 'k', chunkU8: new Uint8Array(10), fileMeta: {}, relayMeta: {}, ttlMs: 1000 });
    return { calls, err: null };
  } catch (err) {
    return { calls, err };
  } finally {
    globalThis.fetch = realFetch;
  }
}

test('a quota 402 becomes a structured upgrade error and is not retried', async () => {
  const { calls, err } = await uploadAgainst(402, { error: 'monthly_transfer_quota_reached', dimension: 'transfers_month', plan: 'community', limit: 10 });
  assert.ok(err, 'a 402 must throw');
  assert.equal(calls, 1);
  assert.equal(err.code, 'quota_reached');
  assert.equal(err.plan, 'community');
  assert.equal(err.limit, 10);
  assert.equal(err.upgradeUrl, UPGRADE_URL);
  assert.equal(err.message, quotaReachedMessage('community', 10));
  assert.match(err.message, /10 monthly transfers on the community plan/);
});

test('any other 402 stays a plain failure, no false upgrade notice', async () => {
  const { err } = await uploadAgainst(402, { error: 'some_other_402' });
  assert.equal(err.code, 'upload_failed');
  assert.match(err.message, /some_other_402/);
});
