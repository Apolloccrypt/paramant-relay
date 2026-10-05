// The browser extension and the Outlook add-in after fase 1 (P09, 2026-10-04).
//
// The extension's own vitest suite runs in no CI job, so what fase 1 found is
// pinned here, in the no-browser job:
//
//   EXT-13-A  every attachment sent through Gmail or Outlook web arrived as an
//             EMPTY file: the content script put an ArrayBuffer in
//             chrome.runtime.sendMessage, which serialises as JSON, and the
//             service worker sealed new Uint8Array({}) = 0 bytes. The test below
//             drives the real service worker through a JSON round trip, the
//             way Chrome does, and decrypts what reached the relay.
//   EXT-03-A  a TOTP sign-in said "Signed in" and every upload answered "Sign in
//             to Paramant": getUploadCredentials knew API keys only.
//   EXT-19-A  a 429 on /v2/check-key read as "Invalid API key"; and the taskpane
//             loaded taskpane.js twice.
//   EXT-20-A  the taskpane offered an e-mail + code sign-in that cannot work
//             from addin.paramant.app.
//   EXT-12-A  Outlook web in Dutch ("Bijvoegen") got no Paramant button.
//   EXT-08-A  the "plain" link format hid the URL behind the file name.
//   EXT-09-A  a self-hosted relay produced links paramant.app/get refuses.
//   EXT-18-A  the manifest asked Mailbox 1.1/1.3 for calls that need 1.8.
//
// Run: node --test tests/extension-fase2.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const core = await import('../extensions/shared/paramant-core.js');

// ── A fake chrome with the one property that matters: messages are JSON ──────────
const store = {};
let listener = null;
globalThis.chrome = {
  storage: { local: {
    get: async (keys) => {
      const ks = Array.isArray(keys) ? keys : [keys];
      return Object.fromEntries(ks.filter((k) => k in store).map((k) => [k, store[k]]));
    },
    set: async (o) => { Object.assign(store, o); },
    remove: async (keys) => { for (const k of [].concat(keys)) delete store[k]; },
  } },
  runtime: { onMessage: { addListener: (fn) => { listener = fn; } } },
  action: { openPopup: async () => {}, setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
  i18n: { getMessage: () => '' },
};

const uploads = [];
let tokenMints = 0;
globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  if (u.endsWith('/v2/inbound')) {
    const body = JSON.parse(init.body);
    uploads.push({ url: u, headers: init.headers, body });
    return new Response(JSON.stringify({ download_token: crypto.randomBytes(24).toString('hex'), ttl_ms: body.ttl_ms }), { status: 200 });
  }
  if (u === 'https://paramant.app/api/user/parasend/token') {
    tokenMints++;
    assert.equal(init.credentials, 'include', 'the token is asked on the signed-in session');
    return new Response(JSON.stringify({ token: 'pst_' + 'a'.repeat(40), expires_in_s: 900 }), { status: 200 });
  }
  throw new Error('unexpected fetch ' + u);
};

await import('../extensions/chromium/src/background/service-worker.js');
assert.ok(listener, 'the service worker registered no message listener');

// What Chrome does to a message: JSON, both ways.
function sendThroughChrome(msg) {
  const wire = JSON.parse(JSON.stringify(msg));
  return new Promise((resolve) => {
    const async = listener(wire, {}, (resp) => resolve(JSON.parse(JSON.stringify(resp ?? null))));
    assert.equal(async, true);
  });
}

async function openSeal(padded, keyB64url) {
  const raw = Buffer.from(keyB64url.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const nonce = padded.subarray(1, 13);
  const ctLen = padded.readUInt32BE(13);
  const ct = padded.subarray(17, 17 + ctLen);
  const d = crypto.createDecipheriv('aes-256-gcm', raw, nonce);
  d.setAuthTag(ct.subarray(ct.length - 16));
  const plain = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  const metaLen = plain.readUInt32BE(4);
  return { meta: JSON.parse(plain.subarray(8, 8 + metaLen).toString()), data: plain.subarray(8 + metaLen) };
}

test('EXT-13-A: a chunk crosses the JSON message boundary whole and is sealed with every byte', async () => {
  for (const k of Object.keys(store)) delete store[k];
  Object.assign(store, { auth_mode: 'apikey', auth_apikey: 'pgp_test', auth_relay: 'https://health.paramant.app', auth_until: Date.now() + 3600e3 });
  uploads.length = 0;
  const file = crypto.randomBytes(300_000);
  const begin = await sendThroughChrome({ type: 'TRANSFER_BEGIN', file: { name: 'rapport.pdf', size: file.length } });
  assert.equal(begin.ok, true, JSON.stringify(begin));
  // Exactly what compose-inject.js sends.
  const res = await sendThroughChrome({ type: 'TRANSFER_CHUNK', transferId: begin.transferId, index: 0, b64: core.encodeChunkMessage(file.buffer.slice(file.byteOffset, file.byteOffset + file.length)) });
  assert.equal(res.ok, true, JSON.stringify(res));
  const fin = await sendThroughChrome({ type: 'TRANSFER_FINISH', transferId: begin.transferId });
  assert.equal(fin.ok, true);
  assert.equal(uploads.length, 1);
  const key = fin.shareUrl.split('#k=')[1];
  const { meta, data } = await openSeal(Buffer.from(uploads[0].body.payload, 'base64'), key);
  assert.equal(data.length, file.length, 'the sealed chunk is not the file (0 bytes is the fase 1 bug)');
  assert.ok(data.equals(file));
  assert.equal(meta.file_size, file.length);
  assert.equal(meta.chunk_size, file.length);
});

test('EXT-13-A: the old ArrayBuffer message is refused, never sealed as an empty file', async () => {
  uploads.length = 0;
  const file = crypto.randomBytes(4096);
  const begin = await sendThroughChrome({ type: 'TRANSFER_BEGIN', file: { name: 'x.bin', size: file.length } });
  const res = await sendThroughChrome({ type: 'TRANSFER_CHUNK', transferId: begin.transferId, index: 0, bytes: file.buffer });
  assert.equal(res.ok, false, 'a chunk that arrived as {} was accepted');
  assert.equal(uploads.length, 0, 'something was uploaded for an unreadable chunk');
});

test('EXT-13-A: a chunk of the wrong length is refused', () => {
  assert.throws(() => core.decodeChunkMessage(core.encodeChunkMessage(new Uint8Array(10)), 11, 0), /could not be read whole/);
  assert.throws(() => core.decodeChunkMessage({}, 0, 0), /could not be read/);
  // Second chunk of a file of CHUNK_PLAIN + 5 bytes holds exactly 5.
  assert.equal(core.decodeChunkMessage(core.encodeChunkMessage(new Uint8Array(5)), core.CHUNK_PLAIN + 5, 1).length, 5);
  assert.equal(core.expectedChunkLength(0, 0), 0);
});

test('EXT-13-A: compose-inject sends base64, not an ArrayBuffer', () => {
  const src = read('extensions/chromium/src/content/compose-inject.js');
  assert.match(src, /encodeChunkMessage\(/);
  assert.doesNotMatch(src, /type: 'TRANSFER_CHUNK'[^}]*\bbytes\b/, 'the chunk travels as an ArrayBuffer again');
});

test('EXT-03-A: after an e-mail + code sign-in an upload goes out with a session token, not "Sign in to Paramant"', async () => {
  for (const k of Object.keys(store)) delete store[k];
  Object.assign(store, { auth_mode: 'totp', auth_email: 'a@b.nl', auth_until: Date.now() + 3600e3 });
  uploads.length = 0;
  tokenMints = 0;
  const file = crypto.randomBytes(2000);
  const begin = await sendThroughChrome({ type: 'TRANSFER_BEGIN', file: { name: 'x.bin', size: file.length } });
  assert.equal(begin.ok, true, 'a TOTP session got: ' + JSON.stringify(begin));
  const res = await sendThroughChrome({ type: 'TRANSFER_CHUNK', transferId: begin.transferId, index: 0, b64: core.encodeChunkMessage(file) });
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.equal(uploads.length, 1);
  assert.equal(uploads[0].url, 'https://health.paramant.app/v2/inbound');
  assert.match(uploads[0].headers.Authorization || '', /^Bearer pst_/);
  assert.equal(uploads[0].headers['X-Api-Key'], undefined, 'a TOTP session must not invent an API key');
  assert.equal(tokenMints, 1, 'one token per transfer, reused across its chunks');
});

test('EXT-09-A: a self-hosted relay uploads, and its link opens on that relay, not on paramant.app', async () => {
  for (const k of Object.keys(store)) delete store[k];
  Object.assign(store, { auth_mode: 'apikey', auth_apikey: 'pgp_test', auth_relay: 'https://relay.mijnbedrijf.nl', auth_until: Date.now() + 3600e3 });
  uploads.length = 0;
  const file = crypto.randomBytes(500);
  const begin = await sendThroughChrome({ type: 'TRANSFER_BEGIN', file: { name: 'x.bin', size: file.length } });
  assert.equal(begin.ok, true, 'a self-hosted relay got: ' + JSON.stringify(begin));
  const res = await sendThroughChrome({ type: 'TRANSFER_CHUNK', transferId: begin.transferId, index: 0, b64: core.encodeChunkMessage(file) });
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.equal(uploads[0].url, 'https://relay.mijnbedrijf.nl/v2/inbound');
  const fin = await sendThroughChrome({ type: 'TRANSFER_FINISH', transferId: begin.transferId });
  assert.equal(fin.ok, true, JSON.stringify(fin));
  const url = new URL(fin.shareUrl);
  assert.equal(url.origin + url.pathname, 'https://relay.mijnbedrijf.nl/get', 'the receiver must open the link on the relay itself');
  assert.equal(url.searchParams.get('r'), 'https://relay.mijnbedrijf.nl');
  // A Paramant relay still opens on paramant.app/get.
  assert.equal(core.receiveBaseFor('https://legal.paramant.app/'), 'https://paramant.app/get');
  assert.equal(core.isReceivableRelay('https://relay.mijnbedrijf.nl'), true);
  // Only an https origin: no http, no path, no query, no user info.
  for (const bad of ['http://relay.mijnbedrijf.nl', 'https://relay.mijnbedrijf.nl/x', 'https://a@relay.mijnbedrijf.nl', 'https://relay.mijnbedrijf.nl/?a=1', 'javascript:alert(1)', 'relay.mijnbedrijf.nl']) {
    assert.equal(core.isReceivableRelay(bad), false, bad);
  }
});

test('EXT-09-A: the link block keeps a self-hosted /get link and still blocks anything else', async () => {
  const { buildLinkHtml } = await import('../extensions/shared/link-block.js');
  const at = new Date().toISOString();
  const own = 'https://relay.mijnbedrijf.nl/get?t=abc&c=1&r=https%3A%2F%2Frelay.mijnbedrijf.nl#k=K';
  assert.ok(buildLinkHtml({ url: own, filename: 'a.pdf', expiresAt: at, format: 'block' }).includes('href="https://relay.mijnbedrijf.nl/get?t=abc&amp;c=1'));
  for (const bad of ['javascript:alert(1)', 'http://relay.mijnbedrijf.nl/get?t=a', 'https://relay.mijnbedrijf.nl/elders', 'https://a:b@relay.mijnbedrijf.nl/get?t=a']) {
    assert.match(buildLinkHtml({ url: bad, filename: 'a.pdf', expiresAt: at, format: 'block' }), /href="#"/, bad);
  }
});

test('EXT-09-A: /get opens a FileLink from its own origin and from Paramant relays, nothing else', () => {
  const src = read('frontend/js/get.page.js');
  const m = src.match(/function parseLink\(\) \{[\s\S]*?\n\}/);
  assert.ok(m, 'parseLink not found');
  const set = src.match(/const FILELINK_RELAYS = new Set\(\[[\s\S]*?\]\);/)[0];
  const run = (href) => {
    const u = new URL(href);
    const fn = new Function('location', 'TOKEN_RE', 'fromB64url', 'RELAY_SECTORS', 'DEFAULT_RELAY',
      set + '\n' + m[0] + '\nreturn parseLink();');
    return fn({ search: u.search, hash: u.hash, origin: u.origin }, /^[0-9a-f]{48}$/,
      (x) => Buffer.from(x.replace(/-/g, '+').replace(/_/g, '/'), 'base64'), {}, 'https://health.paramant.app');
  };
  const tok = 'a'.repeat(48), key = Buffer.alloc(32, 1).toString('base64url');
  const q = (origin, r) => `${origin}/get?t=${tok}&c=1&r=${encodeURIComponent(r)}#k=${key}`;
  assert.equal(run(q('https://relay.mijnbedrijf.nl', 'https://relay.mijnbedrijf.nl')).kind, 'filelink', 'own origin');
  assert.equal(run(q('https://paramant.app', 'https://legal.paramant.app')).kind, 'filelink', 'Paramant relay');
  assert.equal(run(q('https://paramant.app', 'https://relay.mijnbedrijf.nl')).kind, 'invalid', 'paramant.app must not fetch from a foreign host');
  assert.equal(run(q('https://relay.mijnbedrijf.nl', 'https://evil.example')).kind, 'invalid', 'a self-host must not fetch from a third host');
});

test('EXT-19-A / SEND-03-A: a 429 on check-key is "too many attempts", never "invalid key"', async () => {
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ error: 'rate_limited' }), { status: 429 });
  try {
    const ck = await core.checkKey('https://health.paramant.app', 'pgp_x');
    assert.equal(ck.rateLimited, true);
    await assert.rejects(core.discoverRelay('pgp_x'), (e) => e.code === 'rate_limited');
  } finally { globalThis.fetch = real; }
});

test('EXT-19-A: taskpane.js and commands.js are loaded once (webpack injects the tag)', () => {
  for (const f of ['extensions/outlook-addin/src/taskpane/taskpane.html', 'extensions/outlook-addin/src/commands/commands.html']) {
    assert.doesNotMatch(read(f), /<script[^>]+src="(taskpane|commands)\.js"/, f + ' carries its own script tag next to the injected one');
  }
});

test('EXT-20-A: the taskpane signs in with e-mail + code and uploads with a session token', async () => {
  const html = read('extensions/outlook-addin/src/taskpane/taskpane.html');
  assert.match(html, /id="form-totp"/);
  assert.match(html, /id="show-totp"/);
  // Drive the add-in's own module against a fake paramant.app.
  const ls = {};
  globalThis.localStorage = { getItem: (k) => (k in ls ? ls[k] : null), setItem: (k, v) => { ls[k] = String(v); }, removeItem: (k) => { delete ls[k]; } };
  globalThis.Office = { context: { mailbox: { item: { getAttachmentContentAsync: (id, cb) =>
    cb({ status: 'succeeded', value: { format: 'base64', content: Buffer.from('hallo outlook').toString('base64') } }) } } },
    AsyncResultStatus: { Succeeded: 'succeeded' }, MailboxEnums: { AttachmentContentFormat: { Base64: 'base64' } } };
  const seen = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    seen.push({ u, init });
    if (u === 'https://paramant.app/api/user/login') {
      assert.equal(init.credentials, 'include');
      return new Response(JSON.stringify({ ok: true, email: 'demo@example.com', session_expires_at: new Date(Date.now() + 3600e3).toISOString() }), { status: 200 });
    }
    if (u === 'https://paramant.app/api/user/session/verify') return new Response(JSON.stringify({ email: 'demo@example.com' }), { status: 200 });
    if (u === 'https://paramant.app/api/user/parasend/token') {
      assert.equal(init.credentials, 'include');
      return new Response(JSON.stringify({ token: 'pst_' + 'b'.repeat(40), expires_in_s: 900, sector: 'legal' }), { status: 200 });
    }
    if (u.endsWith('/v2/inbound')) return new Response(JSON.stringify({ download_token: crypto.randomBytes(24).toString('hex'), ttl_ms: 3600e3 }), { status: 200 });
    throw new Error('unexpected fetch ' + u);
  };
  try {
    const api = await import('../extensions/outlook-addin/src/shared/paramant-api.js');
    const login = await api.loginWithTotp('demo@example.com', '123456');
    assert.equal(login.success, true, JSON.stringify(login));
    assert.equal((await api.verifySession()).authenticated, true);
    const up = await api.uploadAttachment({ id: 'att1', name: 'a.txt' }, { ttlMs: 3600e3 });
    assert.equal(up.success, true, JSON.stringify(up));
    const inbound = seen.find((x) => x.u.endsWith('/v2/inbound'));
    assert.equal(inbound.u, 'https://legal.paramant.app/v2/inbound', 'the token works on the sector the admin named');
    assert.match(inbound.init.headers.Authorization || '', /^Bearer pst_/);
    assert.equal(inbound.init.headers['X-Api-Key'], undefined);
    assert.match(up.shareUrl, /^https:\/\/paramant\.app\/get\?/);
  } finally {
    globalThis.fetch = real;
  }
});

test('EXT-20-A: the account server answers the taskpane origin on exactly its routes', () => {
  const srv = read('admin/server.js');
  const m = srv.match(/const ADDIN_CORS_PATHS = new Set\(\[([^\]]+)\]\)/);
  assert.ok(m);
  for (const r of ['/user/login', '/user/session/verify', '/user/parasend/token', '/user/logout']) assert.ok(m[1].includes(`'${r}'`), r);
  assert.match(srv, /new Set\(\['https:\/\/addin\.paramant\.app'/);
});

test('EXT-18-A: the manifest asks Mailbox 1.8, which getAttachmentsAsync needs', () => {
  const m = read('extensions/outlook-addin/manifest.xml');
  assert.match(m, /<Set Name="Mailbox" MinVersion="1\.8"\/>/);
  assert.match(m, /DefaultMinVersion="1\.8"/);
  assert.match(read('extensions/outlook-addin/src/shared/office-helpers.js'), /getAttachmentsAsync/);
});

test('EXT-12-A: the Outlook web button also appears in Dutch', () => {
  const src = read('extensions/chromium/src/content/outlook.js');
  const m = src.match(/attachMatch: \(label\) =>\s*([\s\S]*?),\n\s*attachAttempts/);
  assert.ok(m, 'outlook.js has no locale-independent fallback');
  const fn = new Function('label', 'return ' + m[1]);
  assert.equal(fn('Bijvoegen'), true);
  assert.equal(fn('Attach file'), true);
  assert.equal(fn('Invoegen'), false);
});

test('EXT-08-A: the plain format shows the URL itself', async () => {
  const { buildLinkHtml } = await import('../extensions/shared/link-block.js');
  const url = 'https://paramant.app/get?t=abc&c=1&r=x#k=K';
  const html = buildLinkHtml({ url, filename: 'a.pdf', expiresAt: new Date().toISOString(), format: 'plain' });
  const text = html.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&');
  assert.ok(text.includes(url), 'without HTML the URL is gone: ' + text);
});

// EXT-01-A / EXT-18-A / EXT-26-A: the help pages promised a Chrome Web Store and
// an AppSource listing that do not exist, a "Save" button, a green light with an
// e-mail address, a 64-character key, paramant.app/get/XXXXX links, a "Choose
// file" taskpane, and Exchange 2019. They now describe what ships.
const popupHtml = read('extensions/chromium/src/popup/popup.html');
const taskpaneHtml = read('extensions/outlook-addin/src/taskpane/taskpane.html');
for (const slug of ['help/gmail-extension', 'en/help/gmail-extension', 'help/outlook-extension', 'en/help/outlook-extension']) {
  test(`EXT-26-A: ${slug} describes the product that ships`, () => {
    const html = read('frontend/' + slug + '.html');
    const text = html.replace(/<[^>]+>/g, ' ');
    assert.doesNotMatch(text, /Zoek op\s+Paramant|Search for\s+Paramant and click|Toevoegen aan Chrome|Add to Chrome/, 'promises a store listing');
    assert.doesNotMatch(text, /paramant\.app\/get\/XXXXX|Choose file|Upload and insert link|api\.paramant\.app|groen lampje|green indicator/);
    assert.doesNotMatch(html, /<strong>Save<\/strong>/, 'the button is "Sign in", not "Save"');
    if (slug.includes('gmail')) {
      assert.match(text, /Web Store/);
      assert.match(text, /(uitgepakte extensie|unpacked)/i);
      assert.match(popupHtml, />Sign in</);
    } else {
      assert.match(text, /AppSource/);
      assert.match(text, /manifest\.xml/);
      assert.match(text, /Mailbox 1\.8/);
      assert.doesNotMatch(text, /Exchange (Server )?2019[^,]*: (on-premises|on-premises,)/);
      assert.match(taskpaneHtml, /Encrypt all attachments/);
      assert.match(text, /Encrypt all attachments/);
    }
  });
}
