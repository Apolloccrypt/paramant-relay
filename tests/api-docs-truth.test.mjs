// What docs/api.md, /docs and the open-API spec say, held against the relay
// code and the scripts in this repository. P10 rest-round of the fase-1 matrix
// (API-01-N, API-09-N, API-13-F, API-14-N, API-15-K, API-20-N, API-21-N,
// API-24-K, API-29-C, API-29-N, API-30-C, API-30-K, API-30-N, API-31-N,
// API-35-A, API-36-A). Every block names the cell it answers. The relay side
// of the same promises is measured live in relay/test/route-api-docs-truth.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const API = read('docs/api.md');
const SPEC = read('docs/parasign-open-api-spec.md');
const NL = read('frontend/docs.html');
const EN = read('frontend/en/docs.html');
const RELAY = read('relay/relay.js');
const section = (html, id) => {
  const a = html.indexOf(`id="${id}"`);
  assert.ok(a > 0, `section ${id}`);
  const b = html.indexOf('<h2 id="', a + 10);
  return html.slice(a, b > a ? b : undefined);
};

test('API-01-N: the served copy /docs/api.md is docs/api.md, byte for byte', () => {
  assert.equal(read('frontend/docs/api.md'), API, 'frontend/docs/api.md drifted from docs/api.md; copy it over');
});

test('API-29-C: the verify-receipt curl example sends the API key the relay demands', () => {
  const at = API.indexOf('curl -X POST https://relay.paramant.app/v2/verify-receipt');
  assert.ok(at > 0);
  assert.match(API.slice(at, at + 300), /-H "X-Api-Key: pgp_/);
});

test('API-29-N: the receipt and verify-receipt fields are the ones the relay writes', () => {
  // The signed receipt payload in relay.js, and the verify answer.
  assert.match(RELAY, /retrieved_at:\s+Date\.now\(\),/);
  assert.match(RELAY, /tree_size_at_retrieval: Number\.isFinite\(receiptObj\.tree_size_at_retrieval\)/);
  assert.match(API, /"retrieved_at":\s+1744707600000,/, 'inside the receipt retrieved_at is a millisecond number');
  assert.match(API, /`retrieved_at` is a Unix timestamp in milliseconds/);
  const v = API.slice(API.indexOf('### POST /v2/verify-receipt'), API.indexOf('### GET /v2/stream-next'));
  for (const f of ['valid', 'blob_hash', 'retrieved_at', 'sector', 'relay_id', 'burn_confirmed', 'tree_size', 'leaf_index', 'tree_size_at_retrieval']) {
    assert.match(v, new RegExp(`"${f}":`), `verify-receipt success lists ${f}`);
  }
});

test('API-30-C / API-30-N: /v2/dl answers as documented (403 for preview bots, a reason on /info)', () => {
  assert.match(RELAY, /if \(PREVIEW_BOTS\.test\(ua\)\) \{\s*res\.writeHead\(403\); return res\.end\(J\(\{ error: 'Automated clients not permitted' \}\)\);/);
  assert.doesNotMatch(API, /Answers `410` to a known preload/);
  assert.match(API, /Answers `403` \(`Automated clients not permitted`\) to a known link-preview user-agent/);
  assert.match(RELAY, /return res\.end\(J\(\{ ok: false, error: 'Link not found, used, or expired', reason \}\)\);/);
  assert.doesNotMatch(API, /cannot tell "downloaded" apart from "expired"/);
  assert.match(API, /where `reason` is `downloaded`, `expired`, `withdrawn`, `exhausted`, `lost` or `unknown`/);
});

test('API-24-K / API-30-K / API-35-K: nothing burns before the whole body is delivered, and the docs say so', () => {
  assert.match(RELAY, /function afterDelivery\(req, res, \{ onFinish, onDelivered, onAborted, onCleanCloseEarly \}\)/);
  assert.match(RELAY, /'X-Burned': 'on-delivery'/);
  assert.doesNotMatch(RELAY, /'X-Burned': 'true'/, 'no response says burned before a byte has left');
  assert.match(API, /Without a claim \(old SDKs and scripts\) nothing burns until the whole body is\s+delivered, meaning the relay has written the last byte/);
  assert.doesNotMatch(API, /A connection that breaks after that point costs the file\./);
  assert.match(API, /If your client breaks off before the last byte\s+\(it closes or resets the connection\), the relay puts the blob back/);
  // Review #565 B1/H1: a reset after the last byte counts, the hold is once per blob.
  assert.match(API, /A reset after\s+the last byte counts as a delivery\./);
  assert.match(API, /for one retry by the\s+same API key only, once per blob/);
  assert.match(RELAY, /if \(!burned \|\| !apiKey \|\| entry\.retryHeld\) return delivered\(\);/);
  assert.match(section(NL, 'outbound'), /Een lezing telt pas als de hele blob is afgeleverd/);
  assert.match(section(EN, 'outbound'), /A read only counts once the whole blob was delivered/);
});

test('API-31-N: the CT examples show the fields the relay sends', () => {
  const sth = API.slice(API.indexOf('### GET /v2/sth: '), API.indexOf('### GET /v2/sth/history'));
  assert.doesNotMatch(sth, /"pk_hash":/, '/v2/sth carries no pk_hash');
  const log = API.slice(API.indexOf('### GET /v2/ct/log'), API.indexOf('### GET /v2/ct/proof'));
  assert.match(log, /"size":43/);
  assert.doesNotMatch(log, /"tree_size":43/);
  const proof = API.slice(API.indexOf('### GET /v2/ct/proof'), API.indexOf('### GET /v2/sth/consistency'));
  assert.match(proof, /"index":7,"leaf_hash":"d4e1…","tree_hash":"c7a9…","proof":\[…\],"ts":/);
});

test('API-13-F / API-21-N: two error shapes, and 402 in the table and on /docs', () => {
  const e = API.slice(API.indexOf('## Error codes'), API.indexOf('## Python SDK'));
  assert.match(e, /`\/v1` \(the ParaSign API\) answers `\{ "error": "<code>", "message": "<sentence>" \}`/);
  assert.match(e, /`\/v2` answers `\{ "error": "<sentence>" \}` on most routes/);
  assert.match(e, /\| 402 \| Plan limit reached: `monthly_sign_quota_reached`/);
  assert.match(section(NL, 'v1-envelopes'), /<code>402 monthly_sign_quota_reached<\/code>/);
  assert.match(section(EN, 'v1-envelopes'), /<code>402 monthly_sign_quota_reached<\/code>/);
  assert.match(SPEC, /`402 monthly_sign_quota_reached` carries `plan`, `limit`, `used` and\s+`reset_date`/);
});

test('API-20-N: 50 creates in any hour, a sliding window, and the docs say so', () => {
  assert.doesNotMatch(RELAY, /const bucket = Math\.floor\(Date\.now\(\) \/ 3600_000\);/, 'the clock-hour bucket is gone');
  assert.match(RELAY, /rateLimit\.slidingWindowAllowRedis\(redisClient, rk, ENV_CREATE_LIMIT, 3600_000\)/);
  assert.match(section(NL, 'v1-envelopes'), /50 nieuwe envelopes per sleutel in elk willekeurig uur \(een schuivend venster, niet het klokuur\)/);
  assert.match(section(EN, 'v1-envelopes'), /50 envelope creations per key in any sixty minutes \(a sliding window, not the clock hour\)/);
  assert.match(SPEC, /The\s+window slides: at most 50 creations in any hour/);
  assert.doesNotMatch(SPEC + NL + EN, /up to 100|tot 100 bij/);
});

test('API-09-N / API-14-N: id, sign_url and signer status as the relay makes them', () => {
  assert.match(read('relay/envelope.js'), /sign_path: '\/co-sign\?env=' \+ id/);
  assert.doesNotMatch(SPEC, /"id": "env_/);
  assert.doesNotMatch(SPEC, /paramant\.app\/sign\//);
  assert.match(SPEC, /"sign_url": "https:\/\/paramant\.app\/co-sign\?env=/);
  assert.match(SPEC, /`pending` until that slot is signed and `signed` after/);
  assert.doesNotMatch(read('README.md'), /"env_|envelopes\/env_/, 'the README quickstart shows the id the relay makes');
  for (const html of [NL, EN]) {
    assert.doesNotMatch(html, /"envelope_id": "env_/);
    const v1 = section(html, 'v1-envelopes');
    assert.doesNotMatch(v1, /env_\.\.\./);
    assert.match(v1, /co-sign\?env=/);
  }
});

test('API-15-K: the spec says the /v1 document store is durable, as the code is', () => {
  assert.match(read('relay/lib/parasign-open-api.js'), /DURABLE and ENCRYPTED-AT-REST/);
  assert.doesNotMatch(SPEC, /NOT durable across restarts/);
  assert.match(SPEC, /survives a relay restart and is gone when the envelope expires/);
});

test('API-35-A: the Python SDK examples are the 3.0.0 calling convention', () => {
  for (const [name, html] of [['nl', NL], ['en', EN]]) {
    const sdk = section(html, 'sdk');
    assert.match(sdk, /gp\.receive_setup\(\)/, `${name}: receive_setup before send`);
    assert.match(sdk, /hash_, proof = gp\.send\(/, `${name}: send returns a pair`);
    assert.match(sdk, /data, receipt = gp\.receive\(hash_\)/, `${name}: receive returns a pair`);
  }
  const py = API.slice(API.indexOf('## Python SDK'), API.indexOf('## CLI tools'));
  assert.match(py, /gp\.receive_setup\(\)/);
  assert.doesNotMatch(py, /receipt\["burn_confirmed"\]/, 'the SDK 3.0.0 receipt is usually None');
});

test('API-35-A: no Python example calls the mnemonic drop the relay refuses', () => {
  // SDK 3.0.0 drop() posts to /v2/inbound with a hash derived from the phrase,
  // not sha256(payload). The relay binds hash to the bytes on both inbound
  // routes, so the drop comes back 400 hash_mismatch. As long as that binding
  // stands, no runnable Python block may call drop() or pickup().
  const inbound = RELAY.slice(RELAY.indexOf("path === '/v2/inbound'"));
  assert.match(inbound, /createHash\('sha256'\)\.update\(blob\)\.digest\('hex'\) !== hash\) \{[^}]*hash_mismatch/,
    'relay /v2/inbound binds hash to sha256(payload)');
  const blocks = (txt) => [...txt.matchAll(/```python\n([\s\S]*?)```/g)].map((m) => m[1]);
  for (const [name, txt] of [['docs/api.md', API], ['README.md', read('README.md')]]) {
    const py = blocks(txt);
    assert.ok(py.some((b) => /gp\.send\(/.test(b)), `${name}: has the send example`);
    for (const b of py) assert.doesNotMatch(b, /gp\.(drop|pickup)\(/, `${name}: a Python block calls drop/pickup`);
    assert.match(txt, /hash_mismatch/, `${name}: says why drop is left out`);
  }
});

test('API-36-A: every command the CLI reference names exists in the repository', () => {
  for (const [name, html] of [['nl', NL], ['en', EN]]) {
    const cli = section(html, 'client-cli');
    assert.doesNotMatch(cli, /paramant-(send|receive|watch|stream)\b(?!er|r)/, `${name}: no installable paramant-send/receive/watch/stream is claimed`);
    const named = [...cli.matchAll(/<td>((?:scripts|deploy)\/[A-Za-z0-9._-]+)<\/td>/g)].map((m) => m[1]);
    assert.ok(named.length >= 4, `${name}: the table names the scripts`);
    for (const f of named) assert.ok(fs.existsSync(path.join(ROOT, f)), `${name}: ${f} exists`);
  }
  const cli = API.slice(API.indexOf('## CLI tools'), API.indexOf('## Trust model'));
  assert.doesNotMatch(cli, /paramant-receipt/, 'there is no paramant-receipt');
  for (const m of cli.matchAll(/`((?:scripts|deploy)\/[A-Za-z0-9._-]+)`/g)) {
    assert.ok(fs.existsSync(path.join(ROOT, m[1])), `docs/api.md: ${m[1]} exists`);
  }
});
