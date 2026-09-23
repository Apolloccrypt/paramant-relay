'use strict';
// /v2/dl/<token> with a token that is not [a-f0-9]{48}. The three dl routes
// only match a well-formed token, so anything else fell through to the auth
// gate and a receiver got a 401 about API keys. It is a link problem: 400,
// and the words "invalid or incomplete".

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { boot, killAll } = require('./_relay-server');
const { requireEngine } = require('./_requires');

const engineOk = requireEngine();
let srv = null;

before(async () => { if (engineOk) srv = await boot({ tag: 'dl-invalid' }); });
after(killAll);

async function get(p) {
  const r = await fetch(srv.base + p);
  return { status: r.status, type: r.headers.get('content-type') || '', text: await r.text() };
}

for (const bad of ['abc', 'b'.repeat(47), 'B'.repeat(48), 'b'.repeat(49), 'zz' + 'b'.repeat(46)]) {
  test(`GET /v2/dl/${bad.slice(0, 8)}... (len ${bad.length})/get and /info answer 400 invalid_link`, { skip: !engineOk }, async () => {
    for (const suffix of ['/get', '/info']) {
      const r = await get(`/v2/dl/${bad}${suffix}`);
      assert.equal(r.status, 400, `${suffix}: ${r.text}`);
      assert.match(r.type, /application\/json/);
      assert.equal(JSON.parse(r.text).error, 'invalid_link');
    }
  });
}

test('GET /v2/dl/<bad> in a browser gets a page that says the link is invalid, not burned', { skip: !engineOk }, async () => {
  const r = await get('/v2/dl/not-a-token');
  assert.equal(r.status, 400);
  assert.match(r.type, /text\/html/);
  assert.match(r.text, /invalid or incomplete/);
  assert.doesNotMatch(r.text, /burn/i);
});

test('a well-formed but unknown token still reads as gone (404/410), not as invalid', { skip: !engineOk }, async () => {
  const r = await get(`/v2/dl/${'c'.repeat(48)}/info`);
  assert.equal(r.status, 404);
  const g = await get(`/v2/dl/${'c'.repeat(48)}/get`);
  assert.equal(g.status, 410);
});
