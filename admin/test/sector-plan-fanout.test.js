'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

function routeSource(start, end) {
  const from = src.indexOf(start);
  const to = src.indexOf(end, from + start.length);
  assert.ok(from >= 0 && to > from, `route markers missing: ${start}`);
  return src.slice(from, to);
}

test('callRelay can address a named sector and keeps internal authentication', () => {
  const helper = routeSource('async function callRelay(', '// Find API key entry by email');
  assert.match(helper, /sector = "health"/);
  assert.match(helper, /SECTORS\[sector\]/);
  assert.match(helper, /"X-Internal-Auth": INTERNAL_TOKEN/);
});

for (const [name, endpoint, nextMarker] of [
  ['change-plan', '/v2/admin/keys/update-plan', '// ── POST /admin/set-product-plan'],
  ['set-product-plan', '/v2/admin/keys/set-product-plan', '// ── POST /admin/set-parasign'],
]) {
  test(`${name} fans its mutation out to every relay sector`, () => {
    const route = routeSource(`api.post('/admin/${name}'`, nextMarker);
    assert.match(route, /eachSector\(Object\.keys\(SECTORS\)/);
    assert.ok(route.includes(`callRelay('${endpoint}'`));
    assert.match(route, /'POST', s/);
    assert.match(route, /sectors_updated/);
  });
}
