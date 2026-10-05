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

test('fleet helper retries only failed sectors and reports remaining failures', () => {
  const helper = routeSource('async function mutatePlanFleet(', 'async function readEntitlementsFleet(');
  assert.match(helper, /retrySectors/);
  assert.match(helper, /await run\(retrySectors\)/);
  assert.match(helper, /failed:/);
});

test('read-back queries effective entitlements on every sector', () => {
  const helper = routeSource('async function readEntitlementsFleet(', 'function verifyEntitlementsFleet(');
  assert.match(helper, /eachSector\(Object\.keys\(SECTORS\)/);
  assert.match(helper, /\/v2\/admin\/entitlements\//);
  assert.match(helper, /entitlements: body\?\.entitlements/);
});

for (const [name, endpoint, nextMarker] of [
  ['change-plan', '/v2/admin/keys/update-plan', '// ── POST /admin/set-product-plan'],
  ['set-product-plan', '/v2/admin/keys/set-product-plan', '// ── POST /admin/set-parasign'],
]) {
  test(`${name} fans its mutation out to every relay sector`, () => {
    const route = routeSource(`api.post('/admin/${name}'`, nextMarker);
    assert.ok(route.includes(`mutatePlanFleet('${endpoint}'`));
    assert.match(route, /readEntitlementsFleet/);
    assert.match(route, /partial_failure/);
    assert.match(route, /res\.status\(allOk \? 200 : 207\)/);
  });
}
