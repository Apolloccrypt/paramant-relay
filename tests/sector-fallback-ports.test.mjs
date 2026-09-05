// The admin fans every sector call out over SECTORS in admin/server.js. Each
// entry is `process.env.RELAY_X || '<fallback>'`, and the fallback is what runs
// whenever the env is missing, misspelt or empty. It must therefore name the
// port the relay container actually listens on INSIDE the compose network.
//
// It did not. Between 2026-06 and today, health/legal/finance/iot carried
// 3005/3002/3003/3004: the HOST-side published ports out of the comment block
// at the top of docker-compose.yml. On the compose network nothing listens
// there, so four of the five fallbacks were dead and only `main` was right.
// fix/sector-port-drift found this on 10 June 2026 and sat unlanded for 87
// days; the drift survived because production always sets the envs, so the
// fallback is a path nobody walks until the day something goes wrong.
//
// This suite does not hardcode 3000. It reads the port out of docker-compose.yml
// (the x-relay-env anchor every relay service merges) and holds admin/server.js
// to it, so moving the listener moves the expectation with it and a fallback
// left behind goes red.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const compose = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
const adminSrc = fs.readFileSync(path.join(ROOT, 'admin', 'server.js'), 'utf8');

// The shared relay environment, i.e. everything under `x-relay-env: &relay-env`
// up to the next top-level key. Scoped so the admin service's own PORT: "4200"
// further down cannot be mistaken for the relay listener.
function relayEnvBlock() {
  const start = compose.indexOf('x-relay-env: &relay-env');
  assert.notEqual(start, -1, 'docker-compose.yml no longer defines the x-relay-env anchor');
  const rest = compose.slice(start);
  const end = rest.slice(1).search(/\n[^\s#]/);
  return end === -1 ? rest : rest.slice(0, end + 1);
}

function internalRelayPort() {
  const m = relayEnvBlock().match(/^\s+PORT:\s*"?(\d+)"?\s*$/m);
  assert.ok(m, 'x-relay-env no longer sets PORT, so there is nothing to hold the fallbacks to');
  return m[1];
}

// The SECTORS literal in admin/server.js, as {sector: fallbackUrl}.
function sectorFallbacks() {
  const start = adminSrc.indexOf('const SECTORS = {');
  assert.notEqual(start, -1, 'admin/server.js no longer declares a SECTORS map');
  const block = adminSrc.slice(start, adminSrc.indexOf('};', start));
  const out = {};
  for (const m of block.matchAll(/(\w+):\s*process\.env\.(\w+)\s*\|\|\s*'([^']+)'/g)) {
    out[m[1]] = { env: m[2], fallback: m[3] };
  }
  return out;
}

test('every sector fallback points at the container-internal relay port', () => {
  const port = internalRelayPort();
  const sectors = sectorFallbacks();
  assert.ok(Object.keys(sectors).length >= 5,
    `expected all five sectors in SECTORS, parsed ${Object.keys(sectors).length}`);

  const wrong = [];
  for (const [name, { env, fallback }] of Object.entries(sectors)) {
    const u = new URL(fallback);
    if (u.port !== port) wrong.push(`${name} (${env}) falls back to :${u.port}, relay listens on :${port}`);
  }
  assert.deepEqual(wrong, [],
    'A fallback on a port nothing listens on is worse than no fallback: the admin\n' +
    'gets ECONNREFUSED for that sector instead of a working default.\n  ' + wrong.join('\n  '));
});

test('the fallback host is the compose service name, not a host-side address', () => {
  // 127.0.0.1:3001-3004 is the right model for the self-hosted nginx in front
  // of published ports. It is the wrong model here: the admin container reaches
  // its relays by service name over the compose network. Mixing the two is how
  // the port numbers drifted in the first place.
  const bad = [];
  for (const [name, { fallback }] of Object.entries(sectorFallbacks())) {
    const host = new URL(fallback).hostname;
    if (/^(127\.|localhost$|0\.0\.0\.0$|::1$)/.test(host)) bad.push(`${name} -> ${host}`);
    else if (!compose.includes(`  ${host}:`)) bad.push(`${name} -> ${host} is not a service in docker-compose.yml`);
  }
  assert.deepEqual(bad, [], bad.join('\n  '));
});
