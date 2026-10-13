// Self-host: what install.sh writes is what docker-compose.yml needs.
// SELF-01/03: the installer's .env lacked REDIS_PASSWORD, RELAY_REDIS_URL and
// PARAMANT_TOTP_MASTER_KEY, so redis refused to start and no relay came up.
// SELF-07: it wrote PARAMANT_LICENSE, which the compose file never passes.
// SELF-19: the compose file hard-coded RELAY_SELF_URL to paramant.app hosts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const install = readFileSync(join(ROOT, 'install.sh'), 'utf8');
const compose = readFileSync(join(ROOT, 'docker-compose.yml'), 'utf8');
const example = readFileSync(join(ROOT, '.env.example'), 'utf8');
const heredoc = (install.match(/cat > "\$\{INSTALL_DIR\}\/\.env" <<ENV\n([\s\S]*?)\nENV/) || [])[1] || '';
const written = new Set([...heredoc.matchAll(/^([A-Z][A-Z0-9_]*)=/gm)].map((m) => m[1]));
for (const m of heredoc.matchAll(/\$\{LICENSE_KEY:\+([A-Z_]+)=/g)) written.add(m[1]);

test('every ${VAR} the compose file needs without a default is written by install.sh', () => {
  const required = [...new Set([...compose.matchAll(/\$\{([A-Z][A-Z0-9_]*)\}/g)].map((m) => m[1]))];
  const missing = required.filter((v) => v !== 'VAR' && !written.has(v)); // VAR: placeholder in a comment
  assert.deepEqual(missing, [], `install.sh leaves these empty: ${missing.join(', ')}`);
});

test('the license goes in as PLK_KEY, which the compose file passes', () => {
  assert.ok(written.has('PLK_KEY'));
  assert.ok(!written.has('PARAMANT_LICENSE'));
  assert.match(compose, /PLK_KEY: "\$\{PLK_KEY:-\}"/);
});

test('RELAY_SELF_URL comes from .env, with the paramant.app host only as default', () => {
  assert.doesNotMatch(compose, /RELAY_SELF_URL: "https:\/\/[a-z]+\.paramant\.app"/);
  for (const s of ['MAIN', 'HEALTH', 'FINANCE', 'LEGAL', 'IOT']) {
    assert.match(compose, new RegExp(`RELAY_SELF_URL: "\\$\\{RELAY_SELF_URL_${s}:-`));
    assert.ok(written.has(`RELAY_SELF_URL_${s}`), `install.sh sets RELAY_SELF_URL_${s}`);
  }
  assert.ok(written.has('PARASIGN_PUBLIC_ORIGIN'));
});

test('.env.example names the three secrets redis and the relays need', () => {
  for (const v of ['REDIS_PASSWORD', 'RELAY_REDIS_URL', 'PARAMANT_TOTP_MASTER_KEY']) assert.match(example, new RegExp(`^${v}=`, 'm'), v);
});

test('the installer clones a 3.1 release, and upgrade moves the tag clone', () => {
  // The pin is the tag of this release: v plus the root package.json version
  // (docs/RELEASE.md). All three installers carry it.
  const tag = 'v' + JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version;
  assert.equal(tag, 'v3.1.3');
  for (const f of ['install.sh', 'frontend/install.sh', 'frontend/install-pi.sh']) {
    const src = readFileSync(join(ROOT, f), 'utf8');
    assert.ok(src.includes(`RELAY_VERSION="\${PARAMANT_VERSION:-${tag}}"`), `${f} clones ${tag} by default`);
  }
  assert.doesNotMatch(install, /pull --ff-only/);
});
