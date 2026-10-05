// One version, in one place, everywhere.
//
// On 2026-09-02 the repo said four different things at once: root package.json
// 3.1.0, relay/package.json 3.0.0, admin/package.json 0.9.0-beta, the relay
// image label 3.0.0, the admin image label 1.0.0, and a VERSION literal in
// relay.js reading 3.1.0. scripts/post-deploy-verify.sh asserted that /health
// returns "3.0.0", which the relay had already stopped doing. Four places,
// four answers, and the one check that could have caught it was wrong too.
//
// The rule now: root package.json is the version. relay.js reads its own
// package.json at runtime, the Dockerfiles take it as a build-arg whose default
// must match, and this suite is what keeps every copy honest. If you bump a
// version, bump it in package.json and let this test tell you what else moved.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const pkg = (p) => JSON.parse(read(p));

const CANONICAL = pkg('package.json').version;

test('V1 the root package.json version is a plain semver release', () => {
  assert.match(
    CANONICAL,
    /^\d+\.\d+\.\d+$/,
    `root package.json version "${CANONICAL}" is not X.Y.Z. Pre-release ` +
    'suffixes are fine in a branch but not on main: the tag, the image label ' +
    'and the /health response all copy this string verbatim.'
  );
});

test('V2 relay and admin package.json carry the same version', () => {
  assert.equal(pkg('relay/package.json').version, CANONICAL,
    'relay/package.json disagrees with the root package.json');
  assert.equal(pkg('admin/package.json').version, CANONICAL,
    'admin/package.json disagrees with the root package.json');
});

test('V3 both package-lock files agree with their package.json', () => {
  for (const dir of ['', 'relay/', 'admin/']) {
    const lock = pkg(`${dir}package-lock.json`);
    assert.equal(lock.version, CANONICAL, `${dir}package-lock.json version`);
    assert.equal(lock.packages[''].version, CANONICAL,
      `${dir}package-lock.json packages[""] version`);
  }
});

test('V4 relay.js reads its version instead of restating it', () => {
  const src = read('relay/relay.js');
  assert.match(
    src,
    /const VERSION\s*=\s*\(\(\)\s*=>\s*\{[\s\S]{0,200}require\('\.\/package\.json'\)\.version/,
    'relay.js must derive VERSION from ./package.json. A literal here is ' +
    'exactly the drift this suite exists to stop.'
  );
  // And the value it will produce at runtime is the canonical one.
  assert.equal(pkg('relay/package.json').version, CANONICAL);
});

test('V5 package.json is present in the relay runtime image', () => {
  // relay.js require()s ./package.json at startup. The runtime stage copies
  // individual files rather than the whole context, so forgetting this COPY
  // means a running relay reports 0.0.0-unknown on /health and nobody notices
  // until a deploy check fails.
  const df = read('relay/Dockerfile');
  const runtime = df.slice(df.lastIndexOf('\nFROM '));
  assert.match(runtime, /^COPY package\.json \.\/$/m,
    'the runtime stage of relay/Dockerfile must COPY package.json');
});

test('V6 both Dockerfile version labels come from a build-arg with a matching default', () => {
  for (const df of ['relay/Dockerfile', 'admin/Dockerfile']) {
    const src = read(df);
    assert.match(src, /org\.opencontainers\.image\.version="\$\{IMAGE_VERSION\}"/,
      `${df} must label the image from the IMAGE_VERSION build-arg, not a literal`);
    const arg = src.match(/^ARG IMAGE_VERSION=(.+)$/m);
    assert.ok(arg, `${df} must declare ARG IMAGE_VERSION with a default`);
    assert.equal(arg[1].trim(), CANONICAL,
      `${df}: ARG IMAGE_VERSION default must match the root package.json`);
  }
});

test('V7 the CHANGELOG has a released section for this version', () => {
  const cl = read('CHANGELOG.md');
  assert.ok(
    cl.includes(`## [${CANONICAL}]`),
    `CHANGELOG.md has no "## [${CANONICAL}]" section. Per docs/RELEASE.md the ` +
    'CHANGELOG section is written before the version is bumped, not after the ' +
    'tag: it is the only place that says what a release contains.'
  );
});

test('V8 the deploy check derives the expected version instead of hardcoding it', () => {
  // scripts/post-deploy-verify.sh is the last gate between a deploy and an
  // operator saying "it is up". It compared /health against the literal 3.0.0
  // for as long as the relay reported 3.1.0, so it could only ever have been
  // right by accident.
  const sh = read('scripts/post-deploy-verify.sh');
  assert.match(sh, /EXPECT_VER=.*relay\/package\.json/,
    'post-deploy-verify.sh must read the expected version from relay/package.json');
  assert.match(sh, /check "\/health version" "\$EXPECT_VER"/,
    'post-deploy-verify.sh must compare /health against $EXPECT_VER, not a literal');
});
