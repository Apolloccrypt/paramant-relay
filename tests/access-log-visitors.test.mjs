// Tests for the visitor filter (scripts/access-log-visitors.mjs).
//
// Each case is a shape that actually appeared in the logs of 22 August to
// 1 September 2026, because the filter exists to survive exactly those. The two
// that matter most are the ones the previous filter got wrong in opposite
// directions: a scanner wearing a browser string, and heritrix, a crawler that
// really does render.
//
// Node builtins only: runs in the root integration job.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { analyse, classify, collect, ASSET, PROBE, UA_AUTOMATION, operatorIpsFromEnv } from '../scripts/access-log-visitors.mjs';

const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36';

function line({ ip = '1.2.3.4', ts = '01/Sep/2026:16:02:54 +0000', method = 'GET', path = '/', code = 200, size = 100, ref = '-', ua = CHROME }) {
  return `${ip} - - [${ts}] "${method} ${path} HTTP/1.1" ${code} ${size} "${ref}" "${ua}"`;
}

// ── the failure this file was written for ────────────────────────────────────

test('a scanner wearing a browser string is not a visitor', () => {
  // The exact shape of 31 of the 36 IPs that reached /sign: one or two page
  // requests, a real Chrome string, an unearned referer, and not one asset.
  const r = analyse([
    line({ ip: '9.9.9.9', path: '/sign', code: 302, ref: 'https://paramant.app' }),
    line({ ip: '9.9.9.9', path: '/auth/login?next=/sign', ref: 'https://paramant.app' }),
  ]);
  assert.equal(r.atMostVisitors, 0, 'a client that rendered nothing was counted as a visitor');
  assert.equal(r.excludedBy.rendered_nothing, 1);
});

test('a client that renders is not excluded for lacking a referer', () => {
  // no-referrer means a real browser sends none. A rule that wanted one would
  // exclude every genuine visitor on this site.
  const r = analyse([
    line({ ip: '8.8.8.8', path: '/sign' }),
    line({ ip: '8.8.8.8', path: '/design-system.css?v=28' }),
    line({ ip: '8.8.8.8', path: '/sign-flow.js?v=55' }),
  ]);
  assert.equal(r.atMostVisitors, 1);
  assert.equal(r.verdicts.possible_visitor, 1);
});

test('a crawler that really renders is reported apart, not as a person', () => {
  // heritrix fetched 19 assets and would pass the asset rule on behaviour
  // alone. It is a machine we can name, so it is named.
  const ua = 'Mozilla/5.0 (compatible; heritrix/3.14.2-SNAPSHOT-20250101 +http://archive.org)';
  const r = analyse([
    line({ ip: '7.7.7.7', path: '/', ua }),
    line({ ip: '7.7.7.7', path: '/nav.css?v=24', ua }),
  ]);
  assert.equal(r.atMostVisitors, 0, 'a named crawler was counted as a possible visitor');
  assert.equal(r.verdicts.declared_automation, 1);
});

// ── the other rules ──────────────────────────────────────────────────────────

test('one probe path is enough, whatever else the client does', () => {
  const r = analyse([
    line({ ip: '6.6.6.6', path: '/' }),
    line({ ip: '6.6.6.6', path: '/style.css' }),
    line({ ip: '6.6.6.6', path: '/.env', code: 404 }),
  ]);
  assert.equal(r.atMostVisitors, 0);
  assert.equal(r.excludedBy.probe_path, 1);
});

test('a client cycling through user agents is a machine', () => {
  const rows = ['a', 'b', 'c', 'd', 'e'].map((u) => line({ ip: '5.5.5.5', path: '/x.css', ua: `Mozilla/5.0 ${u}` }));
  const r = analyse(rows);
  assert.equal(r.excludedBy.many_user_agents, 1);
});

test('mostly 404s is a machine, but two 404s in a short visit is not', () => {
  const many = analyse([
    line({ ip: '4.4.4.4', path: '/a.css' }),
    line({ ip: '4.4.4.4', path: '/a', code: 404 }),
    line({ ip: '4.4.4.4', path: '/b', code: 404 }),
    line({ ip: '4.4.4.4', path: '/c', code: 404 }),
  ]);
  assert.equal(many.excludedBy.mostly_client_errors, 1);

  const few = analyse([
    line({ ip: '3.3.3.3', path: '/x.css' }),
    line({ ip: '3.3.3.3', path: '/typo', code: 404 }),
  ]);
  assert.equal(few.atMostVisitors, 1, 'a visitor who mistyped once was excluded');
});

// ── operator traffic ─────────────────────────────────────────────────────────

test('operator traffic is separated out, not silently dropped', () => {
  const rows = [line({ ip: '2.2.2.2', path: '/' }), line({ ip: '2.2.2.2', path: '/a.css' })];
  const r = analyse(rows, { operatorIps: new Set(['2.2.2.2']) });
  assert.equal(r.atMostVisitors, 0, 'operator traffic counted as a visitor');
  assert.equal(r.verdicts.operator, 1, 'operator traffic must stay visible in the tally');
  assert.equal(r.excludedBy.operator_ip, 1);
});

test('the operator address comes from the environment, never from the source', () => {
  // This repository is public. The home address of the person running the
  // service is personal data and does not belong in git.
  const src = fs.readFileSync(new URL('../scripts/access-log-visitors.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(src, /\b(?:\d{1,3}\.){3}\d{1,3}\b/, 'a literal IP address is hardcoded in the filter');
  assert.deepEqual([...operatorIpsFromEnv({ PARAMANT_OPERATOR_IPS: ' 1.1.1.1 , 2.2.2.2 ' })], ['1.1.1.1', '2.2.2.2']);
  assert.equal(operatorIpsFromEnv({}).size, 0);
});

// ── the tally, which is half the point ───────────────────────────────────────

test('the result says which rule did the work, not only the total', () => {
  const r = analyse([
    line({ ip: '9.0.0.1', path: '/sign', code: 302 }),
    line({ ip: '9.0.0.2', path: '/sign', code: 302 }),
    line({ ip: '9.0.0.3', path: '/.env', code: 404 }),
    line({ ip: '9.0.0.4', path: '/' }),
    line({ ip: '9.0.0.4', path: '/a.css' }),
  ]);
  assert.equal(r.clients, 4);
  assert.equal(r.atMostVisitors, 1);
  assert.deepEqual(r.excludedBy, {
    rendered_nothing: 2,
    probe_path: 1,
    rendered_and_unremarkable: 1,
  });
});

test('the visitor number is named as a bound, not as a count', () => {
  const r = analyse([line({ ip: '1.0.0.1', path: '/a.css' })]);
  assert.ok('atMostVisitors' in r, 'the field must say it is an upper bound');
  assert.ok(!('visitorCount' in r) && !('people' in r), 'no field may claim to count people');
});

// ── the patterns themselves ──────────────────────────────────────────────────

test('the asset pattern covers what a rendered page actually pulls', () => {
  for (const p of ['/a.css', '/b.js?v=3', '/f.woff2', '/i.svg', '/p.png', '/x.webp', '/favicon.ico', '/y.avif'])
    assert.match(p, ASSET, `${p} should count as an asset`);
  for (const p of ['/sign', '/pricing', '/api/user/check', '/sitemap.xml', '/robots.txt'])
    assert.doesNotMatch(p, ASSET, `${p} is a page or an API call, not an asset`);
});

test('the probe pattern catches what actually hit this server', () => {
  for (const p of ['/.env', '/wp-content/themes/index.php', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
                   '/wp-json/batch/v1', '/.git/config', '/index.php?rest_route=/batch/v1', '/8.php', '/.env.bak'])
    assert.match(p, PROBE, `${p} should be a probe`);
  for (const p of ['/sign', '/parashare', '/docs', '/compliance/nis2', '/v2/envelopes/env_abc'])
    assert.doesNotMatch(p, PROBE, `${p} is a real route`);
});

test('the automation pattern names heritrix, which the previous one missed', () => {
  assert.match('Mozilla/5.0 (compatible; heritrix/3.14.2 +http://archive.org)', UA_AUTOMATION);
  assert.doesNotMatch(CHROME, UA_AUTOMATION, 'a plain Chrome string must not be called automation');
});

test('collect folds requests per client without losing the counts', () => {
  const [d] = collect([
    line({ ip: '1.1.1.1', path: '/' }),
    line({ ip: '1.1.1.1', path: '/a.css' }),
    line({ ip: '1.1.1.1', path: '/b', code: 404 }),
  ]);
  assert.equal(d.requests, 3);
  assert.equal(d.assets, 1);
  assert.equal(d.pages, 2);
  assert.equal(d.clientErrors, 1);
});

test('an external referer is kept; one from our own site is not', () => {
  // Our own pages send no referer, so one that names us was not earned. One
  // from someone else's site is governed by their policy and does mean something.
  const [ours] = collect([line({ ip: '1.1.1.2', path: '/', ref: 'https://paramant.app' })]);
  assert.equal(ours.externalReferers, 0);
  const [theirs] = collect([line({ ip: '1.1.1.3', path: '/', ref: 'https://www.google.com/' })]);
  assert.equal(theirs.externalReferers, 1);
});

test('a malformed line is skipped rather than throwing', () => {
  const r = analyse(['not a log line at all', '', line({ ip: '1.0.0.9', path: '/a.css' })]);
  assert.equal(r.clients, 1);
});
