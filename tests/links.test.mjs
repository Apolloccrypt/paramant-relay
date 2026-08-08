// Where every button leads. The gate the site did not have.
//
// On 2026-08-08 a sweep of the live site found 18 dead destinations out of 144,
// and every gate we had was green while it was true:
//
//   /login                     404. pricing-billing.js sent every signed-out
//                              visitor there when they clicked a price. The
//                              page is /auth/login; the rest of the site knew
//                              that, this one line did not.
//   6 Mollie payment links     404. The no-JS route out of /pricing.
//   5 installer downloads      404. /download offers deb, rpm, AppImage, exe
//                              and apk from a private repo, so every asset is
//                              404 for anyone who is not us.
//   3 ParamantOS links         404, same cause.
//
// None of it is visible from inside a page. The heartbeat proves a page loads
// and initialises; this proves the page leads somewhere. Two questions, two
// gates.
//
// Internal targets resolve against frontend/ the way nginx resolves them, with
// no network, so this runs on every pull request in about a second. External
// targets need the network and a third party's uptime, which has no place in a
// pull request gate: they run hourly against production instead, where a real
// 404 is a real problem and a slow host is not a red PR.
//
//   node --test tests/links.test.mjs                       internal only
//   CHECK_EXTERNAL_LINKS=1 node --test tests/links.test.mjs internal + external
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');

// Routes the relay serves, which have no file in frontend/ and cannot be
// resolved on disk. Everything NOT on this list must exist as a file, which is
// exactly what makes a typo like /login fail here.
const SERVER_ROUTES = [
  /^\/api\//,
  /^\/v1\//,
  /^\/v2\//,
  /^\/\.well-known\//,
  /^\/admin\//,      // the admin container, behind its own gate
];

function htmlFiles(dir) {
  const uit = [];
  for (const naam of fs.readdirSync(dir)) {
    const p = path.join(dir, naam);
    const st = fs.statSync(p);
    if (st.isDirectory()) { if (naam !== 'node_modules') uit.push(...htmlFiles(p)); }
    else if (/\.(html|js)$/.test(naam)) uit.push(p);
  }
  return uit;
}

// Every absolute destination the site hands a visitor: markup links, form
// actions, and the paths a script navigates to on click.
function destinations(file) {
  const src = fs.readFileSync(file, 'utf8');
  const uit = new Set();
  for (const m of src.matchAll(/(?:href|src|action)="([^"]+)"/g)) uit.add(m[1]);
  for (const m of src.matchAll(/(?:location\.href|location\.assign|window\.open)\s*\(?\s*=?\s*['"]([^'"]+)['"]/g)) uit.add(m[1]);
  return [...uit];
}

function resolvesOnDisk(route) {
  const clean = route.split('?')[0].split('#')[0];
  const base = path.join(ROOT, clean);
  if (!base.startsWith(ROOT)) return false;
  return [base, base + '.html', path.join(base, 'index.html')]
    .some((f) => fs.existsSync(f) && fs.statSync(f).isFile());
}

const alle = htmlFiles(ROOT).flatMap((f) => destinations(f).map((d) => ({ d, f })));

test('every internal link resolves to a page that exists', () => {
  const dood = [];
  for (const { d, f } of alle) {
    if (!d.startsWith('/') || d.startsWith('//')) continue;       // relative and protocol-relative: out of scope
    if (SERVER_ROUTES.some((r) => r.test(d))) continue;
    if (resolvesOnDisk(d)) continue;
    dood.push(`${d}   (from ${path.relative(ROOT, f)})`);
  }
  assert.deepEqual([...new Set(dood)].sort(), [],
    `\n  These destinations do not exist. A visitor following them gets the 404 page:\n  ` +
    [...new Set(dood)].sort().join('\n  ') +
    `\n\n  Add the page, fix the path, or add the route to SERVER_ROUTES if the relay serves it.\n`);
});

test('every external link answers', { skip: !process.env.CHECK_EXTERNAL_LINKS && 'set CHECK_EXTERNAL_LINKS=1 (runs hourly against production, not in pull requests)' }, async () => {
  const extern = [...new Set(alle.map(({ d }) => d).filter((d) => /^https?:\/\//.test(d)))];
  const bron = new Map();
  for (const { d, f } of alle) if (extern.includes(d) && !bron.has(d)) bron.set(d, path.relative(ROOT, f));

  // 403 without a browser is how several big hosts answer any bot, so it says
  // nothing about the link. A 404 says the thing is gone, which is what we are
  // hunting: a download button that hands the visitor an error page.
  const dood = [];
  await Promise.all(extern.map(async (url) => {
    const status = await fetch(url, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(20000) })
      .then((r) => r.status).catch((e) => `unreachable (${e.name})`);
    if (status === 404 || status === 410) dood.push(`${status}  ${url}   (from ${bron.get(url)})`);
  }));

  assert.deepEqual(dood.sort(), [],
    `\n  These external destinations are gone:\n  ` + dood.sort().join('\n  ') +
    `\n\n  A download button or a payment link that 404s is worse than not offering it.\n`);
});
