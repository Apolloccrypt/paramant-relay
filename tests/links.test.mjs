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
  /^\/dl\//,         // installers: in the docroot, not in the repo. See DOCROOT_ROUTES.
];

// An exception on SERVER_ROUTES is a hole unless something else covers it, and
// /dl/ is the case that would hurt: five installer buttons that were 404 for
// every visitor is exactly what this file exists to catch. The files live in the
// docroot and not in git (like dist/), so disk cannot answer for them and
// production has to. Collected here, checked against the live site in the
// hourly run below.
const DOCROOT_ROUTES = /^\/dl\//;

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

// A page nothing links to is a page nobody reaches. /parasend shipped exactly
// like that: the product page existed and was in the sitemap, and not one link
// on the whole site pointed at it. /parasign had one, from /sign. The check
// above proves a link leads somewhere; this proves a page is arrived at, which
// is the other half of the same question.
test('the two product pages are reachable, and from the homepage', () => {
  const home = new Set(destinations(path.join(ROOT, 'index.html')).map((d) => d.split('?')[0].split('#')[0]));
  const overal = new Map();
  for (const { d, f } of alle) {
    const clean = d.split('?')[0].split('#')[0];
    if (!overal.has(clean)) overal.set(clean, new Set());
    overal.get(clean).add(path.relative(ROOT, f));
  }
  for (const route of ['/parasign', '/parasend']) {
    const bronnen = [...(overal.get(route) || [])].filter((f) => f !== route.slice(1) + '.html');
    assert.ok(bronnen.length,
      `Nothing on the site links to ${route}. The page exists and is in the sitemap, so it is` +
      ` indexed and unreachable at the same time.`);
    assert.ok(home.has(route),
      `The homepage does not link to ${route}. It is where a visitor starts, and both products` +
      ` are introduced there, so both product pages are reached from there.`);
  }
});

const BASE = process.env.PARAMANT_BASE_URL || 'https://paramant.app';

test('every file served from the docroot is really there', { skip: !process.env.CHECK_EXTERNAL_LINKS && 'set CHECK_EXTERNAL_LINKS=1 (runs hourly against production, not in pull requests)' }, async () => {
  const paden = [...new Set(alle.map(({ d }) => d).filter((d) => DOCROOT_ROUTES.test(d)))];
  assert(paden.length, 'no /dl/ links found at all, which means the download buttons vanished');

  // Range request: proves the file is there and readable without pulling 80 MB
  // of AppImage through CI. 206 or 200 both mean served.
  const dood = [];
  await Promise.all(paden.map(async (p) => {
    const r = await fetch(BASE + p, { headers: { Range: 'bytes=0-1023' }, signal: AbortSignal.timeout(30000) })
      .catch((e) => ({ status: `unreachable (${e.name})` }));
    if (r.status !== 200 && r.status !== 206) dood.push(`${r.status}  ${p}`);
  }));

  assert.deepEqual(dood.sort(), [],
    `\n  These files are offered on the site but not in the docroot on ${BASE}:\n  ` +
    dood.sort().join('\n  ') +
    `\n\n  They are not in git, so a deploy does not carry them. Copy them to\n` +
    `  /home/paramant/app/dl/ or take the button off the page.\n`);
});

test('every external link answers', { skip: !process.env.CHECK_EXTERNAL_LINKS && 'set CHECK_EXTERNAL_LINKS=1 (runs hourly against production, not in pull requests)' }, async () => {
  const extern = [...new Set(alle.map(({ d }) => d).filter((d) => /^https?:\/\//.test(d)))];
  const bron = new Map();
  for (const { d, f } of alle) if (extern.includes(d) && !bron.has(d)) bron.set(d, path.relative(ROOT, f));

  // 403 without a browser is how several big hosts answer any bot, so it says
  // nothing about the link. A 404 says the thing is gone, which is what we are
  // hunting: a download button that hands the visitor an error page.
  //
  // A 404 alone is still not enough. On 2026-08-08 media.defense.gov answered
  // 404 to this test and 403 to both curl and Chromium, which looked like a
  // blocked client rather than a missing file. It was not: the host's root
  // answers 200, the FAQ next to it downloads fine, and the factsheet really
  // was withdrawn. The 403 was the misleading half.
  //
  // So each 404 is weighed against that host's own root. Root reachable means
  // the page is genuinely gone. Root turning us away too means we are being
  // filtered and cannot tell, and the run says so out loud instead of failing
  // on nothing. Never conclude "dead" from one client's word.
  const status = (url) =>
    fetch(url, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(20000) })
      .then((r) => r.status).catch((e) => `unreachable (${e.name})`);

  const dood = [];
  const onmeetbaar = [];
  await Promise.all(extern.map(async (url) => {
    const s = await status(url);
    if (s !== 404 && s !== 410) return;
    const root = await status(new URL(url).origin + '/');
    if (typeof root === 'number' && root < 400) dood.push(`${s}  ${url}   (from ${bron.get(url)})`);
    else onmeetbaar.push(`${s}  ${url}   (host root answers ${root})`);
  }));

  if (onmeetbaar.length) {
    console.log(`\n  Not measurable, the host turns us away on its own root too:\n  ` +
      onmeetbaar.sort().join('\n  ') +
      `\n  Open these by hand before treating them as broken.\n`);
  }

  assert.deepEqual(dood.sort(), [],
    `\n  These external destinations are gone:\n  ` + dood.sort().join('\n  ') +
    `\n\n  A download button or a payment link that 404s is worse than not offering it.\n`);
});

// ---------------------------------------------------------------------------
// The same two questions, for docs/.
//
// Everything above guards frontend/, where a dead link is a visitor on the 404
// page. docs/ has the quieter version of the same failure: a reader following
// [pentest-report-2026-04-08.txt](../pentest-report-2026-04-08.txt) to a file
// that the v2.4.0 repo cleanup deleted. Nothing noticed, because nothing looked.
//
// Two rules, both resolved on disk with no network:
//   a link to a path in the repo must reach a file (or a directory, for the
//   ones that deliberately point at a folder), and a #fragment must exist as a
//   heading, an id or a name in the file it points into.
//
// Code is not prose: fenced blocks, inline spans and HTML comments are removed
// before anything is read as a link, so a <script src="/js/ready.js"> in an
// example stays an example. Template placeholders (<naam>, {x}, $VAR) are not
// destinations either.
const REPO = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const DOCS = path.join(REPO, 'docs');

// Anything with a scheme, or protocol-relative, is somebody else's uptime: the
// hourly external run above owns those, a pull request does not.
const EXTERN = /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i;
const PLACEHOLDER = /[<>{}$|]/;

function docFiles(dir) {
  const uit = [];
  for (const naam of fs.readdirSync(dir)) {
    const p = path.join(dir, naam);
    const st = fs.statSync(p);
    if (st.isDirectory()) { if (naam !== 'node_modules') uit.push(...docFiles(p)); }
    else if (/\.(md|html)$/.test(naam)) uit.push(p);
  }
  return uit;
}

// Fences, inline spans and comments out. An example that shows a link is not a
// link, and treating it as one is how a link checker earns its reputation.
function zonderCode(src) {
  const uit = [];
  let hek = null;
  for (const regel of src.replace(/<!--[\s\S]*?-->/g, '').split('\n')) {
    const m = regel.match(/^\s{0,3}(`{3,}|~{3,})/);
    if (hek) { if (m && m[1][0] === hek[0] && m[1].length >= hek.length) hek = null; uit.push(''); continue; }
    if (m) { hek = m[1]; uit.push(''); continue; }
    uit.push(regel.replace(/`+[^`]*`+/g, ''));
  }
  return uit.join('\n');
}

// Markdown: inline links, reference definitions, and the raw HTML that markdown
// allows. HTML: the same attributes the frontend scan reads.
function docDestinations(file) {
  const ruw = fs.readFileSync(file, 'utf8');
  const src = file.endsWith('.md') ? zonderCode(ruw) : ruw;
  const uit = new Set();
  if (file.endsWith('.md')) {
    for (const m of src.matchAll(/\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+["'][^"']*["'])?\s*\)/g)) uit.add(m[1]);
    for (const m of src.matchAll(/^\s{0,3}\[[^\]]+\]:\s*<?(\S+)>?/gm)) uit.add(m[1]);
  }
  for (const m of src.matchAll(/(?:href|src|action)\s*=\s*["']([^"']+)["']/g)) uit.add(m[1]);
  return [...uit];
}

// GitHub's heading slug: lowercase, punctuation dropped, spaces to hyphens.
// A repeated heading gets -1, -2, which is why the counter is here.
function slug(tekst) {
  return tekst
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[`*_~]/g, '')
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N} \-_]/gu, '')
    .replace(/ +/g, '-');
}

// Every fragment a reader can land on in one file.
function ankers(file) {
  const ruw = fs.readFileSync(file, 'utf8');
  const uit = new Set();
  for (const m of ruw.matchAll(/(?:id|name)\s*=\s*["']([^"']+)["']/g)) uit.add(m[1]);
  if (!file.endsWith('.md')) return uit;
  const geteld = new Map();
  for (const m of zonderCode(ruw).matchAll(/^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$/gm)) {
    const s = slug(m[1]);
    if (!s) continue;
    const n = geteld.get(s) || 0;
    geteld.set(s, n + 1);
    uit.add(n ? `${s}-${n}` : s);
  }
  return uit;
}

const ankerCache = new Map();
function heeftAnker(file, fragment) {
  if (!ankerCache.has(file)) ankerCache.set(file, ankers(file));
  return ankerCache.get(file).has(fragment) || ankerCache.get(file).has(decodeURIComponent(fragment));
}

const docs = docFiles(DOCS).flatMap((f) => docDestinations(f).map((d) => ({ d, f })));

test('every link in docs/ points at something that exists', () => {
  assert(docs.length, 'no links found under docs/ at all, which means the scan stopped reading the files');

  const dood = [];
  for (const { d, f } of docs) {
    if (EXTERN.test(d) || PLACEHOLDER.test(d)) continue;
    const [pad, anker] = [d.split('#')[0].split('?')[0], d.split('#').slice(1).join('#')];

    // A path from the site root is a route, not a file next to the doc, so it
    // is answered by the same rules as the frontend scan above.
    if (pad.startsWith('/')) {
      if (SERVER_ROUTES.some((r) => r.test(pad)) || resolvesOnDisk(pad)) continue;
      dood.push(`${d}   (from ${path.relative(REPO, f)})`);
      continue;
    }

    const doel = pad ? path.resolve(path.dirname(f), decodeURIComponent(pad)) : f;
    if (!doel.startsWith(REPO)) { dood.push(`${d}   (from ${path.relative(REPO, f)}: leaves the repo)`); continue; }
    if (!fs.existsSync(doel)) { dood.push(`${d}   (from ${path.relative(REPO, f)})`); continue; }
    if (!anker) continue;
    if (!fs.statSync(doel).isFile() || !/\.(md|html)$/.test(doel)) continue;   // no headings to have
    if (!heeftAnker(doel, anker)) dood.push(`${d}   (from ${path.relative(REPO, f)}: no such heading or id)`);
  }

  assert.deepEqual([...new Set(dood)].sort(), [],
    `\n  These links in docs/ lead nowhere:\n  ` +
    [...new Set(dood)].sort().join('\n  ') +
    `\n\n  Point them at the file or heading that exists, or take the link off.\n`);
});
