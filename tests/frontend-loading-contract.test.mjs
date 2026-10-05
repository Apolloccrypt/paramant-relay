// The loading contract for frontend scripts. Node builtins only, no browser, so
// this runs in the "Root integration suites" CI job and costs a second.
//
// It gates two mistakes that each killed a shipped product feature, both
// invisible to every other test we have: no build error, no failed request, no
// console output, no red CI. Just a page that quietly stops working.
//
//   1. READINESS BY EVENT.  A loader announced itself with a one-shot event and
//      a consumer listened for it. Module scripts and deferred classic scripts
//      run in document order, the loader sits higher up the page, so the event
//      fired before the listener existed and the callback never ran. /ontvang
//      hung on "Generating keypair..." from 2026-07-02 until 2026-07-28 with a
//      clean console and every asset loaded. Readiness must be sticky:
//      ready.signal() / ready.when(), see frontend/js/ready.js.
//
//   2. RELATIVE PATHS IN ENTRY POINTS.  A file loaded straight from a page
//      resolves its relative imports against its OWN url. Move the file and the
//      import silently 404s. That is precisely how the ParaSend crypto bridge
//      died for three weeks (042b4c5): CSP extraction moved inline code into
//      js/ and './crypto-bridge.js' started pointing at /js/crypto-bridge.js.
//      Entry points use document-root absolute paths. Files INSIDE a vendor
//      package may stay relative: they move as one unit.
//
// See docs/frontend-loading-contract.md.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const FRONTEND = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const READY_SRC = '/js/ready.js';

function walk(dir, ext) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) return e.name === 'node_modules' ? [] : walk(full, ext);
    return e.isFile() && e.name.endsWith(ext) ? [full] : [];
  });
}

const rel = (f) => path.relative(FRONTEND, f);
const isVendor = (f) => rel(f).split(path.sep).includes('vendor');

// Minified third-party bundles are not ours to police and their contents trip
// every heuristic below. We only own what we wrote.
const MINIFIED = /(^|[.\-])min\.js$|bundle\.js$|globe\.gl|qrcode|jsQR|pdf\.worker/i;

function strip(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '')
            .split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
}

// ── the page model ───────────────────────────────────────────────────────────
const SCRIPT_TAG = /<script\b([^>]*)>/gi;

function scriptsOf(pageFile) {
  const html = fs.readFileSync(pageFile, 'utf8');
  const out = [];
  for (const m of html.matchAll(SCRIPT_TAG)) {
    const attrs = m[1];
    const src = /\bsrc\s*=\s*"([^"]+)"/i.exec(attrs)?.[1];
    if (!src) continue;
    out.push({
      src,
      clean: src.split('?')[0].split('#')[0],
      isModule: /\btype\s*=\s*"module"/i.test(attrs),
      isDeferred: /\bdefer\b/i.test(attrs) || /\basync\b/i.test(attrs),
      raw: m[0],
    });
  }
  return out;
}

function localFile(src) {
  if (/^(https?:)?\/\//.test(src)) return null;                 // third party
  const clean = src.split('?')[0].split('#')[0];
  if (!clean.startsWith('/')) return null;                      // caught separately
  const f = path.join(FRONTEND, clean);
  return fs.existsSync(f) ? f : null;
}

const pages = walk(FRONTEND, '.html');
const ourScripts = walk(FRONTEND, '.js').filter((f) => !MINIFIED.test(path.basename(f)));

// ── 1. readiness is sticky, never a one-shot event ───────────────────────────

// A load-time readiness event. Deliberately narrow: 'signing-key-enrolled'
// fires on a click, long after every script exists, and is not this bug.
const READY_EVENT = /dispatchEvent\(\s*new\s+(?:Custom)?Event\(\s*['"]([a-z0-9:_-]*(?:ready|loaded|available|init)[a-z0-9:_-]*)['"]/gi;
const READY_LISTENER = /addEventListener\(\s*['"]([a-z0-9:_-]*(?:ready|loaded|available)[a-z0-9:_-]*)['"]/gi;

// Browser-owned events are sticky already or fire on real user/document state.
const BUILT_IN = new Set(['load', 'DOMContentLoaded', 'readystatechange', 'beforeunload', 'unload', 'pageshow', 'pagehide']);

test('no script announces readiness with a one-shot event', () => {
  const sins = [];
  for (const f of ourScripts) {
    const src = strip(fs.readFileSync(f, 'utf8'));
    for (const m of src.matchAll(READY_EVENT)) {
      if (BUILT_IN.has(m[1])) continue;
      sins.push(`${rel(f)} dispatches '${m[1]}'`);
    }
  }
  assert.deepEqual(sins, [],
    `\n  A readiness event is lost when it fires before the listener is registered,\n` +
    `  which is the normal case for a module loader above a deferred consumer.\n` +
    `  Use ready.signal('<name>', value) instead — see frontend/js/ready.js.\n\n  ` +
    sins.join('\n  ') + '\n');
});

test('no script waits for readiness with a one-shot listener', () => {
  const sins = [];
  for (const f of ourScripts) {
    if (path.basename(f) === 'ready.js') continue;
    const src = strip(fs.readFileSync(f, 'utf8'));
    for (const m of src.matchAll(READY_LISTENER)) {
      if (BUILT_IN.has(m[1])) continue;
      sins.push(`${rel(f)} listens for '${m[1]}'`);
    }
  }
  assert.deepEqual(sins, [],
    `\n  If the producer already ran, this listener never fires and the feature\n` +
    `  hangs with a clean console. Use await ready.when('<name>') or\n` +
    `  ready.within('<name>', ms, 'label') — see frontend/js/ready.js.\n\n  ` +
    sins.join('\n  ') + '\n');
});

// ── 2. every page that uses ready.js actually loads it, and loads it first ───

const USES_READY = /\bready\s*\.\s*(signal|when|within|done)\s*\(/;

test('every page using readiness loads /js/ready.js as the first, blocking script', () => {
  const sins = [];
  for (const page of pages) {
    const scripts = scriptsOf(page);
    const needs = scripts.some((s) => {
      const f = localFile(s.src);
      return f && f !== path.join(FRONTEND, 'js', 'ready.js') && USES_READY.test(strip(fs.readFileSync(f, 'utf8')));
    });
    const own = scripts.find((s) => s.clean === READY_SRC);

    if (needs && !own) {
      sins.push(`${rel(page)} uses ready.* but never loads ${READY_SRC}`);
      continue;
    }
    if (!own) continue;

    // Order is the whole point: a plain <script> in <head> runs during parsing,
    // so it is guaranteed to be there before any module or deferred file.
    if (own.isModule || own.isDeferred) {
      sins.push(`${rel(page)} loads ${READY_SRC} with defer/async/module — it must block, or it can lose the race it exists to prevent (${own.raw})`);
    }
    const first = scripts.findIndex((s) => localFile(s.src));
    if (scripts.indexOf(own) !== first) {
      sins.push(`${rel(page)} loads ${READY_SRC} after ${scripts[first].clean} — it must come first`);
    }
  }
  assert.deepEqual(sins, [], '\n  ' + sins.join('\n  ') + '\n');
});

// ── 3. entry points use document-root absolute paths ─────────────────────────

const ENTRY_POINTS = new Set(
  pages.flatMap((p) => scriptsOf(p).map((s) => localFile(s.src)).filter(Boolean))
);

const RELATIVE_IMPORT = /(?:^|[\s;}])(?:import|export)\s[^\n]*?from\s*['"](\.\.?\/[^'"]+)['"]|import\s*\(\s*['"](\.\.?\/[^'"]+)['"]\s*\)/g;

test('scripts loaded straight from a page use absolute import paths', () => {
  const sins = [];
  for (const f of ENTRY_POINTS) {
    if (MINIFIED.test(path.basename(f))) continue;
    const src = strip(fs.readFileSync(f, 'utf8'));
    for (const m of src.matchAll(RELATIVE_IMPORT)) {
      sins.push(`${rel(f)} imports '${m[1] || m[2]}'`);
    }
  }
  assert.deepEqual(sins, [],
    `\n  A page can load this file from any url, and a relative specifier resolves\n` +
    `  against the file's own location. Move the file and the import 404s in\n` +
    `  silence — see the ParaSend crypto bridge, dead 2026-07-02 to 07-26.\n` +
    `  Write the path from the document root: '/js/thing.js'.\n\n  ` +
    sins.join('\n  ') + '\n');
});

test('no page references a local asset with a relative path', () => {
  const ATTR = /(?:src|href)\s*=\s*"(\.\.?\/[^"]+)"/gi;
  const sins = [];
  for (const page of pages) {
    const html = strip(fs.readFileSync(page, 'utf8'));
    for (const m of html.matchAll(ATTR)) sins.push(`${rel(page)} -> ${m[1]}`);
  }
  assert.deepEqual(sins, [],
    `\n  Pages are served both with and without a trailing slash (/parashare and\n` +
    `  /parashare/), and a relative path resolves differently under each. Use a\n` +
    `  leading slash.\n\n  ` + sins.join('\n  ') + '\n');
});

// ── 4. tests never hardcode a cache-buster ───────────────────────────────────

// A module's identity is its full url, query string included. Load the same
// file under two different ?v= values and you get two INSTANCES, each with its
// own state. Whoever holds the wrong one is talking to a module nobody else
// uses, and it fails as "why is this null".
//
// That is not theory. tests/sign-full.test.mjs imported '/sign-flow.js?v=48'
// while sign.html had moved to ?v=49, so buildStampedPdf ran on a fresh
// instance that had never opened a document. One red CI run, 2026-07-28.
//
// So: one file, one cache-buster, everywhere. Bump it in one place and every
// reference has to follow, which is exactly the coupling we want to be loud.
test('each frontend file uses one and the same ?v= everywhere', () => {
  const ROOT = path.join(FRONTEND, '..');
  const REF = /['"`](\/[\w./-]+\.(?:js|mjs|css))\?v=(\d+)/g;
  const seen = new Map();                                       // path -> Map(v -> [where])

  const scan = (file, label) => {
    for (const m of strip(fs.readFileSync(file, 'utf8')).matchAll(REF)) {
      if (!seen.has(m[1])) seen.set(m[1], new Map());
      const byV = seen.get(m[1]);
      if (!byV.has(m[2])) byV.set(m[2], new Set());
      byV.get(m[2]).add(label);
    }
  };
  for (const f of pages) scan(f, rel(f));
  for (const f of ourScripts) scan(f, rel(f));
  for (const f of fs.readdirSync(path.join(ROOT, 'tests')).filter((n) => n.endsWith('.mjs'))) {
    scan(path.join(ROOT, 'tests', f), `tests/${f}`);
  }

  const sins = [];
  for (const [file, byV] of seen) {
    if (byV.size < 2) continue;
    const detail = [...byV].map(([v, where]) => `v=${v} in ${[...where].join(', ')}`).join('  |  ');
    sins.push(`${file}: ${detail}`);
  }
  assert.deepEqual(sins.sort(), [],
    `\n  Two cache-busters for one file means two module instances with separate\n` +
    `  state. Pick one value and use it everywhere. In a test, the safest form is\n` +
    `  to read the url off the page rather than repeat it:\n` +
    `    await import(document.querySelector('script[src*="thing.js"]').getAttribute('src'))\n\n  ` +
    sins.join('\n  ') + '\n');
});

// ── 5. every local script a page loads actually exists ───────────────────────

test('every local script tag resolves to a file that exists', () => {
  const sins = [];
  for (const page of pages) {
    for (const s of scriptsOf(page)) {
      if (/^(https?:)?\/\//.test(s.src)) continue;
      if (!s.clean.startsWith('/')) continue;                   // rule above owns these
      if (!fs.existsSync(path.join(FRONTEND, s.clean))) sins.push(`${rel(page)} -> ${s.clean} (missing)`);
    }
  }
  assert.deepEqual(sins, [], '\n  ' + sins.join('\n  ') + '\n');
});
