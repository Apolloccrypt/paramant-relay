// A script that uses `import` or `export` at top level MUST be loaded with
// type="module". Without it the browser rejects the whole file as a SyntaxError
// and NOT ONE LINE runs. There is no error in the UI, no failed request in the
// network tab, just a feature that silently does nothing.
//
// That is exactly what shipped: account.html, ontvang.html and parashare.html
// each loaded a module as a classic script. Consequences on production
// (measured 2026-07-25): the account page kept saying "Checking your
// account..." forever, and window._cryptoBridge was never set, so
// ontvang.page.js threw 'WASM crypto bridge not ready' and parashare.page.js
// refused to encrypt. Receiving and sending a file, the core product, was dead.
//
// This gate reads every frontend page, resolves every local script it loads and
// fails on any module loaded as a classic script. Node builtins only, no
// browser, so it runs in the "Root integration suites" CI job.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const FRONTEND = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');

function htmlFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === 'node_modules' ? [] : htmlFiles(full);
    return entry.isFile() && entry.name.endsWith('.html') ? [full] : [];
  });
}

// Top-level import/export only: an `import(` expression is legal in a classic
// script, and the word inside a string or comment must not trip the gate.
const MODULE_SYNTAX = /^\s*(?:import\s+[^(]|import\s*\{|import\s+['"]|export\s+(?:default|const|let|var|function|class|\{))/m;

function isModuleSource(file) {
  let src;
  try { src = fs.readFileSync(file, 'utf8'); } catch { return false; }
  const stripped = src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .filter((line) => !/^\s*\/\//.test(line))
    .join('\n');
  return MODULE_SYNTAX.test(stripped);
}

// Resolve the src attribute of a page-local script to a file on disk. Absolute
// paths are document-root relative, relative ones sit next to the page.
function resolveSrc(pageFile, src) {
  if (/^(https?:)?\/\//.test(src)) return null;      // third party, not ours
  const clean = src.split('?')[0].split('#')[0];
  const file = clean.startsWith('/')
    ? path.join(FRONTEND, clean)
    : path.join(path.dirname(pageFile), clean);
  return file.startsWith(FRONTEND) && fs.existsSync(file) ? file : null;
}

const SCRIPT_TAG = /<script\b([^>]*)>/gi;

test('every module script is loaded with type="module"', () => {
  const offenders = [];
  for (const page of htmlFiles(FRONTEND)) {
    const html = fs.readFileSync(page, 'utf8');
    for (const [, attrs] of html.matchAll(SCRIPT_TAG)) {
      const srcMatch = attrs.match(/\bsrc\s*=\s*["']([^"']+)["']/i);
      if (!srcMatch) continue;
      const isModule = /\btype\s*=\s*["']module["']/i.test(attrs);
      if (isModule) continue;
      const file = resolveSrc(page, srcMatch[1]);
      if (file && isModuleSource(file)) {
        offenders.push(`${path.relative(FRONTEND, page)} loads ${srcMatch[1]} (a module) as a classic script`);
      }
    }
  }
  assert.deepEqual(offenders, [], `\n  ${offenders.join('\n  ')}\n`);
});

// Loading the module correctly is only half of it: its own imports must resolve
// as the browser resolves them. A relative specifier is resolved against the
// importing file, not against the page. When the inline block of parashare.html
// was extracted to js/parashare.inline1.js during the CSP hardening (042b4c5,
// 2026-07-02), its `./crypto-bridge.js` moved with it and started pointing at
// /js/crypto-bridge.js, which does not exist. The import 404s, the module never
// runs, window._cryptoBridge stays unset and parashare.page.js aborts with
// "WASM crypto module not loaded". Sending a file, the core product, was dead
// with no build error and nothing red in CI. ontvang.inline1.js survived only
// because it imports the same file as /crypto-bridge.js, document-root absolute.
const STATIC_IMPORT = /(?:^|\n)\s*(?:import\s[^'"]*?from\s*|import\s*)['"]([^'"]+)['"]/g;

function jsFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === 'node_modules' ? [] : jsFiles(full);
    return entry.isFile() && entry.name.endsWith('.js') ? [full] : [];
  });
}

test('every import inside a frontend module resolves to a file that exists', () => {
  const offenders = [];
  for (const file of jsFiles(FRONTEND)) {
    if (!isModuleSource(file)) continue;
    const src = fs.readFileSync(file, 'utf8');
    for (const [, spec] of src.matchAll(STATIC_IMPORT)) {
      if (/^(https?:)?\/\//.test(spec)) continue;               // third party
      const clean = spec.split('?')[0].split('#')[0];
      const target = clean.startsWith('/')
        ? path.join(FRONTEND, clean)                             // document root
        : path.resolve(path.dirname(file), clean);               // next to the importer
      if (!fs.existsSync(target)) {
        offenders.push(`${path.relative(FRONTEND, file)} imports '${spec}' -> ${path.relative(FRONTEND, target)} does not exist`);
      }
    }
  }
  assert.deepEqual(offenders, [], `\n  ${offenders.join('\n  ')}\n`);
});

// The inverse mistake is cheap to catch here too: a page that declares
// type="module" for a file with no module syntax is harmless but usually means
// the file was meant to export something and does not.
test('the pages that need the WASM crypto bridge load its shim as a module', () => {
  for (const [page, shim] of [['ontvang.html', 'ontvang.inline1.js'], ['parashare.html', 'parashare.inline1.js']]) {
    const html = fs.readFileSync(path.join(FRONTEND, page), 'utf8');
    const tag = [...html.matchAll(SCRIPT_TAG)].map(([, a]) => a).find((a) => a.includes(shim));
    assert.ok(tag, `${page} no longer loads ${shim}; window._cryptoBridge would be unset`);
    assert.match(tag, /\btype\s*=\s*["']module["']/i, `${page} must load ${shim} as a module`);
  }
});
