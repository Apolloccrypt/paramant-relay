// What a page must carry to be found, and what it must NOT carry to stay
// private. Measured on 2026-07-25 before this gate existed: 0 of 56 pages had
// structured data, 11 had no meta description, 8 had no canonical, 9 had no
// Open Graph, 8 had the wrong number of h1, and the sitemap listed 7 URLs that
// return 404 while 13 real pages were missing from it.
//
// No tracking is involved anywhere in this contract. Everything Google needs
// here is static markup: a title, a description, a canonical, an Open Graph
// block, one h1, and a JSON-LD object. Not one cookie, not one third-party
// request.
//
// Node builtins only, so it runs in the existing "Root integration suites" job.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const FRONTEND = path.join(ROOT, 'frontend');
const SITEMAP = path.join(FRONTEND, 'sitemap.xml');
const ORIGIN = 'https://paramant.app';

// Pages behind a login, one-shot flows, and error pages. These must NOT be
// indexed and must NOT appear in the sitemap; they are held to the noindex
// contract instead of the discoverability contract.
const PRIVATE = new Set([
  '404', 'account', 'admin', 'all-systems-go', 'claim', 'co-sign', 'dashboard',
  'developer', 'get', 'ontvang', 'request-key', 'setup',
  'auth/backup', 'auth/login', 'auth/request-reset', 'auth/reset-confirm',
  'auth/setup', 'billing/checkout', 'signup/verified',
]);

// Meta-refresh stubs. They point their canonical at the real page and are held
// to neither contract: no content of their own to describe, and noindexing them
// would cut the signal they exist to pass on.
const REDIRECTS = new Set(['iot']);

// Pages that exist to be found. Everything under frontend/ that is not PRIVATE
// lands here automatically, subdirectories included, so a new page is covered
// the day it is added instead of the day someone remembers this file. The
// subdirectories are not an afterthought: help/ alone holds ten articles, which
// is the long-tail content most likely to be searched for by name.
function publicPages(dir = FRONTEND, prefix = '') {
  const skip = new Set(['node_modules', 'vendor']);
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory()) {
      return skip.has(entry.name) ? [] : publicPages(path.join(dir, entry.name), `${prefix}${entry.name}/`);
    }
    if (!entry.isFile() || !entry.name.endsWith('.html')) return [];
    const slug = `${prefix}${entry.name.slice(0, -5)}`;
    return PRIVATE.has(slug) || REDIRECTS.has(slug) ? [] : [slug];
  }).sort();
}

function read(slug) {
  return fs.readFileSync(path.join(FRONTEND, `${slug}.html`), 'utf8');
}

// frontend/compliance/nis2.html is served as /compliance/nis2, and both
// index.html and help/index.html drop the filename. The sitemap must speak the
// same URLs the server does, or every entry in it is a redirect at best.
function slugToUrl(slug) {
  if (slug === 'index') return `${ORIGIN}/`;
  if (slug.endsWith('/index')) return `${ORIGIN}/${slug.slice(0, -'/index'.length)}`;
  return `${ORIGIN}/${slug}`;
}

function urlToSlug(url) {
  const p = url.replace(ORIGIN, '').replace(/^\/+|\/+$/g, '');
  if (p === '') return 'index';
  return fs.existsSync(path.join(FRONTEND, `${p}.html`)) ? p : `${p}/index`;
}

const rx = {
  title: /<title[^>]*>([\s\S]*?)<\/title>/i,
  desc: /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i,
  canonical: /<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']*)["']/i,
  ogTitle: /<meta[^>]+property=["']og:title["']/i,
  ogDesc: /<meta[^>]+property=["']og:description["']/i,
  ogUrl: /<meta[^>]+property=["']og:url["']/i,
  robots: /<meta[^>]+name=["']robots["'][^>]+content=["']([^"']*)["']/i,
  ld: /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi,
  h1: /<h1[\s>]/gi,
};

test('every public page has a title, a description and a canonical', () => {
  const problems = [];
  for (const slug of publicPages()) {
    const html = read(slug);
    const title = (html.match(rx.title) || [, ''])[1].trim();
    const desc = (html.match(rx.desc) || [, ''])[1].trim();
    const canonical = (html.match(rx.canonical) || [, ''])[1].trim();

    if (!title) problems.push(`${slug}: no <title>`);
    else if (title.length > 65) problems.push(`${slug}: title is ${title.length} chars, Google truncates past ~65`);

    if (!desc) problems.push(`${slug}: no meta description`);
    else if (desc.length < 50 || desc.length > 165) {
      problems.push(`${slug}: description is ${desc.length} chars, aim for 50-165`);
    }

    if (!canonical) problems.push(`${slug}: no canonical link`);
    else if (!canonical.startsWith(ORIGIN)) problems.push(`${slug}: canonical does not point at ${ORIGIN} (${canonical})`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

test('every public page has Open Graph tags so a shared link renders', () => {
  const problems = [];
  for (const slug of publicPages()) {
    const html = read(slug);
    if (!rx.ogTitle.test(html)) problems.push(`${slug}: no og:title`);
    if (!rx.ogDesc.test(html)) problems.push(`${slug}: no og:description`);
    if (!rx.ogUrl.test(html)) problems.push(`${slug}: no og:url`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

test('every public page has exactly one h1', () => {
  const problems = [];
  for (const slug of publicPages()) {
    const count = (read(slug).match(rx.h1) || []).length;
    if (count !== 1) problems.push(`${slug}: ${count} h1 elements, expected exactly 1`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

test('every public page carries valid JSON-LD', () => {
  const problems = [];
  for (const slug of publicPages()) {
    const html = read(slug);
    const blocks = [...html.matchAll(rx.ld)].map((m) => m[1].trim());
    if (!blocks.length) { problems.push(`${slug}: no application/ld+json block`); continue; }
    for (const block of blocks) {
      let parsed;
      // Invalid JSON-LD is worse than none: Google drops the whole block and
      // the page silently loses every rich result it was meant to earn.
      try { parsed = JSON.parse(block); }
      catch (e) { problems.push(`${slug}: JSON-LD does not parse (${e.message})`); continue; }
      const graph = parsed['@graph'] || [parsed];
      for (const node of graph) {
        if (!node['@type']) problems.push(`${slug}: a JSON-LD node has no @type`);
      }
      if (!parsed['@context']) problems.push(`${slug}: JSON-LD has no @context`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

test('private pages are noindex and stay out of the sitemap', () => {
  const problems = [];
  for (const slug of PRIVATE) {
    const file = path.join(FRONTEND, `${slug}.html`);
    if (!fs.existsSync(file)) continue;
    const robots = (fs.readFileSync(file, 'utf8').match(rx.robots) || [, ''])[1];
    if (!/noindex/i.test(robots)) problems.push(`${slug}: private page without <meta name="robots" content="noindex">`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// The sitemap is the one file that can actively hurt: a URL that 404s is a
// wasted crawl and a quality signal, and a page missing from it may never be
// discovered. Both directions are checked against what is actually on disk.
test('the sitemap lists every public page and nothing that does not exist', () => {
  const xml = fs.readFileSync(SITEMAP, 'utf8');
  const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1].trim());
  const slugs = locs.map(urlToSlug);

  const problems = [];
  const onDisk = new Set(publicPages());
  for (const slug of slugs) {
    if (!onDisk.has(slug)) problems.push(`sitemap lists ${slugToUrl(slug)} but frontend/${slug}.html does not exist (or is private)`);
  }
  for (const slug of onDisk) {
    if (!slugs.includes(slug)) problems.push(`frontend/${slug}.html is public but missing from the sitemap`);
  }
  const dupes = slugs.filter((s, i) => slugs.indexOf(s) !== i);
  if (dupes.length) problems.push(`duplicate sitemap entries: ${[...new Set(dupes)].join(', ')}`);

  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

test('the sitemap has a plausible lastmod on every url', () => {
  const xml = fs.readFileSync(SITEMAP, 'utf8');
  const entries = [...xml.matchAll(/<url>([\s\S]*?)<\/url>/g)].map((m) => m[1]);
  const problems = [];
  for (const entry of entries) {
    const loc = (entry.match(/<loc>([^<]+)<\/loc>/) || [, '?'])[1];
    const mod = (entry.match(/<lastmod>([^<]+)<\/lastmod>/) || [, ''])[1];
    if (!mod) { problems.push(`${loc}: no lastmod`); continue; }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(mod)) problems.push(`${loc}: lastmod "${mod}" is not YYYY-MM-DD`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});
