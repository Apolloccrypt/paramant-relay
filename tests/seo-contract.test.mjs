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
  // /parashare sits behind the same nginx auth_request that /sign used to, so
  // by the rule at the top of this list it belongs here: gated pages are held
  // to the noindex contract, not the discoverability one. It was in the sitemap
  // with priority 0.9 while answering 302 to a robots-disallowed login, which
  // indexes nothing and wastes crawl budget on every pass. This does not open or
  // close ParaShare; the page and its gate are untouched. It stops the sitemap
  // from claiming a door is open that is not.
  'parashare',
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

// A page cannot be indexed if the server sends the crawler somewhere robots.txt
// forbids. Measured on 1 September 2026, before this gate existed: sitemap.xml
// listed /sign, nginx answered 302 to /auth/login?next=/sign, and robots.txt
// carries Disallow: /auth/. The crawler was invited to a page, redirected into a
// directory it may not read, and the only title it could see was "302 Found".
// /sign and /parashare were the only two of 59 sitemap URLs that did not answer
// 200.
//
// This gate is about the crawler, not about visitors. An earlier version of this
// comment cited 17 visitors on /sign against 4 on /pricing; that count did not
// survive checking, because 31 of the 36 non-bot IPs that reached /sign fetched
// no CSS, JS, font or favicon, which is a scanner and not a reader. The config
// cycle is measured from nginx and robots.txt, so it holds regardless.
//
// This reads the deployed nginx config in deploy/, not the running server, so it
// gates the commit rather than the machine. Production is a separate copy: see
// scripts/check-prod-drift.sh.
test('no page in the sitemap is gated behind a login redirect', () => {
  const conf = fs.readFileSync(path.join(ROOT, 'deploy', 'nginx-paramant-live.conf'), 'utf8');
  const sitemap = fs.readFileSync(SITEMAP, 'utf8');
  const listed = new Set(
    [...sitemap.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/g)]
      .map((m) => m[1].replace(ORIGIN, '').replace(/\/$/, '') || '/'),
  );

  // Every location block that answers with the login redirect.
  const gated = [...conf.matchAll(/location\s*=?\s*(\/[A-Za-z0-9_\-/.]*)\s*\{[^}]*error_page\s+401\s*=\s*@login_redirect/g)]
    .map((m) => m[1].replace(/\/$/, '') || '/');

  const both = gated.filter((route) => listed.has(route));
  assert.deepStrictEqual(
    both, [],
    `these URLs are in sitemap.xml AND redirect to a robots-disallowed login: ${both.join(', ')}. ` +
    'Either serve the page or take it out of the sitemap; inviting a crawler to a 302 indexes nothing.',
  );
});

// The other half of the same cycle: whatever the login redirect points at must
// stay out of the sitemap, or the next person to add a URL recreates the loop
// from the other side.
test('robots.txt disallows the login path the redirect points at', () => {
  const robots = fs.readFileSync(path.join(FRONTEND, 'robots.txt'), 'utf8');
  const conf = fs.readFileSync(path.join(ROOT, 'deploy', 'nginx-paramant-live.conf'), 'utf8');
  const target = /@login_redirect\s*\{[^}]*?(\/auth\/[A-Za-z0-9_\-/.]*)/.exec(conf);
  if (!target) return;   // no login redirect configured at all
  const dir = target[1].replace(/[^/]*$/, '');
  assert.ok(
    new RegExp(`Disallow:\\s*${dir}`).test(robots),
    `${dir} is where the login redirect sends a crawler, so robots.txt must disallow it`,
  );
});

// ── What a shared link says, and who it says is behind it ────────────────────
// Added 2026-09-02. Two things had drifted page by page and nothing failed when
// they did.
//
// 1. og:title, twitter:title and <title> disagreed on 20 of 38 public pages,
//    and og:description/twitter:description disagreed with the meta description
//    on more. A link pasted in Signal, LinkedIn or WhatsApp then advertised a
//    different page than the one Google shows. These are the same sentence in
//    three places, so they are asserted as one.
//
// 2. The Organization node named no founder and no legal entity, and it existed
//    on the homepage only while every other page pointed a publisher @id at it.
//    The name, the title, the company and the town are all printed on the site:
//    the footer apply-nav.py stamps carries Paramantis Solutions B.V.,
//    Harderwijk and KvK 42115132, and /about carries "founded by Mick Beer,
//    privacy and security researcher". Nothing here is asserted that a reader
//    cannot check on the page itself, which is why it can be pinned at all.
//
// If the founder or the legal name ever has to leave the site, this test is the
// thing that fails first, and the sentence goes out of the pages and out of
// here in the same commit.
const entities = (s) => s
  .replace(/&middot;/g, '·').replace(/&mdash;/g, String.fromCharCode(0x2014))
  .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ')
  .replace(/&amp;/g, '&').trim();

const attr = (html, re) => entities((html.match(re) || [, ''])[1] || '');

// The JSON-LD WebPage node is the fifth copy of the same sentence and it was
// the one that drifted: /trust shipped "Trust & Verification" in the title and
// "Trust & Transparency" in og:title and in the WebPage name at the same time,
// and nothing failed. Structured data that names the page something else is a
// second answer to the same question, and the crawler picks.
function webPageNodes(html) {
  return [...html.matchAll(rx.ld)].flatMap((m) => {
    let parsed;
    try { parsed = JSON.parse(m[1].trim()); } catch { return []; }
    return (parsed['@graph'] || [parsed]).filter((n) => n['@type'] === 'WebPage');
  });
}

test('the title, Open Graph, Twitter cards and JSON-LD say the same thing', () => {
  const problems = [];
  for (const slug of publicPages()) {
    const html = read(slug);
    const title = entities((html.match(rx.title) || [, ''])[1]);
    const desc = attr(html, /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i);
    const pairs = [
      ['og:title', attr(html, /<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']*)["']/i), title],
      ['twitter:title', attr(html, /<meta[^>]+name=["']twitter:title["'][^>]+content=["']([^"']*)["']/i), title],
      ['og:description', attr(html, /<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']*)["']/i), desc],
      ['twitter:description', attr(html, /<meta[^>]+name=["']twitter:description["'][^>]+content=["']([^"']*)["']/i), desc],
    ];
    for (const [name, got, want] of pairs) {
      if (!got) problems.push(`${slug}: no ${name}`);
      else if (got !== want) problems.push(`${slug}: ${name} is "${got}" but the page says "${want}"`);
    }
    const pages = webPageNodes(html);
    if (!pages.length) problems.push(`${slug}: no WebPage node in the JSON-LD`);
    for (const node of pages) {
      if (entities(String(node.name || '')) !== title) {
        problems.push(`${slug}: JSON-LD WebPage name is "${node.name}" but the page says "${title}"`);
      }
      if (node.description !== undefined && entities(String(node.description)) !== desc) {
        problems.push(`${slug}: JSON-LD WebPage description is "${node.description}" but the page says "${desc}"`);
      }
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

test('every public page names the company and the founder in its Organization node', () => {
  const problems = [];
  for (const slug of publicPages()) {
    const html = read(slug);
    const blocks = [...html.matchAll(rx.ld)].map((m) => m[1].trim());
    const nodes = blocks.flatMap((b) => {
      let parsed;
      try { parsed = JSON.parse(b); } catch { return []; }
      return parsed['@graph'] || [parsed];
    });
    const org = nodes.find((n) => n['@type'] === 'Organization');
    if (!org) { problems.push(`${slug}: no Organization node in the JSON-LD`); continue; }
    if (org.legalName !== 'Paramantis Solutions B.V.') {
      problems.push(`${slug}: Organization legalName is "${org.legalName}", the footer says Paramantis Solutions B.V.`);
    }
    if (org.founder?.name !== 'Mick Beer') {
      problems.push(`${slug}: Organization founder is "${org.founder?.name}", /about says Mick Beer`);
    }
    if (org.founder?.jobTitle !== 'Privacy and security researcher') {
      problems.push(`${slug}: founder jobTitle is "${org.founder?.jobTitle}", /about says privacy and security researcher`);
    }
    if (org.address?.addressLocality !== 'Harderwijk' || org.address?.addressCountry !== 'NL') {
      problems.push(`${slug}: Organization address is not Harderwijk, NL`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// ── The sentence itself, not only its consistency ───────────────────────────
// The gate above pins <title>, og:title and twitter:title to each other. That
// is not enough on its own: replacing all three with the same false sentence
// passes it. Measured on 2026-09-02, "Paramant is ISO 27001 certified and free
// forever" on frontend/index.html kept every test in this file and in
// ui-truthfulness green. These three gates pin the content.

// The sentence a buyer reads first, on the pages that carry a claim. Pinned
// word for word on purpose: these are the sentences a search result and a chat
// preview show, so changing one should be a deliberate edit in two files, not a
// side effect of editing a page. Every claim below is printed on the site, and
// the source is named beside it. docs/brand/messaging.md is the guide these
// follow; it landed in #331 and is on main.
//
//   index      "Get documents signed and send files safely, straight from your
//              browser." is the homepage H1 and lede (#328). "Built and hosted
//              in the EU" is the same page's rules grid: Hetzner Germany, Bunny
//              DNS. "Paramantis Solutions B.V." is the footer apply-nav.py
//              stamps on every page. "The Community plan is free, forever" is
//              frontend/pricing.html, quoted in the guide, section 3.
//   pricing    "The Community plan is free, forever" is on
//              frontend/pricing.html. EUR 15/mo is the ParaSend Pro card and
//              EUR 49/month the ParaSign Pro card, so the two floors are named
//              per product: an unsplit "from 15 euro" reads as if signing
//              starts there, and it starts at 49. Both are excl. btw, which is
//              the basis the whole page prices on.
//   about      frontend/about.html: "founded by Mick Beer, privacy and security
//              researcher", plus the footer entity and town.
//   sign       frontend/sign.html: "the file and your private key stay in this
//              browser, and the relay only ever sees a hash" on the account
//              step, "Private key stays on your device" on the mode chooser,
//              and the self-contained downloads that verify offline. The
//              sentence says "the document text", not "the file": in Request
//              signatures the ENCRYPTED document does go to Paramant, because
//              that is how a recipient gets it ("Paramant delivers the
//              encrypted document with the request"). Plaintext and key stay
//              local in all three modes; the file does not.
//   verify     frontend/verify.html checks a signature in the browser with no
//              account and no upload.
//   download   frontend/download.html says the desktop app is not maintained.
//              The old pin promised a download and then counted 21 missing
//              protections, a number nothing in this repo could check. The
//              page now leads with the fact that can be checked: the last
//              release is v0.2.1 of 28 March 2026 and none has followed.
//   trust      frontend/trust.html tags every claim live or planned.
//   signup     the ParaSign Community card on frontend/pricing.html.
//
// The title is pinned as well as the description. A title is the one sentence
// that gets shared, and the gate above only pins the copies to each other: all
// four saying the same false thing passed it.
const PINNED = {
  index: {
    title: 'ParaSign by Paramant · sign and send documents in the EU',
    desc: 'Get documents signed and send files safely, straight from your browser. Built and hosted in the EU by Paramantis Solutions B.V. The Community plan is free, forever.',
  },
  pricing: {
    title: 'Pricing · What is free, and what businesses pay · Paramant',
    desc: 'The Community plan is free, forever. Organisations pay for higher limits: sending from 15 euro a month, signing from 49, excl. btw. From Paramantis Solutions B.V.',
  },
  about: {
    title: 'About Paramant · Founded by Mick Beer',
    desc: 'Paramant is a product of Paramantis Solutions B.V. in Harderwijk, founded by Mick Beer, privacy and security researcher. Company, mission, and how to check us.',
  },
  sign: {
    title: 'Sign a PDF in your browser · Paramant',
    desc: 'Sign a PDF in your browser. The document text and your signing key never leave it, and anyone can check the finished document afterwards.',
  },
  verify: {
    title: 'Check whether a signed document was changed · Paramant',
    desc: 'Check whether a signed document was changed after it was signed. It happens in your browser, without an account and without uploading the file.',
  },
  download: {
    title: 'The Paramant desktop app is no longer maintained',
    desc: 'The Paramant desktop app was last built in March 2026 and is no longer maintained. Paramant runs in your browser instead, with nothing to install.',
  },
  trust: {
    title: 'Trust and verification · Paramant',
    desc: 'What Paramant can see on your own server, what it can do, and how you check both yourself. Every claim on the page is tagged live or planned.',
  },
  signup: {
    title: 'Create a free Paramant account',
    desc: 'Create a Paramant account. ParaSign Community gives 2 signatures a month, unlimited receiving and full post-quantum crypto, forever. No card required.',
  },
};

test('the pages that carry the offer say exactly what they are pinned to say', () => {
  const problems = [];
  for (const [slug, want] of Object.entries(PINNED)) {
    const html = read(slug);
    const title = entities((html.match(rx.title) || [, ''])[1]);
    const desc = attr(html, /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i);
    if (title !== want.title) problems.push(`${slug}: title is "${title}", pinned to "${want.title}"`);
    if (desc !== want.desc) problems.push(`${slug}: description is "${desc}", pinned to "${want.desc}"`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// A certification we do not hold is the cheapest sentence to write and the most
// expensive one to be caught with. Paramant holds none of these: /about states
// a ParaSign signature is a Simple Electronic Signature and explicitly not
// eIDAS-qualified, and no page on the site claims an audit or an ISO number.
// Anything on this list is a claim the site cannot back, so it may not appear
// in the one sentence a search result or a chat preview shows.
const FORBIDDEN_CLAIMS = [
  /ISO\s?\d{4,5}/i, /SOC\s?2/i, /\bcertified\b/i, /\bcertification\b/i,
  /\baccredited\b/i, /\bqualified electronic signature\b/i, /\bQES\b/,
  /\bunbreakable\b/i, /\bmilitary[- ]grade\b/i, /\bguaranteed\b/i,
  /\b100%\s*(secure|private|safe)\b/i, /\bfully compliant\b/i,
];

test('no title or description claims something the site cannot back', () => {
  const problems = [];
  for (const slug of publicPages()) {
    const html = read(slug);
    const title = entities((html.match(rx.title) || [, ''])[1]);
    const desc = attr(html, /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i);
    for (const re of FORBIDDEN_CLAIMS) {
      if (re.test(title)) problems.push(`${slug}: title matches ${re}, and nothing on the site backs that`);
      if (re.test(desc)) problems.push(`${slug}: description matches ${re}, and nothing on the site backs that`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// Internal vocabulary. "The relay" is what we call our own server; a buyer
// reading a Google result or a WhatsApp preview has never seen the word. An
// algorithm name in the first sentence spends the only line we get on something
// the reader cannot act on. The names stay on the pages, where there is room to
// explain them; they stay out of the title and out of the sentence that is read
// before the page is opened.
const INTERNAL = [
  /ML-DSA/i, /ML-KEM/i, /SPHINCS/i, /\bFIPS\b/i, /\.prmnt\b/i,
  /\brelay\b/i, /open-core/i, /\bAES-\d/i, /\benvelope\b/i,
];

// Pages whose reader is an engineer by the time they arrive: they are linked
// from the docs and from /security, not from an ad or a shared link, and the
// vocabulary is the subject of the page rather than a shortcut in it.
const TECHNICAL = new Set(['architecture', 'crypto-agility', 'ct-log', 'docs/paramant-ot-brief']);

test('the preview text a buyer reads first is free of internal vocabulary', () => {
  const problems = [];
  for (const slug of publicPages()) {
    if (TECHNICAL.has(slug)) continue;
    const html = read(slug);
    const title = entities((html.match(rx.title) || [, ''])[1]);
    const desc = attr(html, /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i);
    // The first sentence is the part that survives truncation in a search
    // result; the rest of the description may carry a technical detail.
    const lead = desc.split(/(?<=\.)\s/)[0] || desc;
    for (const re of INTERNAL) {
      if (re.test(title)) problems.push(`${slug}: title carries ${re}, which is our vocabulary and not the reader's`);
      if (re.test(lead)) problems.push(`${slug}: the first sentence of the description carries ${re}`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});
