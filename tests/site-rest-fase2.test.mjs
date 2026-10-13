// Fase 2, restpunten P12 (site en claims). One block per matrix cell, each
// red on cc931c2f and green after the fix. The cell id is in the test title.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const REPO = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const FE = path.join(REPO, 'frontend');
const rd = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');
const pg = (slug) => fs.readFileSync(path.join(FE, slug + '.html'), 'utf8');
const exists = (rel) => fs.existsSync(path.join(REPO, rel));
const strip = (s) => s.replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]+>/g, ' ')
  .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&[a-z]+;|&#\d+;/g, ' ').replace(/\s+/g, ' ');
const hasEnglish = (p) => {
  const rel = p.replace(/^\/+/, '');
  return rel === '' || fs.existsSync(path.join(FE, 'en', rel + '.html')) || fs.existsSync(path.join(FE, 'en', rel, 'index.html'));
};
function englishPages(dir = path.join(FE, 'en')) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...englishPages(full));
    else if (e.name.endsWith('.html')) out.push(full);
  }
  return out;
}

test('SITE-03-A: /gereedschap has an English page, and the language switch on both sides points at it', () => {
  assert.ok(exists('frontend/en/gereedschap.html'), 'frontend/en/gereedschap.html is missing');
  const nl = pg('gereedschap'); const en = pg('en/gereedschap');
  assert.match(en, /<html lang="en">/);
  for (const html of [nl, en]) {
    assert.match(html, /<link rel="alternate" hreflang="en" href="https:\/\/paramant\.app\/en\/gereedschap">/);
    assert.match(html, /<link rel="alternate" hreflang="nl" href="https:\/\/paramant\.app\/gereedschap">/);
    assert.match(html, /<a href="\/en\/gereedschap" hreflang="en" lang="en"/);
  }
  assert.match(rd('frontend/sitemap.xml'), /<loc>https:\/\/paramant\.app\/en\/gereedschap<\/loc>/);
  // The English bar, stamped and re-rendered, sends Tools to the English page.
  assert.match(rd('frontend/js/nav-auth.js'), /\['Tools', '\/en\/gereedschap'\]/);
  assert.match(pg('en/about'), /<a href="\/en\/gereedschap" class="nav-link">Tools<\/a>/);
  // The same promises as the Dutch page: Community numbers and the sign-in-first buttons.
  assert.ok(en.includes('two signatures a month') && en.includes('fifty transfers a month'));
  for (const r of ['/en/sign', '/en/parashare']) assert.ok(en.includes(`href="/en/auth/login?next=${r}"`), r);
  for (const r of ['/en/vault', '/en/verify', '/en/ct-log', '/en/get']) assert.ok(en.includes(`href="${r}"`), r);
});

test('SITE-03-F*: an English page links to the English page wherever one exists, the drawer Help included', () => {
  const wrong = [];
  for (const file of englishPages()) {
    const html = fs.readFileSync(file, 'utf8').replace(/<(div|span) class="nav-lang"[\s\S]*?<\/\1>/g, '');
    for (const m of html.matchAll(/<a\b[^>]*href="(\/(?!en\b|en\/)[^"#?]*)(?:[#?][^"]*)?"[^>]*>/g)) {
      if (/hreflang="nl"|lang="nl"/.test(m[0])) continue;
      if (hasEnglish(m[1])) wrong.push(`${path.relative(FE, file)} -> ${m[1]}`);
    }
  }
  assert.deepEqual(wrong, [], `\n  ${wrong.join('\n  ')}\n`);
  assert.match(pg('en/about'), /<a href="\/en\/help" class="nav-tail-link">Help<\/a>/);
  for (const r of ['terms', 'dpa', 'privacy']) assert.ok(pg('en/signup').includes(`href="/en/${r}"`), `en/signup -> /en/${r}`);
  // An unknown English address gets an English 404.
  assert.ok(exists('frontend/en/404.html'));
  assert.match(pg('en/404'), /<html lang="en">[\s\S]*Page not found/);
  const nginx = rd('deploy/nginx-paramant-live.conf');
  assert.match(nginx, /location \/en\/ \{\s*error_page 404 \/en\/404\.html;/);
  assert.match(nginx, /location = \/en\/404\.html \{ internal; \}/);
});

test('SITE-05-A-en: a signed-out English visitor of a gated page lands on the English login', () => {
  const nginx = rd('deploy/nginx-paramant-live.conf');
  const block = /location @login_redirect \{([\s\S]*?)\n    \}/.exec(nginx);
  assert.ok(block, '@login_redirect is not a block any more');
  assert.match(block[1], /\^\/en\(\/\|\$\)[\s\S]*\/en\/auth\/login\?next=\$uri/);
  assert.match(block[1], /return 302 https:\/\/\$host\/auth\/login\?next=\$uri;/);
});

test('SITE-11-A: the DPA confirmation is Dutch for a Dutch signature and English otherwise', () => {
  const require = createRequire(import.meta.url);
  const { dpaConfirmation } = require('../relay/lib/dpa-mail.js');
  const base = { name: 'Anna <b>', title: 'Notaris', org: 'Kantoor & Co', ref: 'DPA-X1', signed_at: '2026-10-05T10:00:00.000Z', version: '2026-10-04' };
  const nl = dpaConfirmation({ ...base, lang: 'nl' });
  const en = dpaConfirmation({ ...base, lang: 'en' });
  assert.match(nl.subject, /^Verwerkersovereenkomst ondertekend: Kantoor & Co \(DPA-X1\)$/);
  assert.match(nl.html, /Beste Anna &lt;b&gt;,/);
  assert.match(nl.html, /verwerkersovereenkomst \(AVG art\. 28\)/);
  assert.doesNotMatch(nl.html, /Dear |Agreement details/);
  assert.match(en.subject, /^DPA signed: /);
  assert.match(en.html, /Dear Anna &lt;b&gt;,/);
  assert.equal(dpaConfirmation({ ...base }).subject, en.subject, 'no language falls back to English');
  // The pages say which language they were signed in, and the relay uses it.
  assert.match(rd('frontend/js/dpa.inline1.js'), /lang: 'nl'/);
  assert.match(rd('frontend/js/dpa.inline1.en.js'), /lang: 'en'/);
  assert.match(rd('relay/relay.js'), /dpaMail\.dpaConfirmation\(\{[\s\S]{0,120}lang: d\.lang === 'nl' \? 'nl' : 'en'/);
});

test('SITE-13-A: /all-systems-go can draw an info row, which the relay uses for edge TLS and an empty key set', () => {
  for (const p of ['all-systems-go', 'en/all-systems-go']) assert.match(pg(p), /\.asg-info\s*\{/, p);
  const rly = rd('relay/relay.js');
  assert.match(rly, /let tlsStatus = 'info'/);
  assert.match(rly, /apiKeys\.size > 0 \? 'green' : 'info'/);
  assert.match(rly, /const rank = \{ info: 0, green: 0, yellow: 1, red: 2 \};/);
});

test('SITE-21-A: the sources under each competitor on /vs are links where a link can be checked', () => {
  for (const p of ['vs', 'en/vs']) {
    const lines = [...pg(p).matchAll(/<p class="dim mono"[^>]*>((?:Bronnen|Sources):[\s\S]*?)<\/p>/g)].map((m) => m[1]);
    assert.equal(lines.length, 3, `${p}: three source lines`);
    for (const l of lines) assert.match(l, /<a href="https:\/\/[^"]+" rel="noopener"/, `${p}: ${l.slice(0, 80)}`);
    assert.doesNotMatch(pg(p), /niet gelinkt, terug te vinden|not linked, findable/);
  }
});

test('SITE-30-A: the core principle on /security names the named-recipient send as an exception', () => {
  const nl = strip(pg('security')); const en = strip(pg('en/security'));
  const nlCore = nl.slice(nl.indexOf('tussenpersoon die niet vertrouwd hoeft te worden'), nl.indexOf('Waar de zero-knowledge-garantie nu geldt'));
  const enCore = en.slice(en.indexOf('untrusted intermediary'), en.indexOf('Where the zero-knowledge guarantee holds today'));
  assert.match(nlCore, /ontvangers op naam/);
  assert.match(nlCore, /extensies/);
  assert.match(enCore, /named recipients/);
  assert.match(enCore, /extensions/);
});

test('SITE-31-A: /vs says where post-quantum encryption applies, not that every file is', () => {
  const bare = [];
  for (const p of ['vs', 'en/vs']) {
    for (const s of strip(pg(p)).split(/(?<=[.!?])\s+/)) {
      if (/post[- ]?quantum/i.test(s) && /versleutel|encrypt/i.test(s) && !/hybr|ECDH|P-256|live overdracht|live hand-over|SDK|signature|handtekening|verhoudt|compares/i.test(s)) bare.push(`${p}: ${s.slice(0, 120)}`);
    }
  }
  assert.deepEqual(bare, [], `\n  ${bare.join('\n  ')}\n`);
  assert.doesNotMatch(pg('vs'), /relay voor post-quantumversleutelde bestanden/);
  assert.doesNotMatch(pg('en/vs'), /post-quantum encrypted file relay/);
});

test('SITE-33-A: /privacy no longer says every blob is padded to 5 MB', () => {
  assert.doesNotMatch(pg('privacy'), /opgevulde blokken van 5 MB|opgesplitst in versleutelde blokken van 5 MB/);
  assert.doesNotMatch(pg('en/privacy'), /5 MB padded chunks|split into 5 MB encrypted chunks/);
  assert.match(pg('privacy'), /alleen bij de live overdracht opgevuld/);
  assert.match(pg('en/privacy'), /padded only in the live hand-over/);
});

test('SITE-34-A: /architecture does not deny the American mail provider its key material', () => {
  for (const [p, deny] of [['architecture', /Geen Amerikaanse partij heeft versleutelde tekst of een sleutel|geen Amerikaanse partij<\/span>/], ['en/architecture', /No US entity holds ciphertext or a key|no US entity<\/span>/]]) {
    assert.doesNotMatch(pg(p), deny, p);
    assert.match(pg(p), /Resend/, `${p} must name the provider`);
  }
  const partners = JSON.parse(rd('deploy/partners.json'));
  const resend = partners.partijen.find((x) => x.id === 'resend');
  assert.equal(resend.status, 'actief', 'architecture names Resend, so partners.json must still list it as active');
  assert.equal(rd('frontend/partners.json'), rd('deploy/partners.json'));
});

test('SITE-39-A: the /docs audit table lists every finding the published report still marks open', () => {
  const report = rd('docs/security-audit-2026-04.md');
  const open = [...report.matchAll(/^\| (\d+) \| .*\| (\u2699|\u25CF) \|/gmu)].map((m) => Number(m[1]));
  assert.ok(open.length > 0, 'the report has no open rows; this block would assert nothing');
  for (const [p, re] of [['docs', /Smart Cyber Solutions<\/td>[\s\S]*?<\/tr>/], ['en/docs', /Smart Cyber Solutions<\/td>[\s\S]*?<\/tr>/]]) {
    const row = re.exec(pg(p))[0];
    for (const n of open) assert.match(row, new RegExp(`#${n}\\b`), `${p}: SCS row must name #${n}`);
  }
  // SECURITY.md says the same as the report.
  const sec = rd('SECURITY.md');
  for (const n of open) assert.match(sec, new RegExp(`^\\| ${n} \\| `, 'm'), `SECURITY.md open findings must list #${n}`);
});

test('SITE-49-A: every numbered block comment in site-claims.test.mjs is its register row, once', () => {
  const t = rd('tests/site-claims.test.mjs');
  const nums = [...t.matchAll(/^\/\/ (\d+)[a-z]? (?:──|--)/gm)].map((m) => Number(m[1]));
  const dup = nums.filter((n, i) => nums.indexOf(n) !== i);
  assert.deepEqual(dup, [], `duplicate block numbers: ${dup.join(', ')}`);
  const reg = rd('docs/site-claims.md');
  const rows = new Set([...reg.matchAll(/^\| (\d+) \|/gm)].map((m) => Number(m[1])));
  for (const n of nums) assert.ok(rows.has(n), `block ${n} has no register row`);
  // The blocks the register names by title carry the register number.
  const want = { 43: 'no page promises a signing order', 44: 'every TLS-terminating server block', 45: 'the ParaSend credential /privacy describes',
    46: 'the two legal facts', 47: 'the ParaSend read counts', 48: 'every ParaSend link lifetime', 49: 'the tools page only calls', 50: 'the sign-in and account pages' };
  for (const [n, title] of Object.entries(want)) {
    const at = t.indexOf(`test('${title}`);
    assert.ok(at > 0, title);
    const heads = [...t.slice(0, at).matchAll(/^\/\/ (\d+)[a-z]? (?:──|--)/gm)];
    assert.equal(Number(heads[heads.length - 1][1]), Number(n), `"${title}" sits under block ${heads[heads.length - 1][1]}, register row ${n}`);
  }
});

// Test met een vreemde, 13-10-2026 (prod bb9b7192): /en/send, /login en
// /en/login waren 404, en /send serveerde ingelogd /send.html, dat niet
// bestaat. Elk kort adres wijst nu naar de echte pagina, in beide confs die
// deploy/deploy-3.1.sh kent, en de pagina waar het naar wijst bestaat.
test('VREEMDE-06: /send, /en/send, /login en /en/login leiden naar een echte pagina', () => {
  const want = { '/send': '/parashare', '/en/send': '/en/parashare', '/login': '/auth/login', '/en/login': '/en/auth/login' };
  for (const conf of ['deploy/nginx-paramant-live.conf', 'deploy/nginx-paramant-public.conf']) {
    const txt = rd(conf).replace(/#.*$/gm, '');
    for (const [from, to] of Object.entries(want)) {
      const esc = from.replace(/\//g, '\\/');
      const m = new RegExp(`location = ${esc}\\s*\\{([^}]*)\\}`).exec(txt);
      assert.ok(m, `${conf}: geen location voor ${from}`);
      assert.match(m[1], new RegExp(`return 302 https://\\$host${to.replace(/\//g, '\\/')}\\$is_args\\$args;`), `${conf}: ${from} wijst niet naar ${to}`);
      assert.ok(exists(`frontend${to}.html`), `${to} bestaat niet als pagina`);
    }
    assert.doesNotMatch(txt, /try_files \/send\.html/, `${conf}: /send serveert nog een bestand dat niet bestaat`);
  }
});

// Test met een vreemde, 13-10-2026: de stap Ontvangers zei twee keer bijna
// hetzelfde ("Voeg iedereen toe die moet tekenen" boven de lijst, "Voeg de
// mensen toe die dit document moeten tekenen" in de lege lijst). Eén zin zegt
// wie erbij hoort; de lege lijst zegt alleen hoe u hem vult.
test('VREEMDE-09: de stap Ontvangers zegt maar een keer wie u toevoegt', () => {
  const flow = rd('frontend/sign-flow.js');
  for (const zin of [/Voeg de mensen toe die dit document/, /Add the people who need to sign this document/]) {
    assert.doesNotMatch(flow, zin, 'de lege lijst herhaalt de zin boven de lijst');
  }
  assert.match(flow, /Voeg iedereen toe die moet tekenen\./);
  assert.match(flow, /Nog niemand toegevoegd\. Klik op <strong>\+ Ontvanger toevoegen<\/strong>\./);
});

// Test met een vreemde, 13-10-2026: "Probeer het zelf" op de home gaat naar
// /sign?mode=invite, waar u alles klaarzet en pas bij versturen hoort dat dat
// een account vraagt. Elke plek met die knop zegt het nu vooraf, en de
// dialoog zei "voor het tekenen", terwijl een uitnodiging verstuurd wordt.
test('VREEMDE-07: elke Probeer het zelf naar /sign?mode=invite zegt dat versturen een gratis account vraagt', () => {
  const cases = [
    // 13-10-2026: de kop zegt het nu in een korte zin onder de knoppen, met hoofdletter.
    ['index', '/sign?mode=invite', /versturen doet u met een gratis account/i, /Voor het versturen maakt u een gratis account/],
    ['en/index', '/en/sign?mode=invite', /sending needs a free account/i, /To send it, you create a free one/],
  ];
  for (const [slug, href, hero, stage] of cases) {
    const html = pg(slug);
    const head = /<header class="wp-demo-hero">([\s\S]*?)<\/header>/.exec(html);
    assert.ok(head && head[1].includes(`href="${href}"`), `${slug}: de knop in de kop wijst niet meer naar ${href}`);
    assert.match(strip(head[1]), hero, `${slug}: de kop belooft proberen zonder te zeggen dat versturen een account vraagt`);
    const ends = [...html.matchAll(/<div class="wp-end">([\s\S]*?)<\/div>/g)].map((m) => m[1]).filter((b) => b.includes(`href="${href}"`));
    assert.ok(ends.length >= 1, `${slug}: geen dialoog met ${href}`);
    for (const b of ends) assert.match(strip(b), stage, `${slug}: de dialoog zegt niet dat versturen een account vraagt`);
  }
});

// Review op #588, 13-10-2026: de voorbeeldrijen op de home toonden "gisteren
// 16:42", een vorm die /dashboard nooit toont. Een document toont
// paramantDate.day ("12 oktober 2026"), een verzending paramantDate.localMoment
// ("13 oktober 2026 om 09:12 (CEST)"), zie js/dashboard.js en js/format-date.js.
// Daarna: een vaste datum veroudert, dus js/home-demo.js rekent elke datum bij
// het laden terug vanaf vandaag. Hier: de terugval zonder script heeft de
// notatie van het dashboard, en elke datum draagt data-wp-when, zodat hij niet
// vast in de markup blijft hangen. tests/home-demo-datum.test.mjs zet de klok
// en kijkt wat er werkelijk staat.
test('HOME-DATUM: de voorbeeldrijen op de home gebruiken de datumnotatie van het dashboard, gerekend vanaf vandaag', () => {
  const cases = [
    ['index', 'Gemaakt', 'Verstuurd', '[a-z]+', 'om'],
    ['en/index', 'Created', 'Sent', '[A-Z][a-z]+', 'at'],
  ];
  for (const [slug, made, sent, month, at] of cases) {
    const html = pg(slug);
    const rows = (cls) => [...html.matchAll(new RegExp(`<span class="${cls}"><strong>[^<]+<\\/strong><span>([\\s\\S]*?)<\\/span><\\/span>`, 'g'))].map((m) => m[1]);
    const docs = rows('dh-document-name'); const sends = rows('dh-send-name');
    assert.ok(docs.length >= 1 && sends.length >= 1, `${slug}: geen voorbeeldrijen gevonden`);
    for (const r of [...docs, ...sends]) {
      assert.match(r, /<time data-wp-when="(day|moment)" data-wp-ago="\d+"/, `${slug}: "${r}" staat vast in de markup; zonder data-wp-when veroudert hij`);
    }
    for (const d of docs.map((r) => strip(r).trim())) assert.match(d, new RegExp(`^${made} \\d{1,2} ${month} \\d{4}$`), `${slug}: "${d}" is niet de dagnotatie van het dashboard`);
    for (const d of sends.map((r) => strip(r).trim())) assert.match(d, new RegExp(`^${sent} \\d{1,2} ${month} \\d{4} ${at} \\d{2}:\\d{2} \\([A-Z]+\\)$`), `${slug}: "${d}" is niet de tijdnotatie van het dashboard`);
  }
  const js = fs.readFileSync(path.join(FE, 'js/home-demo.js'), 'utf8');
  assert.match(js, /f\.localMoment\(d\)/, 'home-demo.js schrijft een verzending niet meer met paramantDate.localMoment');
  assert.match(js, /f\.day\(d\)/, 'home-demo.js schrijft een document niet meer met paramantDate.day');
});
