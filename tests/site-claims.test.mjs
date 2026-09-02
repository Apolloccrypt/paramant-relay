// Every factual claim on the public site, pinned to the code that makes it true.
//
// The rule (Snoeiplan, 1 September 2026): a page may only exist if there is a
// test that fails when the page lies. This file is that test for the ten
// heaviest claims. Each block reads the number, name or constant from the
// source that enforces it and then checks the page says the same thing. A
// claim the repository cannot show is asserted to be ABSENT, which is what
// makes the page honest rather than merely consistent.
//
// The full inventory, including the claims not yet pinned, is in
// docs/site-claims.md.
//
// Node builtins only, so it runs in the "Root integration suites" job.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const page = (slug) => read(`frontend/${slug}.html`);

// What a visitor reads: no comments, no scripts, no styles. Comments routinely
// quote the very phrasing a test forbids.
function visible(html) {
  return html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/&rsquo;/g, "'").replace(/&middot;/g, '·').replace(/&mdash;/g, '—').replace(/&nbsp;/g, ' ');
}
// Same as seo-contract.test.mjs: everything under frontend/ that is public.
const PRIVATE = new Set([
  '404', 'account', 'admin', 'all-systems-go', 'claim', 'co-sign', 'dashboard',
  'developer', 'get', 'ontvang', 'request-key', 'setup', 'parashare', 'iot',
  'auth/backup', 'auth/login', 'auth/request-reset', 'auth/reset-confirm',
  'auth/setup', 'billing/checkout', 'signup/verified',
]);
function publicPages(dir = path.join(ROOT, 'frontend'), prefix = '') {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    if (e.isDirectory()) return ['node_modules', 'vendor', 'pkg'].includes(e.name) ? [] : publicPages(path.join(dir, e.name), `${prefix}${e.name}/`);
    if (!e.name.endsWith('.html')) return [];
    const slug = `${prefix}${e.name.slice(0, -5)}`;
    return PRIVATE.has(slug) ? [] : [slug];
  }).sort();
}
const WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten',
  'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen', 'twenty'];
const TENS = { 30: 'thirty', 40: 'forty', 50: 'fifty', 60: 'sixty' };
const word = (n) => (n <= 20 ? WORDS[n] : `${TENS[n - (n % 10)]}${n % 10 ? '-' + WORDS[n % 10] : ''}`);
const cap = (s) => s[0].toUpperCase() + s.slice(1);

// 1 ── The parameter sets. Site says ML-KEM-768 (FIPS 203) and ML-DSA-65
// (FIPS 204). The core registers exactly those two unconditionally.
test('the post-quantum parameter sets on the site are the ones the core registers', () => {
  const boot = read('relay/crypto/bootstrap.js').replace(/\/\/.*$/gm, '');
  // Everything registered before the extended-mode branch is what every relay
  // loads regardless of CRYPTO_MODE.
  const gate = boot.search(/if\s*\(\s*resolved\s*===\s*['"]extended['"]\s*\)/);
  assert.ok(gate > 0, 'bootstrap.js must gate the extended set on CRYPTO_MODE');
  const core = boot.slice(0, gate);
  assert.match(core, /registerKEM\(0x0002,\s*mlkem768\)/, 'core mode must register mlkem768');
  assert.match(core, /registerSig\(0x0002,\s*mldsa65\)/, 'core mode must register mldsa65');
  assert.equal((core.match(/register(KEM|Sig)\(/g) || []).length, 2, 'core mode registers exactly the two named on the site');
  const kem = /name:\s*["']([^"']+)["']/.exec(read('relay/crypto/impls/mlkem768.js'))[1];
  const sig = /name:\s*["']([^"']+)["']/.exec(read('relay/crypto/impls/mldsa65.js'))[1];
  assert.equal(kem, 'ML-KEM-768');
  assert.equal(sig, 'ML-DSA-65');

  const problems = [];
  const naming = { kem: [], sig: [] };
  for (const slug of publicPages()) {
    const text = visible(page(slug));
    if (/ML-KEM-\d+/.test(text)) { naming.kem.push(slug); if (!text.includes(kem)) problems.push(`${slug}: names an ML-KEM set but not ${kem}`); }
    if (/ML-DSA-\d+/.test(text)) { naming.sig.push(slug); if (!text.includes(sig)) problems.push(`${slug}: names an ML-DSA set but not ${sig}`); }
    if (/\b(Kyber|Dilithium)\b/.test(text)) problems.push(`${slug}: uses a pre-standard name (Kyber/Dilithium) instead of the FIPS name`);
  }
  // The promise has to be present, not merely consistent.
  for (const slug of ['index', 'security', 'pricing', 'press', 'privacy']) {
    if (!naming.kem.includes(slug)) problems.push(`${slug}: must name ${kem}`);
  }
  for (const slug of ['index', 'about', 'security', 'sign', 'verify']) {
    if (!naming.sig.includes(slug)) problems.push(`${slug}: must name ${sig}`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 2 ── "The relay loads 3 KEMs and 18 signatures" (security, crypto-agility).
// Measured on 2 September 2026: bootstrap.js registers 3 KEMs and 17
// signatures, and only in CRYPTO_MODE=extended; the default (.env.example)
// is core, which loads the two above. Both pages now say so.
test('the algorithm counts on the site are what bootstrap.js registers, and the mode caveat is stated', () => {
  const boot = read('relay/crypto/bootstrap.js').replace(/\/\/.*$/gm, '');
  const kems = (boot.match(/registerKEM\(/g) || []).length;
  const sigs = (boot.match(/registerSig\(/g) || []).length;
  assert.ok(kems > 0 && sigs > 0);
  const env = read('.env.example');
  assert.match(env, /^#\s*CRYPTO_MODE=core/m, '.env.example documents core as the default; if that changes, so must the pages');

  for (const slug of ['security', 'crypto-agility']) {
    const text = visible(page(slug)) + page(slug); // meta descriptions count too
    assert.match(text, new RegExp(`\\b${kems} KEMs\\b`), `${slug}: must state ${kems} KEMs`);
    assert.match(text, new RegExp(`\\b${sigs} signature`), `${slug}: must state ${sigs} signatures`);
    assert.doesNotMatch(text, /\d+ (KEMs|signatures)[^.]*loaded in production/i,
      `${slug}: must not claim the extended set is loaded in production; the default mode is core`);
    assert.match(text, /default core mode loads ML-KEM-768 and ML-DSA-65/,
      `${slug}: must say what the default mode actually loads`);
  }
});

// 3 ── The symmetric primitives: AES-256-GCM, HKDF-SHA256, SHA3-256, PBKDF2.
test('the symmetric primitives named on the site are the ones in the code', () => {
  assert.match(read('relay/lib/encryption.js'), /ALGO\s*=\s*['"]aes-256-gcm['"]/);
  const rs = read('crypto-wasm/src/lib.rs');
  assert.match(rs, /Aes256Gcm/, 'the WASM client must use AES-256-GCM');
  assert.match(rs, /Hkdf::<Sha256>/, 'the WASM client must derive with HKDF-SHA256');
  assert.match(read('relay/lib/ct-hash.js'), /createHash\(['"]sha3-256['"]\)/, 'the CT log must hash with SHA3-256');
  assert.match(read('frontend/sign-flow.js'), /sha3_256\(state\.doc\.bytes\)/, 'documents are hashed with SHA3-256 before signing');
  const vault = read('frontend/vault.js');
  assert.match(vault, /name:\s*['"]PBKDF2['"][^}]*hash:\s*['"]SHA-256['"]/, 'vault derives with PBKDF2-SHA256');
  assert.match(vault, /name:\s*['"]AES-GCM['"],\s*length:\s*256/, 'vault encrypts with AES-256-GCM');

  const sec = visible(page('security'));
  for (const s of ['AES-256-GCM', 'HKDF-SHA256', 'SHA3-256', 'ML-KEM-768']) assert.ok(sec.includes(s), `security: must name ${s}`);
  const priv = visible(page('privacy'));
  for (const s of ['AES-256-GCM', 'HKDF-SHA256']) assert.ok(priv.includes(s), `privacy: must name ${s}`);
  const v = visible(page('vault'));
  for (const s of ['AES-256-GCM', 'PBKDF2']) assert.ok(v.includes(s), `vault: must name ${s}`);
  for (const slug of ['sign', 'verify']) assert.ok(visible(page(slug)).includes('SHA3-256'), `${slug}: must name SHA3-256`);
});

// 4 ── "5 MB". relay.js MAX_BLOB defaults to 5242880; tiers.js mirrors it.
test('the 5 MB limit on the site is the relay default', () => {
  const m = /MAX_BLOB\s*=\s*parseInt\(process\.env\.MAX_BLOB\s*\|\|\s*'(\d+)'\)/.exec(read('relay/relay.js'));
  assert.ok(m, 'relay.js must define MAX_BLOB with a literal default');
  const mb = Number(m[1]) / (1024 * 1024);
  assert.equal(mb, 5);
  const tiers = read('relay/lib/tiers.js');
  for (const t of ['community', 'pro', 'business']) {
    const block = tiers.slice(tiers.indexOf(`${t}:`));
    assert.match(block, new RegExp(`file_mb:\\s*${mb}\\b`), `tiers.js ${t}.file_mb must be ${mb}`);
  }
  const problems = [];
  for (const slug of ['privacy', 'security', 'vs']) {
    if (!visible(page(slug)).includes(`${mb} MB`)) problems.push(`${slug}: must state the ${mb} MB block size`);
  }
  for (const slug of publicPages()) {
    for (const hit of visible(page(slug)).matchAll(/(\d+) MB (file limit|per file|file size limit)/g)) {
      if (Number(hit[1]) !== mb) problems.push(`${slug}: claims "${hit[0]}", relay default is ${mb} MB`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 5 ── Link expiry per tier: 1 hour / 24 hours / 7 days, from tiers.js.
test('link expiry per tier on pricing and privacy matches tiers.js', () => {
  const tiers = read('relay/lib/tiers.js');
  const ttl = (t) => {
    const block = tiers.slice(tiers.indexOf(`${t}:`));
    return Number(/view_ttl_ms:\s*([\d_]+)/.exec(block)[1].replace(/_/g, ''));
  };
  const hours = (ms) => ms / 3_600_000;
  const free = hours(ttl('community')), pro = hours(ttl('pro')), ent = hours(ttl('enterprise'));
  assert.equal(free, 1); assert.equal(pro, 24); assert.equal(ent, 7 * 24);
  const pricing = visible(page('pricing'));
  assert.ok(pricing.includes(`${free} hour link expiry`), `pricing: Free must say ${free} hour link expiry`);
  assert.ok(pricing.includes(`${pro} hour link expiry`), `pricing: Pro must say ${pro} hour link expiry`);
  assert.ok(pricing.includes(`${ent / 24} day link expiry`), `pricing: Enterprise must say ${ent / 24} day link expiry`);
  const priv = visible(page('privacy'));
  assert.ok(priv.includes(`${free} hour for Free, ${pro} hours for Pro, ${ent / 24} days for Enterprise`), 'privacy: retention line must match tiers.js');
  assert.ok(priv.includes(`Free tier blobs expire after ${free} hour maximum. Pro blobs after ${pro} hours. Enterprise blobs after ${ent / 24} days.`), 'privacy: expiry paragraph must match tiers.js');
});

// 6 ── The authentication numbers on the security page. Session cookie
// Max-Age, TOTP step, and the two login rate limits all live in code. The
// sentence "after ten consecutive failures an account locks for thirty
// minutes" had no code behind it (searched 2 September 2026) and is gone.
test('the authentication numbers on the security page are the ones the code enforces', () => {
  const srv = read('admin/server.js');
  const sec = visible(page('security'));

  const maxAge = Number(/paramant_user_session=\$\{token\}[^`]*Max-Age=(\d+)/.exec(srv)[1]);
  assert.equal(maxAge, 3600);
  assert.match(sec, /Sessions last one hour/);

  const step = Number(/Math\.floor\(now \/ 1000 \/ (\d+)\)/.exec(read('relay/lib/totp.js'))[1]);
  assert.equal(step, 30);
  assert.match(sec, /TOTP codes expire thirty seconds after issue/);

  // /auth/login: per-IP fixed window.
  const fn = srv.slice(srv.indexOf('function checkLoginRateLimit'));
  const perIp = Number(/b\.count >= (\d+)/.exec(fn)[1]);
  const winMin = Number(/(\d+) \* 60_000/.exec(fn)[1]);
  // /api/user/login: per-IP and per-email counters in Redis with a TTL.
  const login = srv.slice(srv.indexOf('paramant:user:ratelimit:ip:'));
  const ttlSec = Number(/expire\(ipKey,\s*(\d+)\)/.exec(login)[1]);
  const lim = /ipCount > (\d+) \|\| emailCount > (\d+)/.exec(login);
  assert.equal(Number(lim[1]), perIp, 'both login paths must cap the same per-IP count');
  assert.equal(ttlSec, winMin * 60, 'both login paths must use the same window');
  const perEmail = Number(lim[2]);
  assert.match(sec, new RegExp(`rate-limited to ${WORDS[perIp]} per IP per ${WORDS[winMin]} minutes and ${WORDS[perEmail]} per email per ${WORDS[winMin]} minutes`),
    `security: login limits must read ${perIp}/IP and ${perEmail}/email per ${winMin} minutes`);

  assert.doesNotMatch(srv, /consecutive failures|lockout_minutes|LOCKOUT_MS/i, 'no login lockout is implemented; if one is added, put the sentence back with its numbers');
  assert.doesNotMatch(sec, /consecutive failures|account locks/i, 'security: must not promise an account lockout the code does not implement');
});

// 7 ── The audits. One table on /docs#audits is the source; press, trust and
// the DPA quote it. Williams' summary line in docs/security-audit-2026-04.md
// must agree with that row. Nobody says "fully resolved" while that same
// document still carries findings marked in-progress or open.
test('the audit numbers on press, trust and the DPA match the audit table on /docs', () => {
  const docs = page('docs');
  assert.match(docs, /<h2 id="audits">/, '/docs#audits must exist: trust and the DPA link to it');
  const table = docs.slice(docs.indexOf('<h2 id="audits">'), docs.indexOf('</table>', docs.indexOf('<h2 id="audits">')));
  const rows = [...table.matchAll(/<tr><td>(Apr 2026)<\/td><td>[^<]*<\/td><td>([^<]*)<\/td>/g)];
  const audits = rows.length;
  let total = 0, critical = 0;
  for (const [, , findings] of rows) {
    const m = /(\d+) total/.exec(findings);
    if (m) { total += Number(m[1]); continue; }
    const parts = [...findings.matchAll(/(\d+)([CHML])/g)];
    assert.ok(parts.length, `unreadable findings cell: ${findings}`);
    for (const [, n, sev] of parts) { total += Number(n); if (sev === 'C') critical += Number(n); }
  }
  assert.equal(audits, 3); assert.equal(total, 40); assert.equal(critical, 4);

  const md = read('docs/security-audit-2026-04.md');
  const summary = /\*\*Summary:\*\*\s*(\d+) critical · (\d+) high · (\d+) medium · (\d+) low/.exec(md);
  assert.ok(summary, 'the April 2026 audit document must carry its summary line');
  const williamsRow = rows.find((r) => /C ·/.test(r[2]))[2];
  assert.equal(williamsRow.replace(/\s/g, ''), `${summary[1]}C·${summary[2]}H·${summary[3]}M·${summary[4]}L`, 'the /docs row for Williams must equal the summary in docs/security-audit-2026-04.md');

  const press = visible(page('press'));
  assert.match(press, new RegExp(`${cap(word(total))} findings across ${word(audits)} audits, including ${critical} critical`),
    `press: must read "${cap(word(total))} findings across ${word(audits)} audits, including ${critical} critical"`);
  assert.match(visible(page('trust')), new RegExp(`${cap(word(audits))} external security audits in April 2026`));

  // Finding rows only, not the legend that explains the symbols.
  const unresolved = (md.match(/^\| \S+ \|.*\| [⚙●] \|/gm) || []).length;
  if (unresolved > 0) {
    for (const slug of ['press', 'trust', 'dpa', 'security', 'index']) {
      assert.doesNotMatch(visible(page(slug)), /fully resolved|all findings (were )?resolved/i,
        `${slug}: docs/security-audit-2026-04.md still lists ${unresolved} finding(s) in progress or open`);
    }
  }
  for (const slug of ['trust', 'dpa']) {
    assert.match(page(slug), /href="\/docs#audits"/, `${slug}: the audit link must point at the table that exists`);
  }
});

// 8 ── The SLA. Pricing quotes the figure the SLA page commits to, and the
// measurement paragraph describes the check that exists: the hourly
// product-heartbeat workflow. There is no 60-second multi-location probe
// and the CT log holds no uptime data (checked 2 September 2026).
test('the SLA figures are consistent across pages and the measurement described exists', () => {
  const sla = page('sla');
  const ent = /<div class="tier">Enterprise<\/div>\s*<div class="uptime">([\d.]+%)<\/div>/.exec(sla)[1];
  const pricing = visible(page('pricing'));
  const quoted = [...pricing.matchAll(/(\d{2}\.\d{1,2}%) SLA|SLA (\d{2}\.\d{1,2}%)/g)].map((m) => m[1] || m[2]);
  assert.ok(quoted.length >= 2, 'pricing must quote the Enterprise SLA');
  for (const q of quoted) assert.equal(q, ent, `pricing quotes ${q}, the SLA page commits to ${ent}`);

  const text = visible(sla);
  assert.doesNotMatch(text, /every 60 seconds|multiple EU locations|three consecutive checks/, 'sla: describes a probe that does not exist');
  assert.doesNotMatch(text, /uptime data is published in the Certificate Transparency log/i, 'sla: the CT log holds key and transfer commitments, not uptime');
  const wf = read('.github/workflows/product-heartbeat.yml');
  assert.match(wf, /cron:\s*'\d+ \* \* \* \*'/, 'product-heartbeat must run hourly for the SLA text to hold');
  assert.match(text, /runs hourly from the product-heartbeat workflow/);
  assert.match(text, /measured from your (own )?browser/);
});

// 9 ── IP logging. The repository carries no log-rotation config, so the page
// may not promise a retention period.
test('the IP-logging row promises no retention the repository cannot show', () => {
  const rotation = fs.readdirSync(path.join(ROOT, 'deploy')).filter((f) => /logrotate/i.test(f));
  const sec = visible(page('security'));
  if (rotation.length === 0) {
    assert.doesNotMatch(sec, /Retention:\s*\d+ days/, 'security: no retention config in deploy/, so no retention number on the page');
    assert.match(sec, /No separate retention period is promised/);
  }
  assert.match(sec, /Not linked to transfer content/);
});

// 10 ── "10 encrypted CLI tools" on the homepage is the developer catalogue.
test('the CLI tool count on the homepage is the size of the developer catalogue', () => {
  const n = (read('admin/lib/developer-tools.js').match(/^\s*\{ name: 'paramant-/gm) || []).length;
  assert.ok(n > 0);
  const html = page('index');
  assert.ok(html.includes(`${n} encrypted CLI tools`), `index: must say "${n} encrypted CLI tools"`);
  assert.ok(html.includes(`${cap(WORDS[n])} encrypted CLI tools in total`), `index: the terminal aria-label must count ${cap(WORDS[n])}`);
});
