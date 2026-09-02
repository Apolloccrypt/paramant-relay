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
// Every .html under frontend/, subdirectories included, so a claim cannot hide
// on a page nobody thought to list.
const allPages = (dir = path.join(ROOT, 'frontend'), prefix = '') =>
  fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    if (e.isDirectory()) return ['node_modules', 'vendor'].includes(e.name) ? [] : allPages(path.join(dir, e.name), `${prefix}${e.name}/`);
    return e.isFile() && e.name.endsWith('.html') ? [`${prefix}${e.name.slice(0, -5)}`] : [];
  });

// Comments out, strings intact. The obvious /\/\/.*$/gm cuts a line at the
// first "//", which inside 'https://relay.paramant.app/health' deletes the
// very call test 8 asserts is absent: a real health check written as a full
// URL would strip away and the assertion would pass on nothing. So walk the
// source instead. String, template and regex literals are copied through
// untouched; line and block comments are dropped. Node builtins only, so no
// parser dependency.
const REGEX_AFTER_CHAR = /[([{,;:=!&|?+\-*%~^<>]$/;
const REGEX_AFTER_WORD = /\b(return|typeof|instanceof|in|of|new|delete|void|do|else|case|yield|await)$/;
function endOfQuoted(src, start) {
  const quote = src[start];
  let i = start + 1;
  while (i < src.length) {
    const c = src[i];
    if (c === '\\') { i += 2; continue; }
    if (c === quote) return i + 1;
    if (quote === '`' && c === '$' && src[i + 1] === '{') { i = endOfHole(src, i + 2); continue; }
    if (quote !== '`' && c === '\n') return i; // unterminated: do not run away
    i += 1;
  }
  return i;
}
function endOfHole(src, start) { // start sits just after the "${"
  let depth = 1;
  let i = start;
  while (i < src.length && depth > 0) {
    const c = src[i];
    if (c === '"' || c === "'" || c === '`') { i = endOfQuoted(src, i); continue; }
    if (c === '{') depth += 1;
    else if (c === '}') depth -= 1;
    i += 1;
  }
  return i;
}
function endOfRegex(src, start) {
  let i = start + 1;
  let inClass = false;
  while (i < src.length) {
    const c = src[i];
    if (c === '\\') { i += 2; continue; }
    if (c === '\n') return start + 1; // not a regex after all: emit the slash
    if (inClass) { if (c === ']') inClass = false; }
    else if (c === '[') inClass = true;
    else if (c === '/') { i += 1; while (i < src.length && /[a-z]/i.test(src[i])) i += 1; return i; }
    i += 1;
  }
  return i;
}
function stripJsComments(src) {
  let out = '';
  let tail = ''; // the last few emitted characters, for the regex heuristic
  let i = 0;
  const emit = (s) => { out += s; tail = (tail + s).slice(-16); };
  while (i < src.length) {
    const two = src.slice(i, i + 2);
    if (two === '//') { while (i < src.length && src[i] !== '\n') i += 1; continue; }
    if (two === '/*') { const end = src.indexOf('*/', i + 2); i = end === -1 ? src.length : end + 2; emit(' '); continue; }
    const c = src[i];
    if (c === '"' || c === "'" || c === '`') { const j = endOfQuoted(src, i); emit(src.slice(i, j)); i = j; continue; }
    if (c === '/') {
      const before = tail.replace(/\s+$/, '');
      if (before === '' || REGEX_AFTER_CHAR.test(before) || REGEX_AFTER_WORD.test(before)) {
        const j = endOfRegex(src, i); emit(src.slice(i, j)); i = j; continue;
      }
    }
    emit(c);
    i += 1;
  }
  return out;
}

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
  const boot = stripJsComments(read('relay/crypto/bootstrap.js'));
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
  const boot = stripJsComments(read('relay/crypto/bootstrap.js'));
  const kems = (boot.match(/registerKEM\(/g) || []).length;
  const sigs = (boot.match(/registerSig\(/g) || []).length;
  assert.ok(kems > 0 && sigs > 0);
  const env = read('.env.example');
  assert.match(env, /^#\s*CRYPTO_MODE=core/m, '.env.example documents core as the default; if that changes, so must the pages');

  for (const slug of ['security', 'crypto-agility']) {
    const text = visible(page(slug)) + page(slug); // meta descriptions count too
    assert.match(text, new RegExp(`\\b${kems} KEMs\\b`), `${slug}: must state ${kems} KEMs`);
    assert.match(text, new RegExp(`\\b${sigs} signature`), `${slug}: must state ${sigs} signatures`);
    // A stale count elsewhere on the same page is the failure this exists for.
    for (const m of text.matchAll(/\b(\d+) (KEMs|signatures?)\b/g)) {
      const want = m[2] === 'KEMs' ? kems : sigs;
      assert.equal(Number(m[1]), want, `${slug}: says "${m[0]}", bootstrap.js registers ${want}`);
    }
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
  assert.ok(pricing.includes(`${free} hour link expiry`), `pricing: Community must say ${free} hour link expiry`);
  assert.ok(pricing.includes(`${pro} hour link expiry`), `pricing: Pro must say ${pro} hour link expiry`);
  assert.ok(pricing.includes(`${ent / 24} day link expiry`), `pricing: Enterprise must say ${ent / 24} day link expiry`);
  const priv = visible(page('privacy'));
  assert.ok(priv.includes(`${free} hour for Community, ${pro} hours for Pro, ${ent / 24} days for Enterprise`), 'privacy: retention line must match tiers.js');
  assert.ok(priv.includes(`Community plan blobs expire after ${free} hour maximum. Pro blobs after ${pro} hours. Enterprise blobs after ${ent / 24} days.`), 'privacy: expiry paragraph must match tiers.js');
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
// measurement paragraph describes the checks that exist and nothing more.
// What exists (read on 2 September 2026, after the heartbeat rebuild): the
// hourly heartbeat workflow loads paramant.app in a browser and pushes a real
// transfer and a real signature through relay.paramant.app, keeping an evidence
// file per step. Before the rebuild the transfer and signature clauses were
// aspirational: both canaries skipped for want of a secret and reported green.
//
// The run also calls GET /health and the deep readiness check on the main
// relay, and reaches all six hosts to confirm one retired route stays refused,
// and the page mentions neither. That is under-promising, which is safe, and it
// is a deliberate follow-up: the paragraph gets rewritten once the monitor has
// actually run, which needs two secrets that do not exist yet.
//
// The only thing that polls /health on all five relays is /status, from the
// visitor's browser. There is still no 60-second multi-location probe and the
// CT log still holds no uptime data.
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

  // The hourly workflow: what it runs, against what, and whether it is switched
  // on. It moved out of product-heartbeat.yml on 2026-09-02, which is now only
  // the pull-request gate, so the page may no longer name that file.
  const wf = read('.github/workflows/heartbeat.yml');
  assert.match(wf, /cron:\s*'\d+ \* \* \* \*'/, 'the heartbeat must be scheduled hourly');
  assert.match(wf, /PARAMANT_BASE_URL:\s*https:\/\/paramant\.app/, 'the hourly job must target paramant.app');
  assert.match(wf, /PARAMANT_RELAY_URL:\s*https:\/\/relay\.paramant\.app/, 'the hourly job must target the main relay');
  // The measurement paragraph with the markup taken out, so a regex is matching
  // sentences rather than code tags.
  const measure = text.replace(/<[^>]+>/g, '');
  assert.match(measure, /heartbeat workflow/,
    'the page must name the workflow that actually holds the schedule');
  assert.doesNotMatch(measure, /product-heartbeat workflow/,
    'product-heartbeat.yml has no schedule any more; naming it on /sla is a false claim');

  // Whether it is running at all. The job is gated on a repository variable
  // until its two canary secrets exist, so until that gate goes the page must
  // say the check is switched off, and afterwards it must stop saying so. Both
  // directions are pinned, which is what forces the follow-up rewrite to happen
  // rather than being remembered.
  const gated = /vars\.HEARTBEAT_ENABLED\s*==\s*'true'/.test(wf);
  if (gated) {
    assert.match(measure, /runs hourly once enabled/,
      'the hourly job is gated off, so the page must not claim it is running');
    assert.match(measure, /switched off until its credentials are in place/,
      'the page must say why it is not running');
    assert.doesNotMatch(measure, /workflow[^.]*runs hourly and exercises/,
      'the page describes a monitor that is switched off as though it were running');
  } else {
    assert.doesNotMatch(measure, /runs hourly once enabled|switched off until/,
      'the gate is gone, so the page must stop saying the check is switched off');
  }

  // Each clause of the sentence, pinned to the code that makes it true. These
  // used to point at tests/transfer-canary.test.mjs and
  // tests/parasign-canary.test.mjs, which is how the page came to promise an
  // hourly signature check that had never signed anything: both suites skipped
  // for want of a secret and reported green, and this test only ever checked
  // that the workflow named them.
  assert.ok(wf.includes('node --test tests/product-heartbeat.test.mjs'),
    'the page promises a page load in a real browser');
  assert.match(wf, /node scripts\/heartbeat\/run\.mjs/, 'the page promises a transfer and a signature');

  const parasend = stripJsComments(read('scripts/heartbeat/parasend.mjs'));
  assert.match(parasend, /v2\/anon-inbound/, 'the page promises a transfer sent');
  assert.match(parasend, /v2\/dl\//, 'the page promises that transfer read back');

  const parasign = stripJsComments(read('scripts/heartbeat/parasign.mjs'));
  assert.match(parasign, /\/sign`/, 'the page promises a document signed');
  assert.match(parasign, /mldsa\.verify/, 'the page promises that signature verified');
  // And verified for real, not by trusting a 200. The negative check is what
  // separates the two, so it is pinned by name.
  assert.match(parasign, /bad_signature/,
    'the run must still prove the relay refuses a signature that does not verify');

  // "A run that fails opens an issue in the repository." That sentence is a
  // promise about behaviour, so it is pinned to the step that keeps it rather
  // than to the workflow merely existing.
  assert.match(measure, /A run that fails opens an issue in the repository/);
  const issueStep = wf.slice(wf.indexOf('if: failure()'));
  assert.ok(wf.includes('if: failure()'), 'the workflow must have a step that runs only on failure');
  assert.match(issueStep, /issues\.create/, 'that step must actually open an issue');
  assert.match(wf, /issues:\s*write/, 'and the job must be allowed to');

  // The four sector relays, pinned to what surface.mjs actually does. The
  // earlier version of this block exempted the sector hosts as long as no
  // PRODUCT step named them, which let the sentence on /sla stay while the
  // heartbeat POSTed to all four and went red if one did not answer. There is
  // no exemption now: the code must reach them, and the page must say both
  // halves of why.
  const surface = stripJsComments(read('scripts/heartbeat/surface.mjs'));
  for (const sector of ['health', 'legal', 'finance', 'iot']) {
    assert.ok(surface.includes(`${sector}.paramant.app`),
      `the run no longer reaches ${sector}.paramant.app; the SLA measurement text must say so`);
  }
  assert.match(surface, /paraid\/issue-/,
    'the sector relays are reached for the ParaID deny check; if that changed, so must the page');
  assert.match(measure, /The four sector relays \(health, legal, finance, IoT\) are reached only to confirm that a retired route stays refused there, so their uptime is not measured/,
    'the page must say both what the run does at those hosts and what it does not measure');

  // A step that records no evidence must fail. It is the mechanism that makes
  // the hourly green tick mean anything at all, so it is pinned here too: the
  // previous version of this paragraph was true of a workflow whose ParaSign
  // step passed in 0.68 seconds without sending a packet.
  assert.match(stripJsComments(read('scripts/heartbeat/lib.mjs')), /produced no proofs/,
    'a heartbeat step that observes nothing must not report success');
  assert.ok(wf.includes('upload-artifact'), 'the evidence must be kept with the run');

  // /status: the one place that polls GET /health, on every sector, from the
  // browser.
  const status = read('frontend/js/status.inline1.js');
  const sectors = (status.match(/^\s*\{ id: '[a-z]+',\s*label:/gm) || []).length;
  assert.equal(sectors, 5, 'status.inline1.js must list the five relays');
  assert.match(status, /fetch\(s\.url \+ '\/health'/, 'status.inline1.js must fetch GET /health per sector');
  assert.match(page('status'), /status\.inline1\.js/, '/status must load that script');

  // The paragraph may only describe those two things, and it may not
  // over-promise. Under-promising is safe and is currently the case: the
  // rebuilt hourly run also calls GET /health and reaches all six hosts for a
  // deny check, and the page does not mention either. That gap is a follow-up
  // to be made once the monitor has actually run; a page that describes a
  // monitor which has never executed is the failure mode this whole file is
  // here to prevent.
  const plain = measure;
  assert.doesNotMatch(plain, /automated HTTP health checks/i,
    'sla: /status is a reading taken in one visitor browser, not a health-check monitor');
  assert.match(plain, /heartbeat workflow/);
  assert.match(plain, /main relay \(relay\.paramant\.app\)/);
  assert.match(plain, /a transfer sent and read back, a document signed and its signature verified/);
  assert.match(plain, new RegExp(`fetches GET /health on all ${word(sectors)} relays from your own browser`));
  assert.match(visible(sla), /measured from your (own )?browser/);
});

// 9 ── IP logging. The deploy configuration in the repository switches nginx
// access logging off on every public server block, and there is no
// log-rotation config, so the page may neither describe access logs as a
// fact of life nor promise a retention period. Whether the server matches
// deploy/nginx-paramant-live.conf is not something this repository can show
// (see docs/site-claims.md).
test('the IP-logging row says what the deploy configuration does and promises no retention', () => {
  const conf = read('deploy/nginx-paramant-live.conf').replace(/#.*$/gm, '');
  assert.doesNotMatch(conf, /access_log\s+(?!off;)/, 'nginx-paramant-live.conf now writes an access log; rewrite the IP-logging row on /security');
  // Every block that serves the docroot or proxies to a relay or the admin.
  // (The last block only fronts the Outlook add-in via an external host.)
  const blocks = conf.split(/^server \{/m).slice(1)
    .filter((b) => /root \/home\/paramant|proxy_pass http:\/\/127\.0\.0\.1:/.test(b));
  assert.ok(blocks.length >= 6, 'nginx-paramant-live.conf must carry the site and relay server blocks');
  for (const b of blocks) {
    assert.match(b, /^\s*access_log off;/m, `the server block on ${/listen\s+([^;]+)/.exec(b)?.[1]} logs requests; rewrite the IP-logging row on /security`);
  }
  const rotation = fs.readdirSync(path.join(ROOT, 'deploy')).filter((f) => /logrotate/i.test(f));
  const sec = visible(page('security'));
  const row = /IP logging<\/td><td>(.*?)<\/td>/s.exec(page('security'))?.[1] || '';
  assert.match(row, /access_log off<\/code> on every server block that serves the site and the relays in <code>deploy\/nginx-paramant-live\.conf/,
    'security: the IP-logging row must cite the config that switches logging off');
  assert.doesNotMatch(sec, /Nginx access logs, for|follow the server's log rotation/, 'security: must not describe access logs as existing');
  if (rotation.length === 0) {
    assert.doesNotMatch(sec, /Retention:\s*\d+ days/, 'security: no retention config in deploy/, so no retention number on the page');
    assert.match(sec, /No separate retention period is promised/);
  }
  assert.match(sec, /Not linked to transfer content/);
});

// 10 ── "10 encrypted CLI tools" on the homepage is the developer catalogue.
test('any CLI tool count the site states is the size of the developer catalogue', () => {
  const n = (read('admin/lib/developer-tools.js').match(/^\s*\{ name: 'paramant-/gm) || []).length;
  assert.ok(n > 0);
  // Every page, not just the homepage: the claim used to live there and was
  // removed with the rest of the developer pitch, because paramant-solutions is
  // private and a visitor cannot actually get the tools. The invariant is not
  // "a page must say this" but "no page may say it wrong".
  const wrong = [];
  for (const slug of allPages()) {
    const html = read(`frontend/${slug}.html`);
    // Broadened: the old regex only matched "encrypted CLI tools", the exact
    // phrasing of a claim this PR removed, so it matched nothing anywhere and
    // guarded nothing. It now catches any count of CLI or command-line tools,
    // however the sentence is worded.
    //
    // Zero matches is ALLOWED and is the state today. The invariant is "if a
    // page states a count, the count is right", not "some page must state one":
    // the "10 encrypted CLI tools" claim came off the homepage on purpose,
    // because paramant-solutions is private and a visitor cannot obtain the
    // tools (July 2026 claims audit). Requiring the sentence to exist would
    // force an unobtainable claim back onto the site.
    // A COUNT is a numeral or a number word. "SDKs and CLI tools" states no
    // count and is not this test's business.
    const COUNT = `\\d+|${WORDS.join('|')}`;
    for (const m of html.matchAll(new RegExp(`(${COUNT})(?:\\s+\\w+)? (?:CLI|command-line) tools\\b`, 'gi'))) {
      const stated = m[1];
      const ok = stated === String(n) || stated.toLowerCase() === WORDS[n];
      if (!ok) wrong.push(`${slug}: "${m[0]}" but the catalogue holds ${n}`);
    }
  }
  assert.deepEqual(wrong, [], `\n  ${wrong.join('\n  ')}\n`);
});

// 11 ── What the free Community plan actually gives you.
//
// The homepage, the docs FAQ and the API reference all sold Community as "10
// uploads per hour". That number is ANON_RATE_PER_HOUR, the per-IP ceiling on
// POST /v2/anon-inbound (relay.js), an endpoint deprecated 2026-05-28 with a
// sunset of 31 December 2026. It was never the limit of a logged-in Community
// account. The real caps live in relay/lib/tiers.js and are enforced in
// relay.js: transfers_month via the 402 monthly_transfer_quota_reached gate,
// file_mb via the 413 "Max 5MB" check. So the pages read the tier row.
test('the Community plan limits on the site are the ones tiers.js declares', () => {
  const tiers = read('relay/lib/tiers.js');
  const block = tiers.slice(tiers.indexOf('community:'), tiers.indexOf('pro:'));
  const num = (dim) => {
    const m = new RegExp(`${dim}:\\s*([\\d_]+)`).exec(block);
    assert.ok(m, `tiers.js community.${dim} must be a literal number`);
    return Number(m[1].replace(/_/g, ''));
  };
  const transfers = num('transfers_month');
  const mb = num('file_mb');

  // The quota gate and the size check must still be the things that enforce
  // them, or the pages would be pinned to a constant nobody reads.
  const relay = read('relay/relay.js');
  assert.match(relay, /monthly_transfer_quota_reached/, 'relay.js must enforce transfers_month');
  assert.match(relay, /dimension:\s*'transfers_month'/, 'relay.js must decline on the transfers_month dimension');
  assert.match(relay, /Max \$\{Math\.round\(planMaxSize\/1048576\)\}MB/, 'relay.js must enforce the per-file size cap');

  const problems = [];
  const says = (where, text, phrase) => { if (!text.includes(phrase)) problems.push(`${where}: must state "${phrase}"`); };
  says('index', visible(page('index')), `${transfers} transfers a month`);
  says('index', visible(page('index')), `${mb} MB per file`);
  says('docs', visible(page('docs')), `${transfers} transfers a month`);
  says('docs', visible(page('docs')), `${mb} MB per file`);
  const apiMd = read('frontend/docs/api.md');
  says('docs/api.md', apiMd, `${transfers} transfers a month`);
  says('docs/api.md', apiMd, `${mb} MB per file`);

  // And no page may go back to selling the retired anonymous rate as a plan
  // limit. Per-MINUTE claims are out of scope here: those are nginx and API
  // rate limits with their own source (nginx-selfhost.conf, the envelope
  // create limiter), not the tier table.
  //
  // parasign and parasend carry the same stale sentence and are corrected in
  // their own PR (#339). Drop them from this list once that lands; the
  // exclusion is the only reason this scan is not global.
  //
  // pricing came off this list in #336: its Community card now names the two
  // limits the relay enforces (transfers_month and file_mb out of tiers.js,
  // refused with 402 and 413) instead of the per-IP rate on the deprecated
  // /v2/anon-inbound, and relay/test/pricing-page.test.js reads both figures
  // out of tiers.js so they cannot drift back.
  const DEFERRED = new Set(['parasign', 'parasend']);
  for (const slug of publicPages()) {
    if (DEFERRED.has(slug)) continue;
    for (const m of visible(page(slug)).matchAll(/\d+\s*uploads?\s*(?:\/|\s+(?:per|an|a)\s+)(?:hour|day)/gi)) {
      problems.push(`${slug}: claims "${m[0]}", which is the retired /v2/anon-inbound rate, not a tier limit`);
    }
  }
  for (const m of apiMd.matchAll(/\d+\s*uploads?\s*(?:\/|\s+(?:per|an|a)\s+)(?:hour|day)/gi)) {
    problems.push(`docs/api.md: claims "${m[0]}", which is the retired /v2/anon-inbound rate, not a tier limit`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 12 ── The free-versus-paid block on /about. It is the block a buyer reads to
// decide, and it repeats numbers that live on /pricing: signature allowance,
// link expiry, read count, device count, the Enterprise SLA. Nothing pinned it,
// so /about could drift away from /pricing (or be edited outright) and every
// test stayed green. This reads each number out of the /pricing tier card that
// owns it and requires /about to say the same.
test('the tier block on /about repeats the numbers /pricing charges for', () => {
  const pricing = page('pricing');
  const about = page('about');

  // The two product blocks, split on their own headings, then the tier cards
  // inside each one, keyed by the tier name /pricing prints. #336 renamed both
  // headings and put ParaSign first, so the split finds the headings by their
  // product prefix and orders them by position rather than assuming either.
  const HEAD = /<h3[^>]*>(ParaSign|ParaSend)\s*(?:&middot;|\u00b7)[^<]*<\/h3>/g;
  const marks = [...pricing.matchAll(HEAD)].map((m) => ({ product: m[1], at: m.index }));
  assert.equal(marks.length, 2,
    `pricing.html must carry one heading per product, found ${marks.length}`);
  const section = (product) => {
    const i = marks.findIndex((m) => m.product === product);
    assert.notEqual(i, -1, `pricing.html no longer has a ${product} block`);
    return pricing.slice(marks[i].at, i + 1 < marks.length ? marks[i + 1].at : undefined);
  };
  const tiers = (html) => {
    const out = {};
    for (const card of html.split('class="tier-card').slice(1)) {
      const name = /<div class="tier-name">([^<]+)</.exec(card)?.[1];
      if (name) out[name] = card;
    }
    return out;
  };
  const send = tiers(section('ParaSend'));
  const sign = tiers(section('ParaSign'));
  // The free tier is called Community on /pricing since #328, and the guide
  // (docs/brand/messaging.md section 3) makes that name the rule rather than a
  // preference. /about has to use the same word or a reader cannot find the
  // card the sentence is about.
  for (const [label, set, names] of [['ParaSend', send, ['Community', 'Pro', 'Enterprise']],
                                     ['ParaSign', sign, ['Community', 'Pro', 'Business', 'Enterprise']]]) {
    for (const n of names) assert.ok(set[n], `pricing.html no longer has a ${label} ${n} tier`);
  }

  // Each fact is a phrase lifted WHOLE out of the /pricing card that owns it,
  // not a number plus a unit this file spells itself. #359 reworded "2
  // signatures per month" to "2 signatures a month" and a hand-spelled unit
  // went stale on a rewording that changed no number at all.
  const phrase = (card, re, what) => {
    const m = re.exec(card);
    assert.ok(m, `pricing.html no longer states ${what}`);
    return m[1].trim();
  };
  const facts = [
    [phrase(sign.Community, /<li>(\d+ signatures? (?:a|per) month)<\/li>/, 'the ParaSign Community signature allowance'), 'ParaSign Community'],
    [phrase(send.Community, /<li>(\d+ hour link expiry)<\/li>/, 'the ParaSend Community link expiry'), 'ParaSend Community'],
    [phrase(send.Pro, /<li>(\d+ hour link expiry)<\/li>/, 'the ParaSend Pro link expiry'), 'ParaSend Pro'],
    [phrase(send.Pro, /<li>(Up to \d+ reads per link)<\/li>/, 'the ParaSend Pro read limit'), 'ParaSend Pro'],
    [phrase(send.Pro, /<li>(Up to \d+ registered devices)<\/li>/, 'the ParaSend Pro device limit'), 'ParaSend Pro'],
    [phrase(send.Enterprise, /<li>SLA ([\d.]+%),/, 'the ParaSend Enterprise SLA'), 'ParaSend Enterprise'],
  ];
  for (const [expected, tier] of facts) {
    assert.ok(about.toLowerCase().includes(expected.toLowerCase()),
      `about: the ${tier} line must say "${expected}", because that is what pricing.html sells`);
  }

  // Free means free, in the same two words on both pages.
  assert.match(sign.Community, /<div class="tier-price">&euro;0<\/div>/);
  assert.match(send.Community, /<div class="tier-price">&euro;0<\/div>/);
  assert.ok((about.match(/&euro;0, forever/g) || []).length >= 2,
    'about: both free tiers must be named as costing &euro;0, forever');
  assert.match(about, /No card required/,
    'about: the free tier must say no card is required, as pricing.html does');

  // And the paid tiers are named the way /pricing names them, so a reader can
  // find the card the sentence is about.
  for (const name of ['ParaSign Community', 'ParaSend Community',
                      'ParaSign Pro', 'ParaSign Business', 'ParaSign Enterprise',
                      'ParaSend Pro', 'ParaSend Enterprise']) {
    assert.ok(about.includes(name), `about: the tier block must name ${name} the way /pricing does`);
  }
  // Scoped to /about in the first version of this check, which is exactly how
  // security.html kept "ParaSign Free and ParaSend Free cost &euro;0" through a
  // review. The three pages of this round are checked together; the sitewide
  // sweep lives in tests/ui-truthfulness.test.mjs.
  for (const slug of ['about', 'security', 'trust']) {
    assert.doesNotMatch(page(slug), /Para(Sign|Send) Free/,
      `${slug}: the free plan is called Community, which is what /pricing prints on the card`);
  }
});
