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
  // Business exists in tiers.js with the same ceiling as Enterprise, and the
  // privacy policy used to skip it: a Business customer read the page and found
  // no row that was theirs. Both sentences now name it, and this asserts the two
  // tiers really do share the ceiling before it lets them share a sentence.
  const bus = hours(ttl('business'));
  assert.equal(bus, ent, 'business and enterprise no longer share a ceiling; split the sentence on /privacy and /terms');
  const priv = visible(page('privacy'));
  assert.ok(priv.includes(`${free} hour for Community, ${pro} hours for Pro, ${ent / 24} days for Business and Enterprise`), 'privacy: retention line must match tiers.js');
  assert.ok(priv.includes(`Community plan blobs expire after ${free} hour maximum. Pro blobs after ${pro} hours. Business and Enterprise blobs after ${ent / 24} days.`), 'privacy: expiry paragraph must match tiers.js');
  const WORD = { 1: 'one', 24: 'twenty-four', 7: 'seven' };
  assert.ok(visible(page('terms')).includes(`${WORD[free]} hour on Community, ${WORD[pro]} hours on Pro and ${WORD[ent / 24]} days on Business and Enterprise`),
    'terms: the time-to-live sentence must match tiers.js');
});

// 6 ── The authentication numbers on the security page. Session cookie
// Max-Age, TOTP step, and the login limits all live in code. The sentence
// "after ten consecutive failures an account locks for thirty minutes" had no
// code behind it (searched 2 September 2026) and is gone.
//
// The per-email half is no longer a limit at all, and the page has to say so.
// It used to be a counter on the address, incremented before authentication and
// refusing at eleven, which meant a stranger could put the owner of an address
// on 429 for fifteen minutes. It counts failures now, a success clears it, and
// past the threshold the attempt costs a proof-of-work instead of being
// refused. So the page may claim exactly one hard limit, the per-IP one.
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
  // /api/user/login: the limiter now lives in admin/lib/login-ratelimit.js.
  const rl = read('admin/lib/login-ratelimit.js');
  const ipLimit = Number(/const IP_LIMIT = (\d+);/.exec(rl)[1]);
  const windowS = Number(/const WINDOW_S = (\d+);/.exec(rl)[1]);
  const powAt = Number(/const EMAIL_FAIL_THRESHOLD = (\d+);/.exec(rl)[1]);
  assert.equal(ipLimit, perIp, 'both login paths must cap the same per-IP count');
  assert.equal(windowS, winMin * 60, 'both login paths must use the same window');

  assert.match(sec, new RegExp(`rate-limited to ${WORDS[perIp]} per IP per ${WORDS[winMin]} minutes`),
    `security: the per-IP login limit must read ${perIp} per ${winMin} minutes`);
  assert.match(sec, new RegExp(`past ${WORDS[powAt]} inside ${WORDS[winMin]} minutes the next attempt has to carry a proof-of-work`),
    `security: the per-email threshold must read ${powAt} and must be described as a cost, not a refusal`);

  // The page must not sell the per-email counter as a limit again, and the
  // handler must not implement one. A refusal keyed on an address is a lockout
  // whatever it is called.
  assert.doesNotMatch(sec, /per email per/i, 'security: there is no per-email refusal to advertise');
  const handler = srv.slice(srv.indexOf('api.post("/user/login"'), srv.indexOf('api.post("/user/login-with-backup"'));
  assert.doesNotMatch(handler, /paramant:user:ratelimit:email:|emailCount\s*>/,
    'the login handler must not refuse on a per-email attempt counter');
  assert.match(handler, /clearEmailFailures/, 'a successful sign-in must clear the failures counted on that address');

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
  // Every block that serves the docroot or proxies to a relay or the admin,
  // plus :8090.
  //
  // :8090 used to be excluded, with a comment saying it "only fronts the
  // Outlook add-in via an external host". That was wrong twice over. Its
  // /outlook/* aliases duplicate the :8081 block and are served for real from
  // addin.paramant.app; what the block actually does is answer for
  // "location /dicom/" in the public block, which reaches it over
  // 127.0.0.1:8090. So it serves the site, and it belongs in this sweep.
  // It matches neither half of the filter on its own (it uses alias, and its
  // catch-all proxies to an external https upstream), hence the third arm.
  //
  // The doesNotMatch above does not cover this: it fires on an access_log
  // pointed at a file, and DELETING the line leaves nothing to match. The
  // sweep below is what makes a missing line fail.
  const blocks = conf.split(/^server \{/m).slice(1)
    .filter((b) => /root \/home\/paramant|proxy_pass http:\/\/127\.0\.0\.1:|listen 127\.0\.0\.1:8090/.test(b));
  assert.ok(blocks.length >= 7, 'nginx-paramant-live.conf must carry the site, relay and :8090 server blocks');
  for (const b of blocks) {
    assert.match(b, /^\s*access_log off;/m, `the server block on ${/listen\s+([^;]+)/.exec(b)?.[1]} logs requests; rewrite the IP-logging row on /security`);
  }
  const dicomBlock = blocks.find((b) => /listen 127\.0\.0\.1:8090/.test(b));
  assert.ok(dicomBlock, 'the :8090 block backs location /dicom/; if it was retired, retire the /dicom/ proxy with it');
  assert.match(dicomBlock, /^\s*access_log off;/m,
    'the :8090 block serves /dicom/ and must switch access logging off like every other block in this file');
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

// 13 ── The file size a page tells you it will take. relay.js MAX_BLOB and the
// file_mb column in tiers.js are the only two numbers that decide it, and they
// are 5 MB. Two help pages said "Files up to 5 GB are supported": a thousand
// times the ceiling, on the two pages a buyer reads while deciding whether the
// product fits their attachment. Test 4 did not catch it because it scans for a
// size in MB, and these two said GB. This one reads the ceiling out of the code
// and then refuses any file-size figure on the site that is not it.
test('the file size the site promises is the ceiling relay.js and tiers.js enforce', () => {
  const tiersSrc = read('relay/lib/tiers.js');
  const declared = [...tiersSrc.matchAll(/file_mb:\s*(-?[\d_]+|UNLIMITED)/g)].map((m) => m[1]);
  assert.ok(declared.length >= 4, 'tiers.js must declare file_mb on every tier row');
  const capped = [...new Set(declared.filter((v) => /^\d/.test(v)).map((v) => Number(v.replace(/_/g, ''))))];
  assert.equal(capped.length, 1, `every capped tier must share one file_mb, found ${capped.join(', ')}`);
  const mb = capped[0];
  const blob = Number(/MAX_BLOB\s*=\s*parseInt\(process\.env\.MAX_BLOB\s*\|\|\s*'(\d+)'\)/.exec(read('relay/relay.js'))[1]);
  assert.equal(blob, mb * 1048576, 'MAX_BLOB and tiers.js file_mb must be the same ceiling');
  // And it is still the relay that refuses a larger upload, or the number is a
  // constant nobody reads (same reasoning as test 11).
  assert.match(read('relay/relay.js'), /Max \$\{Math\.round\(planMaxSize\/1048576\)\}MB/,
    'relay.js must still refuse an oversized upload');

  const problems = [];
  // The two help pages that quote a supported file size have to quote this one.
  for (const slug of ['help/gmail-extension', 'help/iot-integration']) {
    if (!visible(page(slug)).includes(`${mb} MB are supported`)) {
      problems.push(`${slug}: must say "Files up to ${mb} MB are supported"`);
    }
  }
  // Nowhere on the site may a Paramant file size be stated in gigabytes. The
  // competitor comparison on /vs quotes other vendors' gigabyte allowances and
  // is the one page this sweep leaves alone.
  const GB = [/\b(\d+(?:[.,]\d+)?)\s*GB\b[^.<]{0,40}\b(?:are supported|per file|file size|file limit|maximum)/i,
              /\b(?:files?|uploads?|attachments?)\b[^.<]{0,40}\b(\d+(?:[.,]\d+)?)\s*GB\b/i];
  for (const slug of publicPages()) {
    if (slug === 'vs') continue;
    const text = visible(page(slug));
    for (const re of GB) {
      const m = re.exec(text);
      if (m) problems.push(`${slug}: states a file size of "${m[0].trim()}", and the relay refuses anything over ${mb} MB`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 14 ── "The API accepts up to 60 uploads per minute per API key" (/help/iot-
// integration). Two things wrong at once. The 60 a minute is an nginx zone
// keyed on $binary_remote_addr, so it is per IP address and not per key, and it
// is the general API zone: uploads sit in a stricter one. The ceiling that IS
// per key is outbound_per_hour in tiers.js, and it counts retrievals, not
// uploads. A device operator sizing a fleet off that sentence sizes it wrong.
test('the rate limits the IoT page quotes are the ones the configuration sets', () => {
  const conf = read('deploy/nginx-selfhost.conf');
  const zone = (name) => {
    const m = new RegExp(`limit_req_zone\\s+(\\S+)\\s+zone=${name}:[^ ]+\\s+rate=(\\d+)r/m`).exec(conf);
    assert.ok(m, `deploy/nginx-selfhost.conf must define the ${name} zone`);
    return { key: m[1], rate: Number(m[2]) };
  };
  const api = zone('api');
  const inbound = zone('inbound');
  assert.equal(api.key, '$binary_remote_addr', 'the API zone is keyed per IP, not per API key');
  assert.ok(inbound.rate < api.rate, 'uploads must sit in a stricter zone than general API traffic');

  const tiersSrc = read('relay/lib/tiers.js');
  const perHour = (tier) => {
    const block = tiersSrc.slice(tiersSrc.indexOf(`${tier}:`));
    return Number(/outbound_per_hour:\s*([\d_]+)/.exec(block)[1].replace(/_/g, ''));
  };
  const community = perHour('community');
  const pro = perHour('pro');
  assert.match(read('relay/relay.js'), /Outbound rate limit exceeded/, 'relay.js must still enforce outbound_per_hour');

  const iot = visible(page('help/iot-integration'));
  const problems = [];
  const says = (phrase, why) => { if (!iot.includes(phrase)) problems.push(`help/iot-integration: must say "${phrase}" (${why})`); };
  says(`${api.rate} requests a minute`, 'the general API zone rate');
  says('per IP address, not per API key', 'the zone is keyed on the client address');
  says(`${community} downloads an hour`, 'the Community outbound_per_hour');
  says(`${pro} an hour`, 'the Pro outbound_per_hour');
  if (/\d+\s*uploads? per minute/i.test(iot)) problems.push('help/iot-integration: the per-minute figure is a request rate per IP, not an upload rate per key');
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 15 ── The account lockout. PR #327 struck "after ten consecutive failures an
// account locks for thirty minutes" from /security because no code implements
// it, and test 6 keeps it off that one page. The identical promise survived on
// /help/session-issues, with an email address to write to for an early unlock
// that nobody can grant, and /dpa quoted the login limiter as "5 attempts/min"
// when the window is fifteen minutes. So the sweep goes sitewide.
test('no page promises an account lockout, and the login limits are the enforced ones', () => {
  const srv = read('admin/server.js');
  const fn = srv.slice(srv.indexOf('function checkLoginRateLimit'));
  const perIp = Number(/b\.count >= (\d+)/.exec(fn)[1]);
  const winMin = Number(/(\d+) \* 60_000/.exec(fn)[1]);
  // The /api/user/login limiter moved into a module in #368, when the per-email
  // half stopped being a refusal. The numbers are read from there now.
  const rl = read('admin/lib/login-ratelimit.js');
  const perEmail = Number(/const EMAIL_FAIL_THRESHOLD = (\d+);/.exec(rl)[1]);
  assert.equal(Number(/const IP_LIMIT = (\d+);/.exec(rl)[1]), perIp);
  assert.equal(Number(/const WINDOW_S = (\d+);/.exec(rl)[1]), winMin * 60);
  // No lockout anywhere in the server code, or the pages should say so again.
  for (const src of ['admin/server.js', 'relay/relay.js']) {
    assert.doesNotMatch(read(src), /consecutive fail|lockout_minutes|LOCKOUT_MS|account_locked/i,
      `${src}: no login lockout is implemented; if one is added, put the sentence back with its numbers`);
  }

  const LOCKOUT = [/consecutive fail/i, /accounts? (?:are|is) (?:temporarily )?locked/i,
                   /the lock lifts/i, /request an early unlock/i, /account locks/i];
  const problems = [];
  for (const slug of publicPages()) {
    const text = visible(page(slug));
    for (const re of LOCKOUT) {
      const m = re.exec(text);
      if (m) problems.push(`${slug}: promises a lockout ("${m[0]}") that no code implements`);
    }
  }
  // And the page that used to promise it now states what the code does.
  const help = visible(page('help/session-issues'));
  if (!help.includes('There is no account lock')) problems.push('help/session-issues: must say there is no account lock');
  for (const phrase of [`${perIp} attempts from one IP address`, `${winMin} minutes`]) {
    if (!help.includes(phrase)) problems.push(`help/session-issues: must state "${phrase}"`);
  }
  // The per-email number is no longer a refusal, so the page states it as the
  // point where an attempt starts costing work. Naming it as a second limit
  // would put the lockout back in the reader's head.
  if (!help.includes(`past ${word(perEmail)} inside ${word(winMin)} minutes`)) {
    problems.push(`help/session-issues: must state the ${perEmail}-failure threshold as a cost, not a limit`);
  }
  if (/for one email address/.test(help)) {
    problems.push('help/session-issues: there is no per-email refusal to state any more');
  }

  // "No lockout" is not the same as "nobody can lock you out". The email
  // counter is keyed on the ADDRESS alone, it is incremented before the code is
  // checked, and a successful login never clears it, so someone else's attempts
  // on your address spend your budget and hold you at 429 for the rest of the
  // window. The first version of this row said the opposite in a subordinate
  // clause and nothing pinned it, which is the whole failure mode this file
  // exists for. Read the three properties out of the handler and require the
  // page to carry the caveat exactly while they hold.
  const handler = srv.slice(srv.indexOf('api.post("/user/login"'));
  const body = handler.slice(0, handler.indexOf('\napi.'));
  // Three properties, read out rather than asserted, because the whole point of
  // this branch is that the page follows whichever way they fall. #368 turned
  // all three off: the counter counts failures, it runs after authentication,
  // and a success deletes it. If any of them comes back the caveat comes back
  // with it, on the page, in the reader's language.
  const emailKeyed = /paramant:user:ratelimit:email:/.test(body);
  const authAt = body.indexOf('findUserByEmail');
  assert.ok(authAt > 0, 'the login handler must still look the account up');
  // indexOf returns -1 for "not found", and -1 sorts before every real offset,
  // so a counter that was deleted outright would read as "counted first". Both
  // offsets are required to exist before they are compared.
  const incrAt = body.indexOf('redis().incr(emailKey)');
  const beforeAuth = incrAt > 0 && incrAt < authAt;
  const neverCleared = !/clearEmailFailures|del\(\s*emailKey/.test(body);
  const shared = emailKeyed && beforeAuth && neverCleared;

  const CAVEAT = 'attempts someone else makes on your address count against you too';
  if (shared) {
    if (!help.includes(CAVEAT)) {
      problems.push(`help/session-issues: the ${perEmail}-per-address counter is spent by anyone who knows the address, and the page must say so`);
    }
    // And no page may deny it, in any of the shapes that denial takes.
    const DENIES = [/nobody can lock you out/i, /no ?one can lock you out/i,
                    /cannot be locked out by/i, /only your own attempts count/i];
    for (const slug of publicPages()) {
      const text = visible(page(slug));
      for (const re of DENIES) {
        const m = re.exec(text);
        if (m) problems.push(`${slug}: "${m[0]}" is not true while the counter is keyed on the address alone`);
      }
    }
  } else if (help.includes(CAVEAT)) {
    problems.push('help/session-issues: the per-address counter is no longer shared, so drop the caveat');
  }
  // /dpa quotes the same limiter in its access-control row.
  const dpa = visible(page('dpa'));
  const perMin = /per-IP rate limiting \((\d+) attempts?\/min\)/.exec(dpa);
  if (perMin) problems.push(`dpa: says ${perMin[1]} attempts a minute; checkLoginRateLimit is ${perIp} per ${winMin} minutes`);
  if (!dpa.includes(`${perIp} attempts per ${winMin} minutes`)) {
    problems.push(`dpa: the access-control row must state ${perIp} attempts per ${winMin} minutes`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 16 ── The session cookie. /security described it as SameSite=Strict. It is
// Lax, and deliberately so: the comment above setUserCookie in admin/server.js
// explains that a Strict cookie is not sent on the top-level navigation from an
// emailed invite, which is the one flow ParaSign is built around. (That comment
// cites ADR R018 for the decision, but docs/adrs/R018-parasign-invite-webauthn.md
// says nothing about SameSite, so the comment is the source, not the ADR.)
// Describing a security control as stricter than it is, is the wrong direction
// to be wrong in.
test('the session cookie described on /security is the cookie admin/server.js sets', () => {
  const srv = read('admin/server.js');
  const set = /paramant_user_session=\$\{token\};([^`]*)`/.exec(srv);
  assert.ok(set, 'admin/server.js must set the session cookie from a template literal');
  const attrs = set[1];
  const sameSite = /SameSite=(\w+)/.exec(attrs)[1];
  const maxAge = Number(/Max-Age=(\d+)/.exec(attrs)[1]);
  const bits = Number(/const sessionToken = crypto\.randomBytes\((\d+)\)/.exec(srv)[1]) * 8;
  assert.equal(maxAge, 3600);
  // Sliding, because every authenticated read pushes the Redis TTL back out.
  assert.match(srv, /expire\(`paramant:user:session:\$\{token\}`,\s*3600\)/,
    'the session TTL must be refreshed on use for "sliding" to be true');

  const sec = visible(page('security'));
  const problems = [];
  for (const phrase of [`${bits}-bit session token`, 'httpOnly', 'Secure', `SameSite=${sameSite}`, 'one-hour sliding expiry']) {
    if (!sec.includes(phrase)) problems.push(`security: the session row must say "${phrase}"`);
  }
  // Nowhere may the site claim an attribute value the code does not set.
  for (const slug of publicPages()) {
    for (const m of visible(page(slug)).matchAll(/SameSite=(\w+)/g)) {
      if (m[1] !== sameSite) problems.push(`${slug}: claims SameSite=${m[1]}, admin/server.js sets SameSite=${sameSite}`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 17 ── Which HMAC a TOTP code is checked with. /security said "SHA-256 HMAC,
// matching the cryptographic posture of the transport layer". totp.js dual-
// verifies: the default algorithm list is SHA-256 AND SHA-1, deliberately, so
// that Google Authenticator and the iCloud Keychain authenticator work at all.
// /help/authenticator-apps already said both. /security said one, which reads
// as a stronger guarantee than the login path gives.
test('the TOTP algorithms named on the site are the ones totp.js accepts', () => {
  const totp = stripJsComments(read('relay/lib/totp.js'));
  const list = /const algs = algorithms \|\| \(algorithm \? \[algorithm\] : \[([^\]]+)\]\)/.exec(totp);
  assert.ok(list, 'totp.js must build its default algorithm list in one place');
  const algs = list[1].split(',').map((s) => s.trim().replace(/['"]/g, ''));
  assert.deepEqual(algs, ['sha256', 'sha1'], 'the default TOTP algorithm set changed; update the pages with it');
  const label = (a) => (a === 'sha256' ? 'SHA-256' : 'SHA-1');

  const problems = [];
  // Every page that names a TOTP HMAC has to name all of them.
  for (const slug of ['security', 'help/authenticator-apps']) {
    const text = visible(page(slug));
    for (const a of algs) {
      if (!text.includes(label(a))) problems.push(`${slug}: TOTP accepts ${label(a)} too, and the page does not say so`);
    }
  }
  for (const slug of publicPages()) {
    const text = visible(page(slug));
    const m = /TOTP[^.]{0,60}\bSHA-256\b[^.]{0,60}\./i.exec(text);
    if (m && !/SHA-1/i.test(m[0])) problems.push(`${slug}: "${m[0].trim()}" names one algorithm where the code accepts two`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 18 ── "Each code can be used exactly once across the system, enforced
// atomically in Redis." The NX key is real and it is atomic. The absolute is
// not: verifyTotpGeneric ends the store call with .catch(() => 'OK'), so when
// Redis is unreachable the replay check is skipped and the code is accepted
// again. That is a deliberate availability choice, and the page has to say it
// rather than sell the failure mode as a guarantee.
test('the single-use TOTP guarantee is stated with the fail-open the code has', () => {
  const totp = stripJsComments(read('relay/lib/totp.js'));
  const guard = /store\.set\(slotKey, '1', \{ NX: true, EX: (\d+) \}\)(\.catch\(\(\) => 'OK'\))?/.exec(totp);
  assert.ok(guard, 'totp.js must guard replay with a per-slot NX key');
  const failsOpen = Boolean(guard[2]);

  const sec = visible(page('security'));
  const problems = [];
  if (failsOpen) {
    if (!/If Redis cannot be reached the check is skipped/.test(sec)) {
      problems.push('security: the replay guard fails open on a Redis error, and the page must say so');
    }
    for (const slug of publicPages()) {
      const m = /used exactly once across the system/i.exec(visible(page(slug)));
      if (m) problems.push(`${slug}: claims "${m[0]}" while the replay store call falls back to accepting the code`);
    }
  } else if (/the check is skipped/.test(sec)) {
    problems.push('security: the .catch fail-open is gone, so drop the caveat and state the guarantee');
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 19 ── Argon2id in the crypto tables. /security listed it as "Password-based
// blob encryption" and /docs as "Password-protected blob derive". Neither is
// what relay.js does: the password is hashed with Argon2id into pw_hash and
// compared on retrieval, and the blob key is not derived from it at any point.
// It is also an optional module (a bare try/require, 501 when it is absent),
// which a table of primitives that carries the product should not hide.
test('the Argon2id row says what relay.js uses Argon2id for', () => {
  const relay = stripJsComments(read('relay/relay.js'));
  assert.match(relay, /pw_hash = await argon2Lib\.hash\(password/, 'Argon2id must still hash the transfer password');
  assert.match(relay, /argon2Lib\.verify\(entry\.pw_hash/, 'Argon2id must still verify it on retrieval');
  assert.match(relay, /try \{ argon2Lib = require\('argon2'\); \} catch/, 'Argon2id must still be an optional module');
  assert.match(relay, /Argon2id not available on this relay/, 'a relay without the module must refuse the password option');
  // The key that encrypts a blob never comes out of argon2.
  assert.doesNotMatch(relay, /argon2Lib\.hash\([^)]*\)[^;]*(?:deriveKey|createCipheriv)/,
    'if the blob key is ever derived from the password, this row can say "derive" again');

  const problems = [];
  const ROW = /<tr><td>Argon2id<\/td><td>([^<]*)<\/td>/;
  for (const slug of ['security', 'docs']) {
    const m = ROW.exec(page(slug));
    if (!m) { problems.push(`${slug}: the crypto table must still carry the Argon2id row`); continue; }
    const role = m[1];
    if (/encryption|encrypt|derive/i.test(role)) problems.push(`${slug}: Argon2id is described as "${role}"; it hashes a password and never encrypts or derives`);
    if (!/hash/i.test(role)) problems.push(`${slug}: the Argon2id row must say it is a hash`);
    if (!/optional/i.test(role)) problems.push(`${slug}: the Argon2id row must say the module is optional`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 20 ── The padding claim. /security and /docs said an observer "cannot infer
// (or determine) file size, type, or content". Finding 5 of the audit this site
// publishes says the opposite and calls it an accepted trade-off: total_chunks
// travels in the clear, so the number of 5 MB blocks is visible and the size
// follows to an order of magnitude. The site was contradicting its own report.
test('the 5 MB padding claim matches audit finding 5 and what ParaShare sends', () => {
  const audit = read('docs/security-audit-2026-04.md');
  // /security and /trust link a reader to /docs/security-audit-2026-04.md, which
  // is the copy under frontend/. This row is bounded by a finding in the repo
  // copy, so the two have to be the same bytes: a drift between them would mean
  // the test reads one report and the visitor reads another.
  assert.equal(read('frontend/docs/security-audit-2026-04.md'), audit,
    'frontend/docs/security-audit-2026-04.md must be byte-identical to docs/security-audit-2026-04.md');
  for (const slug of ['security', 'trust']) {
    assert.match(page(slug), /href="\/docs\/security-audit-2026-04\.md"/,
      `${slug}: must still link the published report this row is bounded by`);
  }
  const row = /\|\s*5\s*\|\s*\*\*Metadata size leakage\*\*[^|]*\|\s*(\S+)\s*\|([^|]*)\|/.exec(audit);
  assert.ok(row, 'audit finding 5 (metadata size leakage) must still be in the report');
  assert.match(row[2], /Accepted tradeoff/, 'finding 5 is the accepted trade-off this claim is bounded by');
  // And the chunk count really is sent to the relay in the clear.
  assert.match(read('frontend/js/parashare.page.js'), /total_chunks:\s*totalChunks/,
    'ParaShare must still send total_chunks, or this caveat can go');

  const problems = [];
  const ABSOLUTE = /(?:cannot|can not|can't)\s+(?:infer|determine|tell)[^.]{0,40}\b(?:size|type|content)/i;
  for (const slug of publicPages()) {
    const text = visible(page(slug));
    const m = ABSOLUTE.exec(text);
    if (m) problems.push(`${slug}: "${m[0].trim()}" is finding 5, an accepted leak, stated as impossible`);
  }
  // The two pages that explain the padding carry the bound.
  for (const slug of ['security', 'docs']) {
    if (!/block count|number of blocks|chunk count/i.test(visible(page(slug)))) {
      problems.push(`${slug}: the padding section must say the block count of a multi-block transfer is visible`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 21 ── "no IP rate limit" as a paid-plan benefit on the homepage. There is no
// per-IP ceiling a paid plan lifts: the only per-IP rate in the product is
// ANON_RATE_PER_HOUR on the deprecated /v2/anon-inbound, the same fossil test 11
// hunts, and it does not read a plan at all. What a paid plan really raises is
// outbound_per_hour, per API key, which is the number /parasend already sells.
test('the hourly ceiling a paid plan buys is outbound_per_hour, and no page sells a lifted IP limit', () => {
  const tiersSrc = read('relay/lib/tiers.js');
  const perHour = (tier) => {
    const block = tiersSrc.slice(tiersSrc.indexOf(`${tier}:`));
    const m = /outbound_per_hour:\s*([\d_]+|UNLIMITED)/.exec(block);
    assert.ok(m, `tiers.js ${tier} must declare outbound_per_hour`);
    return m[1] === 'UNLIMITED' ? Infinity : Number(m[1].replace(/_/g, ''));
  };
  const community = perHour('community');
  const pro = perHour('pro');
  assert.ok(pro > community, 'a paid plan must actually raise the hourly ceiling');
  const relay = stripJsComments(read('relay/relay.js'));
  assert.match(relay, /const max = parasendLimitsOf\(rec\)\.limits\.outbound_per_hour/,
    'relay.js must read the ceiling off the ParaSend entitlement');
  // The per-IP rate that does exist belongs to the deprecated anonymous route
  // and reads no plan, so no tier can lift it.
  assert.match(relay, /ANON_RATE_PER_HOUR/, 'the per-IP rate is the anon-inbound one');
  assert.doesNotMatch(relay, /ANON_RPH[^;]*plan/, 'the anonymous per-IP rate must not read a plan');

  const problems = [];
  const idx = visible(page('index'));
  if (!idx.includes(`up to ${pro} retrievals an hour through the API instead of ${community}`)) {
    problems.push(`index: the paid-plan line must say up to ${pro} retrievals an hour instead of ${community}`);
  }
  for (const slug of publicPages()) {
    const m = /no IP rate limit|IP rate limit (?:is )?(?:lifted|removed)/i.exec(visible(page(slug)));
    if (m) problems.push(`${slug}: sells "${m[0]}", and no tier lifts a per-IP rate`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 22 ── "No third-party requests. Your browser talks only to us. No fonts,
// CDNs, analytics or pixels." (/parasend) and "No tracking." (/pricing). Both
// are true today and nothing held them there: one Google Fonts stylesheet, one
// analytics snippet or one tracking pixel added to a shared header would leave
// the sentences standing. This walks every public page and fails on any
// subresource, of any kind, that is not served from paramant.app.
//
// A tag scan alone is not enough. Audit finding 17 was a font stylesheet on
// drop.html, and the two ways a page reaches off-origin without a tag are a
// bare `@import "https://..."` (no url(), so a url() scan misses it) and a
// runtime call in an inline script. Both are checked here, along with the
// worker and socket constructors that fetch code or open a connection.
//
// The page set is the public list plus /ontvang and /parashare. Those two are
// in PRIVATE because they are one-shot flows with no place in the sitemap, but
// a recipient reaches them by opening a share link, without an account and
// without a login: a third-party request there is as public as one anywhere,
// and drop.html was exactly that kind of page.
test('no page a visitor can open loads anything from a third party, which is what /parasend promises', () => {
  const TAGS = 'script|link|img|iframe|source|video|audio|embed|object|track|image';
  const ATTR = /\b(?:src|href|srcset|poster|data)\s*=\s*"([^"]*)"/gi;
  const ABS = String.raw`(?:https?:)?\/\/`;
  // Off-origin without a tag: a bare @import, and anything an inline script
  // fetches, opens or loads at runtime.
  const RUNTIME = [
    [new RegExp(String.raw`@import\s+(?:url\(\s*)?['"]?(${ABS}[^'")\s;]+)`, 'gi'), 'a stylesheet @import of'],
    [new RegExp(String.raw`\bfetch\(\s*['"\`](${ABS}[^'"\`]+)`, 'gi'), 'an inline fetch() of'],
    [new RegExp(String.raw`\.open\(\s*['"][A-Z]+['"]\s*,\s*['"\`](${ABS}[^'"\`]+)`, 'gi'), 'an XMLHttpRequest to'],
    [new RegExp(String.raw`new\s+(?:WebSocket|EventSource|Worker|SharedWorker)\(\s*['"\`](${ABS}[^'"\`]+)`, 'gi'), 'a connection or worker from'],
    [new RegExp(String.raw`importScripts\(\s*['"\`](${ABS}[^'"\`]+)`, 'gi'), 'an importScripts() of'],
    [new RegExp(String.raw`url\(\s*['"]?(${ABS}[^)'"]+)`, 'gi'), 'a stylesheet rule loading'],
  ];
  const ours = (url) => {
    const host = /^(?:https?:)?\/\/([^/?#]+)/.exec(url);
    return !host || host[1] === 'paramant.app' || host[1].endsWith('.paramant.app');
  };
  // Reachable without an account: every public page, plus the two share-link
  // landing pages that PRIVATE excludes from the sitemap but not from a visitor.
  const reachable = [...new Set([...publicPages(), 'ontvang', 'parashare'])].sort();
  assert.ok(reachable.includes('ontvang') && reachable.includes('parashare'),
    'the two share-link landing pages must be in the scan');

  const problems = [];
  for (const slug of reachable) {
    const html = page(slug).replace(/<!--[\s\S]*?-->/g, '');
    for (const tag of html.matchAll(new RegExp(`<(?:${TAGS})\\b[^>]*>`, 'gi'))) {
      for (const a of tag[0].matchAll(ATTR)) {
        const url = a[1].trim();
        if (/^(?:https?:)?\/\//.test(url) && !ours(url)) problems.push(`${slug}: loads ${url}`);
      }
    }
    for (const [re, what] of RUNTIME) {
      for (const m of html.matchAll(re)) {
        if (!ours(m[1])) problems.push(`${slug}: ${what} ${m[1]}`);
      }
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);

  // And the two pages that make the promise still make it.
  assert.match(visible(page('parasend')), /No third-party requests/, 'parasend: the promise must still be on the page');
  assert.match(visible(page('parasend')), /No fonts, CDNs, analytics or pixels/, 'parasend: name what is not loaded');
  assert.match(visible(page('pricing')), /No tracking\./, 'pricing: the free tier line must still say No tracking.');
});

// 23 ── The BUSL conversion. LICENSE is the operative grant; /license quotes it
// in a code block, repeats it in prose, and repeats it again in four head
// copies, and /terms repeats it once more. All six said 1 January 2030 and MIT
// while the file granted 2029-01-01 and Apache License 2.0: a reader deciding
// whether to build on the code was told the wrong licence and the wrong year.
// Verified by sabotage: with the old page text in place this block fails on the
// licence-box line first and on each head copy after it.
test('the BUSL conversion the site publishes is the one LICENSE grants', () => {
  const esc = (v) => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const lic = read('LICENSE');
  const d = /^Change Date:\s*(\d{4})-(\d{2})-(\d{2})\s*$/m.exec(lic);
  const n = /^Change License:\s*(\S.*?)\s*$/m.exec(lic);
  assert.ok(d, 'LICENSE must state a Change Date as YYYY-MM-DD');
  assert.ok(n, 'LICENSE must state a Change License');
  const iso = `${d[1]}-${d[2]}-${d[3]}`;
  const name = n[1];
  const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'];
  const human = `${Number(d[3])} ${MONTHS[Number(d[2]) - 1]} ${d[1]}`;

  // The copy that ships with a self-hosted relay must not grant something else.
  assert.match(read('deploy/LICENSE'), new RegExp(`^Change Date:\\s*${iso}\\s*$`, 'm'),
    'deploy/LICENSE states a different Change Date than LICENSE');
  assert.match(read('deploy/LICENSE'), new RegExp(`^Change License:\\s*${esc(name)}\\s*$`, 'm'),
    'deploy/LICENSE states a different Change License than LICENSE');

  const licPage = page('license');
  assert.match(licPage, new RegExp(`Change Date:\\s+${iso}`), 'license: the licence box must quote the Change Date in LICENSE');
  assert.match(licPage, new RegExp(`Change License:\\s+${esc(name)}`), 'license: the licence box must quote the Change License in LICENSE');
  assert.ok(visible(licPage).includes(`On ${human} the entire codebase will be released under the ${name}.`),
    `license: the prose must say ${human} and ${name}`);
  // The head copies: description, og, twitter and the JSON-LD all carry the
  // sentence, and seo-contract only pins them to each other, so all four can be
  // wrong together.
  const heads = [...licPage.matchAll(/converts to the ([^"<]+?) on (\d{4}-\d{2}-\d{2})\./g)];
  assert.ok(heads.length >= 4, `license: expected the conversion sentence in every head copy, found ${heads.length}`);
  for (const h of heads) {
    assert.equal(h[1], name, 'license: a head copy names a different licence than LICENSE');
    assert.equal(h[2], iso, 'license: a head copy names a different date than LICENSE');
  }
  assert.ok(visible(page('terms')).includes(`converts to the ${name} on ${human}.`),
    `terms: the licence sentence must say ${name} and ${human}`);

  // The three fields that decide who may run this in production, and they are
  // the ones the review found saying three different things. LICENSE grants
  // production use up to five API keys and one self-hosted deployment,
  // commercial use included. deploy/LICENSE, which ships with a self-hosted
  // relay, carried no Additional Use Grant at all while its Terms referred to
  // one "above"; the box on /license granted non-commercial use only and named
  // a different Licensor and a different Licensed Work. Only the Change Date
  // and Change License were pinned, so all three could disagree and stay green.
  // Verified by sabotage in both directions: editing the grant, the Licensor or
  // the Licensed Work in LICENSE turns this red, and so does editing either
  // copy.
  const licenseField = (src, key, where) => {
    const m = new RegExp(`^${key}:[ \\t]*(\\S.*?)[ \\t]*$`, 'm').exec(src);
    assert.ok(m, `${where}: must state ${key}`);
    return m[1];
  };
  const grantOf = (src, where) => {
    const start = src.indexOf('Additional Use Grant');
    assert.ok(start >= 0, `${where}: must carry the Additional Use Grant, not a reference to one`);
    const end = src.indexOf('\nTerms', start);
    assert.ok(end > start, `${where}: the Additional Use Grant must sit above the Terms section`);
    return src.slice(start, end).replace(/\s+/g, ' ').trim();
  };
  const flat = (src) => src.replace(/\s+/g, ' ').trim();
  const boxMatch = /<div class="license-box">([\s\S]*?)<\/div>/.exec(licPage);
  assert.ok(boxMatch, 'license: the full licence text box must still be on the page');
  const copies = [['deploy/LICENSE', read('deploy/LICENSE')], ['license (box)', boxMatch[1]]];
  for (const [where, src] of copies) {
    for (const key of ['Licensor', 'Licensed Work']) {
      assert.equal(licenseField(src, key, where), licenseField(lic, key, 'LICENSE'),
        `${where}: ${key} differs from LICENSE, and LICENSE is the operative grant`);
    }
    assert.equal(grantOf(src, where), grantOf(lic, 'LICENSE'),
      `${where}: the Additional Use Grant is not word for word the one LICENSE gives`);
    // The whole file, not only the fields. The field pins above let a copy drop
    // a shared paragraph and stay green: the box was missing the MariaDB
    // trademark clause and the Covenants section, and carrying a line
    // ("(c) 2026 ... All Rights Reserved.") that LICENSE does not have, while
    // the page called it reproduced word for word. Whitespace is normalised, so
    // the box may keep its own column alignment and nothing else.
    assert.equal(flat(src), flat(lic),
      `${where}: is not the LICENSE file. Something was added, dropped or reworded; the page calls this a verbatim copy, so copy the file in whole`);
  }
  // The grant permits commercial production use inside the limits, so no page
  // may sell the licence as non-commercial only.
  const grantProblems = [];
  for (const slug of publicPages()) {
    for (const m of visible(page(slug)).matchAll(/\bnon-commercial\b[^.<]*/g)) {
      grantProblems.push(`${slug}: says "non-commercial${m[0].slice(14, 60)}"; LICENSE grants commercial production use within the Additional Use Grant`);
    }
  }
  assert.deepEqual(grantProblems, [], `\n  ${grantProblems.join('\n  ')}\n`);

  // No page may name a conversion the file does not grant.
  const problems = [];
  for (const slug of publicPages()) {
    const text = page(slug);
    for (const m of text.matchAll(/Change Date:\s*(\d{4}-\d{2}-\d{2})/g)) {
      if (m[1] !== iso) problems.push(`${slug}: quotes Change Date ${m[1]}, LICENSE says ${iso}`);
    }
    for (const m of text.matchAll(/(?:converts to|released under) the ([A-Za-z0-9][A-Za-z0-9. ]*?(?:License|licence)(?: \d+(?:\.\d+)*)?)/g)) {
      if (m[1] !== name) problems.push(`${slug}: names "${m[1]}" as the conversion licence, LICENSE says ${name}`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 24 ── "Burned on read" as a universal property. tiers.js gives Pro 10 reads
// per link, Business 25 and Enterprise 100, and /pricing sells exactly that, so
// the privacy policy claiming every chunk is destroyed after the first download
// was describing the Community plan and calling it the service. Verified by
// sabotage: raising community.max_views to 2 fails the first assertion, and
// changing any of the three paid numbers fails the sentence.
test('the reads a link allows on /privacy are the ones tiers.js grants', () => {
  const tiers = read('relay/lib/tiers.js');
  const views = (t) => Number(/max_views:\s*(\d+)/.exec(tiers.slice(tiers.indexOf(`${t}:`)))[1]);
  const comm = views('community');
  assert.equal(comm, 1, 'community no longer burns on the first read; rewrite the burn-on-read paragraph on /privacy');
  const priv = visible(page('privacy'));
  assert.ok(priv.includes('On the Community plan it is permanently and irreversibly destroyed after the first download'),
    'privacy: burn-on-read must be attributed to the plan that has it');
  assert.ok(priv.includes(`up to ${views('pro')} on Pro, ${views('business')} on Business and ${views('enterprise')} on Enterprise`),
    'privacy: the reads a paid link allows must be the max_views in tiers.js');
  assert.doesNotMatch(priv, /relay server and is permanently and irreversibly destroyed after the first download/,
    'privacy: must not state burn-on-read as a property of every plan');

  // The other half of the same untruth. Fifteen pages called burn-on-read
  // universal; that sweep is block 37. /press went further and
  // denied the timer outright ("destroyed on download, not on a timer") while
  // tiers.js gives every plan a view_ttl_ms. Saying a thing exists where it does
  // not is a different mistake from denying a thing that does, and the denial is
  // the one that can be pinned in one line here.
  const ttls = [...tiers.matchAll(/view_ttl_ms:\s*([\d_]+)/g)].map((m) => Number(m[1].replace(/_/g, '')));
  assert.ok(ttls.length >= 4 && ttls.every((t) => t > 0),
    'every tier in tiers.js must still carry a positive view_ttl_ms; if a plan lost its timer, /press may say so');
  const denials = [];
  for (const slug of publicPages()) {
    const m = /not on a timer|destroyed on download, not on a timer/.exec(visible(page(slug)));
    if (m) denials.push(`${slug}: says "${m[0]}", and tiers.js gives every plan a view_ttl_ms`);
  }
  assert.deepEqual(denials, [], `\n  ${denials.join('\n  ')}\n`);
  // And the ceilings it does name are read off tiers.js, so a changed TTL moves
  // /press too instead of leaving it quietly stale.
  const ttlOf = (t) => Number(/view_ttl_ms:\s*([\d_]+)/.exec(tiers.slice(tiers.indexOf(`${t}:`)))[1].replace(/_/g, ''));
  const hours = (t) => ttlOf(t) / 3_600_000;
  // Spelled out, the way /press and /terms write these. The shared word() helper
  // stops at twenty and then jumps to the tens, so twenty-four is not in it;
  // block 5 keeps its own small map for the same reason.
  const SPAN_WORD = { 1: 'one', 7: 'seven', 24: 'twenty-four' };
  const span = (t) => {
    const h = hours(t);
    const [n, unit] = h <= 24 ? [h, 'hour'] : [h / 24, 'day'];
    assert.ok(SPAN_WORD[n], `tiers.js now sets a ${t} ceiling of ${h} hours, which this block cannot spell; add it to SPAN_WORD and to /press`);
    return `${SPAN_WORD[n]} ${unit}${n === 1 ? '' : 's'}`;
  };
  const sentence = `${span('community')} on Community, ${span('pro')} on Pro, ${span('business')} on Business and Enterprise`;
  assert.equal(ttlOf('business'), ttlOf('enterprise'),
    'business and enterprise no longer share a ceiling; the /press sentence names them together');
  const press = visible(page('press'));
  assert.ok(press.includes(sentence),
    `press: the expiry bullet must say "${sentence}", the ceilings tiers.js sets, instead of denying the timer`);
});

// 25 ── The sub-processor lists. /dpa is signed by customers and named two
// parties; the relay and the admin call a third at runtime. Every external host
// the server code sends a request to has to be on both lists, because a
// controller signing the DPA is authorising exactly that list.
// Verified by sabotage: deleting the Mollie row from the /dpa table fails this
// by vendor name. Renaming only the first cell does not, and should not: the
// question is whether the party is named, not which cell names it.
test('every third party the server code calls is named on /privacy and /dpa', () => {
  const sources = [
    'relay/relay.js', 'relay/envelope.js', 'relay/parasign.js',
    ...fs.readdirSync(path.join(ROOT, 'relay/lib')).filter((f) => f.endsWith('.js')).map((f) => `relay/lib/${f}`),
    'admin/server.js',
    ...fs.readdirSync(path.join(ROOT, 'admin/lib')).filter((f) => f.endsWith('.js')).map((f) => `admin/lib/${f}`),
  ];
  const hosts = new Set();
  for (const f of sources) {
    const src = stripJsComments(read(f));
    for (const m of src.matchAll(/https\.request\(\s*\{[^}]*?hostname:\s*['"`]([^'"`]+)/g)) hosts.add(m[1]);
    for (const m of src.matchAll(/fetch\(\s*['"`]https:\/\/([^/'"`]+)/g)) hosts.add(m[1]);
    for (const m of src.matchAll(/^const [A-Z_]*HOST\s*=\s*['"`]([^'"`]+)/gm)) hosts.add(m[1]);
  }
  const external = [...hosts].filter((h) => !/(^|\.)paramant\.app$/.test(h) && !/^(localhost|127\.|10\.|192\.168\.)/.test(h));
  assert.ok(external.length >= 2, `only ${external.length} external hosts found; the scan stopped seeing the calls it exists for`);
  // The vendor is the registrable name in the host: api.resend.com -> resend.
  const vendors = [...new Set(external.map((h) => h.split('.').slice(-2)[0]))];
  const priv = visible(page('privacy'));
  const dpa = visible(page('dpa'));
  const subs = priv.slice(priv.indexOf('<h2>Subprocessors</h2>'));
  const table = dpa.slice(dpa.indexOf('id="subprocessors"'), dpa.indexOf('</table>', dpa.indexOf('id="subprocessors"')));
  assert.ok(subs.length > 200 && table.length > 200, 'the sub-processor sections must still be findable on both pages');
  const problems = [];
  for (const v of vendors) {
    const re = new RegExp(`\\b${v}\\b`, 'i');
    if (!re.test(subs)) problems.push(`privacy: the code calls ${v}, and the sub-processor list does not name it`);
    if (!re.test(table)) problems.push(`dpa: the code calls ${v}, and the sub-processor table does not name it`);
  }
  // A US sub-processor is on the signed table, under Standard Contractual
  // Clauses. /press said "No US entity in the chain" in the same breath as the
  // Hetzner location, which is the opposite of what the controller signs.
  // Verified by sabotage in both directions: putting the sentence back turns
  // this red, and so does removing the US row from /dpa.
  const usRow = /<tr><td>([^<]+)<\/td><td>US[^<]*<\/td>/.exec(page('dpa'));
  if (usRow) {
    const denials = [];
    for (const slug of publicPages()) {
      const m = /No US entity in the chain/.exec(visible(page(slug)));
      if (m) denials.push(`${slug}: says "${m[0]}", and the /dpa sub-processor table names ${usRow[1]} in the US`);
    }
    assert.deepEqual(denials, [], `\n  ${denials.join('\n  ')}\n`);
  }
  assert.ok(usRow, 'the /dpa table no longer names a US sub-processor; check /press and /privacy before deleting this assertion');
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 26 ── The two retentions the privacy policy left open. A signing envelope is
// kept for a fixed term (envelope.js) and a delivery receipt for fifteen minutes
// (relay.js); the page said "until its expiry" for the first and nothing at all
// for the second. Verified by sabotage: DEFAULT_TTL_DAYS 30 -> 31 and
// RECEIPT_TTL_MS 15 -> 20 minutes each turn this red.
test('the signing and receipt retentions on /privacy are the ones the relay applies', () => {
  const env = stripJsComments(read('relay/envelope.js'));
  const def = Number(/DEFAULT_TTL_DAYS\s*=\s*(\d+)/.exec(env)[1]);
  const max = Number(/MAX_TTL_DAYS\s*=\s*(\d+)/.exec(env)[1]);
  assert.ok(def > 0 && max >= def, 'envelope.js must declare a default and a maximum retention');
  const priv = visible(page('privacy'));
  assert.ok(priv.includes(`${def} days unless the request asks for another term, and never longer than ${max} days`),
    `privacy: the envelope retention must say ${def} days by default and ${max} days at most`);
  // /dpa is the document a controller signs, and its Hetzner row said the
  // capsule "may persist until envelope expiry": a term with no number in it.
  // Same two constants, same sentence, so the signed table cannot drift from
  // the policy page. Verified by the same sabotage as above.
  assert.ok(visible(page('dpa')).includes(`persist until the envelope expires: ${def} days unless the request asks for another term, and never longer than ${max} days`),
    `dpa: the sub-processor row must state the ${def} day default and the ${max} day maximum, not "until envelope expiry"`);

  const rly = stripJsComments(read('relay/relay.js'));
  const m = /RECEIPT_TTL_MS\s*=\s*(\d+)\s*\*\s*(\d+)\s*\*\s*(\d+)/.exec(rly);
  assert.ok(m, 'relay.js must declare RECEIPT_TTL_MS as a literal product');
  const minutes = (Number(m[1]) * Number(m[2]) * Number(m[3])) / 60000;
  assert.ok(priv.includes(`Redis · ${minutes} minutes, then deleted`),
    `privacy: the delivery-receipt row must say ${minutes} minutes`);
});

// 27 ── The CT log hash. ct-hash.js is SHA3-256 throughout and /dpa says so;
// /privacy said SHA-256 in the same table row, which is a different algorithm
// and the one the blob hash uses two rows above. Verified by sabotage: the row
// with SHA-256 in it fails here.
test('the CT-log hash named on /privacy and /dpa is the one ct-hash.js computes', () => {
  const src = stripJsComments(read('relay/lib/ct-hash.js'));
  const algos = [...new Set([...src.matchAll(/createHash\('([^']+)'\)/g)].map((m) => m[1]))];
  assert.deepEqual(algos, ['sha3-256'], `ct-hash.js now hashes with ${algos.join(', ')}; rewrite the CT-log rows`);
  const shown = 'SHA3-256';
  assert.ok(visible(page('privacy')).includes(`/data/ct-log.json · ${shown} one-way hash only`),
    `privacy: the CT-log row must name ${shown}`);
  assert.ok(visible(page('dpa')).includes(`device IDs hashed ${shown} in CT log`),
    `dpa: the data-minimisation row must name ${shown}`);
});

// 28 ── The browser-storage list. It named ps_free_uses "to enforce the 10/day
// limit client-side" and pm_docs_key; neither string exists anywhere in the
// repository, and the limit it described is 10 a month, not a day. Meanwhile the
// key the site really does write, an API key, was not on the list at all.
// Verified by sabotage: deleting any one <code> entry fails this by key name.
test('the browser storage /privacy lists is the storage the frontend writes', () => {
  const files = [];
  (function walk(dir, prefix) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) { if (!['node_modules', 'vendor', 'pkg'].includes(e.name)) walk(path.join(dir, e.name), `${prefix}${e.name}/`); continue; }
      if (/\.(js|mjs|html)$/.test(e.name)) files.push(`${prefix}${e.name}`);
    }
  })(path.join(ROOT, 'frontend'), '');
  assert.ok(files.length > 20, `the frontend walk found only ${files.length} files; the check would be vacuous`);

  const keys = new Set();
  for (const f of files) {
    const src = stripJsComments(read(`frontend/${f}`));
    for (const m of src.matchAll(/localStorage\.(?:get|set|remove)Item\(\s*['"`]([^'"`]+)/g)) keys.add(m[1]);
    // A key held in a constant, and a key built by a helper: both are used here.
    for (const m of src.matchAll(/localStorage\.(?:get|set|remove)Item\(\s*([A-Za-z_$][\w$]*)\s*[,)]/g)) {
      const c = new RegExp(`(?:const|let|var)\\s+${m[1]}\\s*=\\s*['"\`]([^'"\`]+)`).exec(src);
      if (c) keys.add(c[1]);
    }
    for (const m of src.matchAll(/localStorage\.(?:get|set|remove)Item\(\s*([A-Za-z_$][\w$]*)\(/g)) {
      const fn = new RegExp(`function\\s+${m[1]}\\s*\\([^)]*\\)\\s*\\{\\s*return\\s+['"\`]([^'"\`]+)`).exec(src);
      if (fn) keys.add(fn[1]);
    }
  }
  assert.ok(keys.size >= 5, `only ${keys.size} storage keys resolved; the check would be vacuous`);

  const priv = visible(page('privacy'));
  const list = priv.slice(priv.indexOf('<h2>Local storage in your browser</h2>'), priv.indexOf('</ul>', priv.indexOf('<h2>Local storage in your browser</h2>')));
  const named = [...list.matchAll(/<code>([^<]+)<\/code>/g)].map((m) => m[1].replace(/&hellip;$/, ''));
  const problems = [];
  for (const k of [...keys].sort()) {
    if (!named.some((n) => k === n || k.startsWith(n))) problems.push(`privacy: the frontend writes "${k}" and the storage list does not name it`);
  }
  for (const n of named) {
    if (![...keys].some((k) => k === n || k.startsWith(n))) problems.push(`privacy: the storage list names "${n}" and no frontend file writes it`);
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 29 ── The IP-logging row read as "we do not log requests", and for the hosted
// service that is what the config does. The self-host configuration in the same
// repository does the opposite: its log_format starts with $remote_addr. A
// self-hoster reading /security had no way to know. Verified by sabotage:
// dropping $remote_addr from the format fails the first assertion.
test('the self-host access log /security describes is the one the self-host config writes', () => {
  const conf = read('deploy/nginx-selfhost.conf').replace(/#.*$/gm, '');
  const fmt = /log_format\s+(\S+)\s+'([^;]*)';/s.exec(conf);
  assert.ok(fmt, 'deploy/nginx-selfhost.conf must define its access log format');
  assert.match(fmt[2], /^\$remote_addr/, 'the self-host log format no longer starts with the client address; rewrite the IP-logging row on /security');
  assert.match(conf, new RegExp(`access_log\\s+\\S+\\s+${fmt[1]};`), 'the self-host config must still use that format');
  const sec = visible(page('security'));
  assert.ok(sec.includes('<code>deploy/nginx-selfhost.conf</code> writes an access log whose first field is the client address'),
    'security: the IP-logging row must state what a self-hosted relay logs');
});

// 30 ── One city. /dpa and /privacy are the documents a customer relies on and
// both say Nuremberg; README said Frankfurt in the same table that claims EU
// jurisdiction. Nothing in this repository can prove which datacentre runs the
// service, but nothing in it may name two.
test('the repository names one Hetzner location, the one the DPA names', () => {
  const CITY = /Hetzner[^.<|\n]*?\b(Nuremberg|Frankfurt|Falkenstein|Helsinki|Ashburn|Hillsboro|Singapore)\b/g;
  const dpaCities = [...new Set([...visible(page('dpa')).matchAll(CITY)].map((m) => m[1]))];
  assert.deepEqual(dpaCities, ['Nuremberg'], `the DPA now names ${dpaCities.join(', ')}; this test follows the DPA, so update it deliberately`);
  const files = ['README.md', 'ROADMAP.md', 'SECURITY.md',
    ...publicPages().map((s) => `frontend/${s}.html`)];
  const problems = [];
  for (const f of files) {
    for (const m of read(f).matchAll(CITY)) {
      if (m[1] !== dpaCities[0]) problems.push(`${f}: names Hetzner ${m[1]}, the DPA says ${dpaCities[0]}`);
    }
  }
  assert.deepEqual(problems, [], `\n  ${problems.join('\n  ')}\n`);
});

// 31 ── Mollie is wired and unconditional. /v2/billing/checkout and
// /v2/billing/webhook are routed (relay.js), createPayment runs on every
// checkout, so the DPA row stays. What the row said it sends was wrong in both
// directions: it named an email address, which the payload does not carry
// while the recurring layer is off, and it did not name the four metadata keys
// it does carry. /privacy and /terms were a version behind the code as well:
// both still said billing was not live and that plans were arranged by hand,
// while production has taken one-off Mollie payments since 2026-08-08 and takes
// no subscriptions because BILLING_MODE is unset. Verified by sabotage in both
// directions: renaming a metadata key in relay.js turns this red, so does
// editing the row on /dpa; making billingStance recurring by default turns the
// stance half red, so does putting "not yet live" back on /privacy or /terms.
test('the Mollie row on /dpa is the payload relay.js sends, and the stance the pages describe is the one mollie.js takes', async () => {
  const rly = stripJsComments(read('relay/relay.js'));
  for (const route of ['/v2/billing/checkout', '/v2/billing/webhook']) {
    assert.ok(rly.includes(`path === '${route}'`), `relay.js no longer routes ${route}; the Mollie sub-processor row may need to go`);
  }
  const at = rly.indexOf('mollie.createPayment(');
  assert.ok(at > 0, 'relay.js must still build the Mollie payment inline; this block reads that payload');
  const payload = rly.slice(at, rly.indexOf('}, customerId', at));
  const fields = [...payload.matchAll(/^\s{8}(\w+):/gm)].map((m) => m[1]);
  assert.deepEqual(fields, ['amount', 'description', 'redirectUrl', 'webhookUrl', 'metadata'],
    `the checkout payload now sends ${fields.join(', ')}; the /dpa data column has to say so`);
  const meta = /metadata:\s*\{([^}]*)\}/.exec(payload);
  assert.ok(meta, 'the checkout payload must still carry a metadata object');
  const metaKeys = meta[1].split(',').map((k) => k.split(':')[0].trim()).filter(Boolean);
  assert.deepEqual(metaKeys, ['accountId', 'product', 'plan', 'interval'],
    `the payment metadata is now ${metaKeys.join(', ')}; the /dpa and /privacy columns name the old set`);
  assert.ok(!/email/i.test(payload),
    'the checkout payload now carries an email field; /dpa and /privacy say no email address is sent');

  // The only place an address could reach Mollie is the customer record, and
  // that whole step is skipped while the recurring layer is off.
  const rec = stripJsComments(read('relay/lib/billing-recurring.js'));
  assert.match(rec, /if \(!recurringAllowed\(d\)\) return \{ customerId: null, result: 'skipped', reason: 'recurring_disabled' \}/,
    'ensureCustomer no longer skips on a disabled recurring layer; an email address may now reach Mollie');
  assert.match(rec, /email:\s*\(rec && rec\.email\)/,
    'the customer record no longer sends the account email; rewrite the Mollie rows rather than delete this line');

  // The stance itself, called rather than pattern-matched: an unset
  // BILLING_MODE with a live key is production today, and it is one-off only.
  const { createRequire } = await import('node:module');
  const mollieLib = createRequire(import.meta.url)(path.join(ROOT, 'relay/lib/mollie.js'));
  const savedEnv = { BILLING_MODE: process.env.BILLING_MODE, MOLLIE_API_KEY: process.env.MOLLIE_API_KEY, MOLLIE_TEST_API_KEY: process.env.MOLLIE_TEST_API_KEY };
  try {
    delete process.env.BILLING_MODE; delete process.env.MOLLIE_TEST_API_KEY;
    process.env.MOLLIE_API_KEY = 'live_siteclaims_stance_pin';
    assert.equal(mollieLib.billingStance().recurring, false,
      'an unset BILLING_MODE now opens the recurring layer; /privacy and /terms say there are no subscriptions');
    process.env.BILLING_MODE = 'live';
    assert.equal(mollieLib.billingStance().recurring, true,
      'BILLING_MODE=live no longer switches the recurring layer on; the stance the pages describe has moved');
  } finally {
    for (const [k, v] of Object.entries(savedEnv)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }

  const dpaPage = visible(page('dpa'));
  assert.ok(dpaPage.includes(`the payment metadata the relay sets: ${metaKeys.join(', ')}`),
    `dpa: the Mollie data column must name the metadata keys relay.js sends (${metaKeys.join(', ')})`);
  assert.ok(dpaPage.includes('The amount, a plan description'),
    'dpa: the Mollie data column must name the amount and the description, which are what the payload also carries');
  assert.ok(dpaPage.includes('No email address is sent while recurring billing is off'),
    'dpa: the Mollie data column must say no email address is sent, because the payload carries none');

  const privPage = visible(page('privacy'));
  assert.ok(privPage.includes(`payment metadata (${metaKeys.join(', ')})`),
    'privacy: the Mollie entry must name the same metadata keys');
  assert.ok(privPage.includes('Every payment is a one-off for the term you buy; there are no subscriptions'),
    'privacy: the Mollie entry must describe the stance the code takes, which is one-off payments only');
  const termsPage = visible(page('terms'));
  assert.ok(termsPage.includes('Every checkout is a one-off payment for the term you buy.'),
    'terms: the payment paragraph must describe one-off payments');
  assert.ok(termsPage.includes('Automatic renewal is not switched on'),
    'terms: the payment paragraph must say renewal is not automatic while the recurring layer is off');

  const stale = [];
  for (const slug of publicPages()) {
    const text = visible(page(slug));
    for (const re of [/[Bb]illing is not yet live/, /automated billing is not yet live/, /arranged by hand, by e-mail/, /arranged manually/, /once billing is enabled/]) {
      const m = re.exec(text);
      if (m) stale.push(`${slug}: says "${m[0]}", and the relay has taken Mollie payments since billing exists`);
    }
  }
  assert.deepEqual(stale, [], `\n  ${stale.join('\n  ')}\n`);
});

// 32 ── Who gets a DPA. POST /v2/sign-dpa is in the ALLOWED path list for every
// relay profile and its handler checks a name, an organisation, an email and a
// rate limit, and nothing else: no API key, no plan, no account. So the DPA is
// public, and "applies to all plans" on /pricing was the one sentence out of
// four that matched the code. The other three (a paid-tier-only line on
// /pricing, "For Pro and Enterprise customers" on /privacy, an Enterprise
// bullet on the tier card) described a gate that does not exist.
// /audit-log-export went the other way and denied the position the whole of
// /dpa takes. Verified by sabotage in both directions: adding an unauthorized
// check to the handler turns this red, and so does putting a tier back in front
// of the DPA on any page.
test('the DPA the pages offer is the public endpoint relay.js serves', () => {
  const rly = stripJsComments(read('relay/relay.js'));
  const allowed = /const ALLOWED = \{([\s\S]*?)\n\};/.exec(rly);
  assert.ok(allowed, 'relay.js must still declare the per-profile ALLOWED path list');
  for (const profile of ['ghost_pipe', 'iot']) {
    const list = new RegExp(`${profile}:\\s*\\[([\\s\\S]*?)\\]`).exec(allowed[1]);
    assert.ok(list && list[1].includes(`'/v2/sign-dpa'`), `relay.js: ${profile} no longer allows /v2/sign-dpa; the DPA is no longer reachable everywhere the pages say`);
  }
  const at = rly.indexOf(`path === '/v2/sign-dpa'`);
  assert.ok(at > 0, 'relay.js must still handle POST /v2/sign-dpa');
  const handler = rly.slice(at, rly.indexOf(`  if (path === `, at + 10));
  assert.ok(handler.length > 500, 'the /v2/sign-dpa handler could not be sliced; this block would assert on nothing');
  for (const gate of [/!keyData/, /unauthorized/, /requireAuth/, /plan\s*===/]) {
    assert.doesNotMatch(handler, gate, 'the /v2/sign-dpa handler now gates on an account or a plan; the pages say the DPA applies to all plans');
  }
  assert.match(handler, /if \(!name \|\| !org \|\| !email\)/, 'the handler must still require a name, an organisation and an email');
  assert.match(handler, /Too many requests/, 'the handler must still rate limit; a public endpoint without one is a different claim');

  const SCOPE = 'applies to all plans';
  for (const slug of ['pricing', 'privacy', 'audit-log-export']) {
    assert.ok(visible(page(slug)).toLowerCase().includes(SCOPE), `${slug}: must say the DPA ${SCOPE}, because the endpoint has no gate`);
  }
  // The homepage is the page a buyer reads first, and it listed a signed DPA as
  // an Enterprise feature while the endpoint asks nobody for a plan. #382 fixed
  // the sentence; this is what stops it coming back, on any page, in any tier
  // list. Scoped to list items that name a tier, because /index says "that is
  // in the signed Data Processing Agreement" in a breach-notification sentence
  // where the phrase is right.
  assert.ok(visible(page('index')).includes('The Data Processing Agreement applies to every plan.'),
    'index: the homepage must say the DPA applies to every plan, because the endpoint gates on nothing');
  // Two shapes carry a tier's feature list, and the sweep has to know both: the
  // one-line form on /index (<li> ... <b>Enterprise</b> ... </li>) and the card
  // on /pricing (a tier-name heading followed by its own <ul>). Scanning only
  // the <li> found the first and walked straight past the second.
  const ENTERPRISE_REGIONS = (html) => {
    const out = [];
    for (const li of html.match(/<li\b[\s\S]*?<\/li>/g) || []) {
      if (/<b>Enterprise<\/b>/.test(li)) out.push(li);
    }
    let at = html.indexOf('tier-name">Enterprise');
    while (at !== -1) {
      const end = html.indexOf('</ul>', at);
      out.push(html.slice(at, end === -1 ? at + 2000 : end));
      at = html.indexOf('tier-name">Enterprise', at + 1);
    }
    return out;
  };
  const tierGated = [];
  let regionsSeen = 0;
  for (const slug of publicPages()) {
    for (const region of ENTERPRISE_REGIONS(page(slug))) {
      regionsSeen += 1;
      const m = /signed DPA|signed Data Processing Agreement/i.exec(region);
      if (m) tierGated.push(`${slug}: lists "${m[0]}" as an Enterprise feature, and /v2/sign-dpa asks nobody for a plan`);
    }
  }
  assert.ok(regionsSeen >= 3, `only ${regionsSeen} Enterprise feature lists found; the sweep stopped seeing the lists it exists for`);
  assert.deepEqual(tierGated, [], `\n  ${tierGated.join('\n  ')}\n`);

  const gated = [];
  const GATES = [
    /available on request for all paid tiers/i,
    /For Pro and Enterprise customers we provide a/i,
    /relay does not process personal data/i,
  ];
  for (const slug of allPages()) {
    const text = visible(page(slug));
    for (const re of GATES) {
      const m = re.exec(text);
      if (m) gated.push(`${slug}: says "${m[0]}", which the /v2/sign-dpa handler and /dpa both contradict`);
    }
  }
  assert.deepEqual(gated, [], `\n  ${gated.join('\n  ')}\n`);
});

// 33 ── The host-hardening numbers. /dpa row "Integrity and availability" and
// the CIS section of SECURITY.md quote the same audit, and nothing kept them
// equal: either could be edited alone and stay green. Neither file proves the
// host is in that state, and this block does not claim it does; it only forbids
// the repository from quoting two different figures for one benchmark.
// Verified by sabotage in both directions: 49 to 48 in SECURITY.md, or 114 to
// 113 on /dpa, each turn this red.
test('the hardening figures on /dpa are the ones SECURITY.md records', () => {
  const sec = read('SECURITY.md');
  const bench = /### [\d-]+ [^\n]*CIS Ubuntu ([\d.]+) benchmark/.exec(sec);
  assert.ok(bench, 'SECURITY.md must still record the CIS Ubuntu benchmark section');
  const checks = /^(\d+) checks applied across/m.exec(sec);
  assert.ok(checks, 'SECURITY.md must still state how many CIS checks were applied');
  const rules = /\|\s*auditd\s*\|\s*(\d+) CIS L2 rules loaded\s*\|/.exec(sec);
  assert.ok(rules, 'SECURITY.md must still state the auditd rule count');
  assert.match(sec, /\|\s*AIDE\s*\|\s*Installed, daily integrity check\s*\|/, 'SECURITY.md must still record the daily AIDE check');
  assert.match(sec, /\|\s*AppArmor\s*\|\s*\d+\/\d+ profiles enforcing\s*\|/, 'SECURITY.md must still record AppArmor enforcing');

  const row = visible(page('dpa'));
  assert.ok(row.includes(`auditd (${rules[1]} CIS L2 rules)`), `dpa: the Article 32 row must say ${rules[1]} auditd rules, the figure SECURITY.md records`);
  assert.ok(row.includes(`CIS Ubuntu ${bench[1]} L2 benchmark \u2014 ${checks[1]} checks`), `dpa: the Article 32 row must say CIS Ubuntu ${bench[1]} and ${checks[1]} checks`);
  assert.ok(row.includes('AIDE daily file integrity check'), 'dpa: the Article 32 row must name the daily AIDE check SECURITY.md records');
  assert.ok(row.includes('AppArmor enforcing'), 'dpa: the Article 32 row must name AppArmor enforcing');
});

// 34 ── The signature level. /about and /parasign name it: a Simple Electronic
// Signature. /sign and /co-sign, the two screens where somebody actually signs,
// said only what it is not. A reader who has just been told the thing is not
// eIDAS-qualified is owed the level it does reach, in the same box.
// Verified by sabotage in both directions: dropping SES from any of the four
// turns this red, and so does adding an eIDAS disclaimer to a fifth page
// without naming the level.
test('every page that says the signature is not eIDAS-qualified names the level it does reach', () => {
  const LEVEL = 'Simple Electronic Signature (SES)';
  const named = [];
  const bare = [];
  for (const slug of allPages()) {
    const text = visible(page(slug));
    if (!/[Nn]ot eIDAS-qualified/.test(text) && !text.includes(LEVEL)) continue;
    if (text.includes(LEVEL)) named.push(slug); else bare.push(`${slug}: says the signature is not eIDAS-qualified and never names the level it is`);
  }
  assert.deepEqual(bare, [], `\n  ${bare.join('\n  ')}\n`);
  for (const slug of ['about', 'parasign', 'sign', 'co-sign']) {
    assert.ok(named.includes(slug), `${slug}: must name the signature level as a ${LEVEL}`);
  }
  const qes = [];
  for (const slug of named) {
    if (!/\(QES\)/.test(visible(page(slug)))) qes.push(`${slug}: names SES without naming the qualified level it is not`);
  }
  assert.deepEqual(qes, [], `\n  ${qes.join('\n  ')}\n`);
});

// 35 ── The edge access log, which no page described. /privacy said an IP is
// "processed only transiently", and the web server config in this repository
// backs that up: it logs nothing. The edge in front of it is not in this
// repository and it logs everything, which is how the sentence survived every
// review: scripts/access-log-visitors.mjs exists to read those files and its
// own test cites real ones. So the page named a property of the half of the
// stack that is checked in.
//
// The admin half of this block is gone, and deliberately. When it was written,
// three console lines in admin/server.js wrote a full client IP and one of them
// the account email; #374 landed first and masked all three at the call site.
// That claim now belongs to admin/test/log-redact.test.js and to row 9, which
// pin it at the source. Repeating it here would be a second, weaker copy of
// somebody else's pin. What is left here is the guard that /privacy cannot go
// back to describing raw admin lines, plus the log that is genuinely only
// described because of this pull request.
//
// Verified by sabotage in both directions: deleting the section on /privacy,
// putting "only transiently" back, and taking the access-log reader out of
// scripts/ each turn this red.
test('the logs that hold an address are the ones /privacy names, with the bounds the code applies', () => {
  const reader = read('scripts/access-log-visitors.mjs');
  assert.match(reader, /access\.log/, 'scripts/access-log-visitors.mjs must still be the tool that reads the edge access log');
  assert.match(reader, /remote_addr|\bip\b/i, 'the reader must still work on client addresses; if it stopped, say so on /privacy');

  const priv = visible(page('privacy'));
  assert.ok(priv.includes('<h2>Logs that hold an address</h2>'),
    'privacy: the section naming the logs must still be on the page');
  assert.ok(priv.includes('Our own edge writes a server access log with the client address'),
    'privacy: the edge access log must be described, because a script in this repository reads it');
  assert.ok(priv.includes('The nginx configuration in this repository logs nothing; the edge in front of it does'),
    'privacy: the difference between the config in this repository and the edge must be stated');
  assert.doesNotMatch(priv, /an IP is processed only transiently/,
    'privacy: "only transiently" is not true of the edge access log');

  // The admin lines are masked at the call site now (#374). /privacy describes
  // that masking, so it may not go back to claiming raw lines, and the sentence
  // it does carry has to stay true of the helper that does the masking.
  const redact = read('admin/lib/log-redact.js');
  assert.match(redact, /function maskIpForLog\s*\(/, 'admin/lib/log-redact.js must still mask a client address for the process log');
  assert.match(redact, /function maskEmailForLog\s*\(/, 'admin/lib/log-redact.js must still mask an email address for the process log');
  assert.ok(priv.includes('an address is truncated to its network before it is written'),
    'privacy: the admin log entry must describe the masking admin/lib/log-redact.js applies');
  assert.doesNotMatch(priv, /Three operational lines write the client IP/,
    'privacy: the admin lines no longer write a client IP; #374 masked them at the call site');

  // The audit trail. The row this block first wrote said the audit log was
  // "capped by volume, not by time", and both halves of that were wrong:
  // admin/lib/audit.js trims by score as well as by rank, so there is an age
  // bound, and what it stores is not a client IP but its network part. A page
  // that understates a retention is not being careful, it is being wrong in the
  // direction that flatters us.
  const audit = stripJsComments(read('admin/lib/audit.js'));
  const days = /AUDIT_RETENTION_DAYS\s*\|\|\s*'(\d+)'/.exec(audit);
  assert.ok(days, 'admin/lib/audit.js must still declare a default retention in days');
  const maxEntries = /MAX_ENTRIES\s*=\s*(\d+)/.exec(audit);
  assert.ok(maxEntries, 'admin/lib/audit.js must still declare a per-account entry ceiling');
  assert.match(audit, /zRemRangeByScore\(userKey, 0, cutoff\)/,
    'admin/lib/audit.js no longer trims the audit trail by age; the 400 day bound on /privacy would be a promise nothing keeps');
  assert.match(audit, /zRemRangeByRank\(userKey, 0, -1001\)/,
    'admin/lib/audit.js no longer trims the audit trail by count; the per-account ceiling on /privacy would be unbacked');
  // The mask shape, read off the code rather than restated: p[0].p[1].x.x is a
  // /16, which is what the page has to show an example of.
  const v4mask = /return `\$\{p\[0\]\}\.\$\{p\[1\]\}\.x\.x`/.test(audit);
  assert.ok(v4mask, 'admin/lib/audit.js no longer masks an audit IPv4 to its /16; rewrite the audit rows on /privacy');
  assert.match(audit, /s\.split\(':'\)\.slice\(0, 2\)\.join\(':'\) \+ '::x'/,
    'admin/lib/audit.js no longer masks an audit IPv6 to its first two groups; rewrite the audit rows on /privacy');

  assert.ok(priv.includes(`at most ${days[1]} days, and at most ${maxEntries[1]} entries per account`),
    `privacy: the audit row must state the ${days[1]} day and ${maxEntries[1]} entry bounds admin/lib/audit.js applies`);
  assert.ok(priv.includes('1.2.x.x'),
    'privacy: the audit rows must show the masked form, not claim a full client IP is stored');
  assert.ok(priv.includes(`nothing older than ${days[1]} days survives, and an account keeps at most its last ${maxEntries[1]} entries`),
    'privacy: the audit entry must say the trail is bounded by age as well as by count');
  assert.doesNotMatch(priv, /audit log[^<]*capped by volume, not by time/,
    'privacy: the audit log is bounded by age too; that sentence is false');
});

// 36 -- The norm mappings. /pricing said "NEN 7510, eIDAS, and IEC 62443
// mappings ship with Pro and Enterprise", and the round before this one called
// that unbacked because the only artefact it looked at was an ASVS checklist.
// Both readings were wrong. Two of the three mappings are written and in the
// tree: an IEC 62443 requirement table in docs/ot-guide.md and a NEN 7510 table
// in docs/dicom-guide.md, and both are served under frontend/docs/ where a
// Community account reads them for nothing. So the false half of the sentence
// was never "these exist"; it was "ship with Pro and Enterprise", which sells
// as a paid deliverable something that is public. eIDAS is the one with no
// mapping document at all, and the page now says so.
// Verified by sabotage in both directions: deleting either mapping section, or
// putting a plan back in front of the mappings on any page, turns this red.
test('the norm mappings the site claims are the ones written in the tree, and no plan gates them', () => {
  const iec = read('docs/ot-guide.md');
  assert.match(iec, /^##\s+IEC 62443 compliance mapping\s*$/m,
    'docs/ot-guide.md no longer carries the IEC 62443 mapping section; /pricing claims it exists');
  assert.match(iec, /\|\s*IEC 62443 Requirement\s*\|/,
    'the IEC 62443 mapping must still be a requirement table, which is what /pricing calls it');

  const nen = read('docs/dicom-guide.md');
  const nenRows = [...nen.matchAll(/^\|.*NEN 7510.*\|$/gm)];
  assert.ok(nenRows.length >= 3,
    `docs/dicom-guide.md carries ${nenRows.length} NEN 7510 table rows; /pricing calls it a mapping table`);

  // Published, not shipped. Both guides are served from frontend/docs/, so the
  // paid-tier framing was wrong about the delivery as well as the artefact.
  for (const f of ['ot-guide.md', 'dicom-guide.md']) {
    assert.ok(fs.existsSync(path.join(ROOT, 'frontend/docs', f)),
      `frontend/docs/${f} is gone; if a mapping stopped being public, /pricing may not call it free to read`);
  }
  assert.match(read('frontend/docs/ot-guide.md'), /^##\s+IEC 62443 compliance mapping\s*$/m,
    'the served OT guide lost the mapping section the repository copy still has');
  assert.match(read('frontend/docs/dicom-guide.md'), /NEN 7510/,
    'the served DICOM guide lost the NEN 7510 mapping the repository copy still has');

  // eIDAS is the one that has no mapping document. If somebody writes one, this
  // goes red and the sentence on /pricing gets to change with it.
  const docFiles = fs.readdirSync(path.join(ROOT, 'docs')).filter((f) => f.endsWith('.md') && f !== 'site-claims.md');
  const eidasMappings = docFiles.filter((f) => /^#{1,3}\s+.*eIDAS.*mapping/im.test(read(`docs/${f}`)));
  assert.deepEqual(eidasMappings, [],
    `an eIDAS mapping now exists in ${eidasMappings.join(', ')}; /pricing says there is none`);

  const pricing = visible(page('pricing'));
  assert.ok(pricing.includes('an IEC 62443 requirement table in the OT guide, and a NEN 7510 table in the DICOM guide'),
    'pricing: the compliance paragraph must name the two mappings that exist');
  assert.ok(pricing.includes('There is no eIDAS mapping document.'),
    'pricing: the one mapping that does not exist must be named as absent');

  const gated = [];
  for (const slug of publicPages()) {
    const text = visible(page(slug));
    for (const re of [/mappings ship with [A-Z]/, /mappings? (?:are )?available (?:on request )?(?:for|to) [A-Z]/, /IEC 62443[^.<]{0,40}\bonly on\b/]) {
      const m = re.exec(text);
      if (m) gated.push(`${slug}: says "${m[0]}", and both mappings are public and ungated`);
    }
  }
  assert.deepEqual(gated, [], `\n  ${gated.join('\n  ')}\n`);
});

// 37 -- Burn-on-read, and the two things the site was wrong about at once.
//
// WHICH PLAN. tiers.js gives a link 1 read on Community and more on a paid plan
// (Pro 10, Business 25, Enterprise 100), so "the file is gone after the first
// read" is true on the free plan and false on every plan a customer pays for.
// That was the sweep block 24 named and left for a batch of its own.
//
// WHICH CLIENT. The read count is an API parameter, and the clients most of the
// site is about never send it. frontend/js/parashare.page.js does not, and
// neither does extensions/shared/paramant-core.js, which is the single upload
// path for both the Chromium extension and the Outlook add-in. relay.js
// defaults a transfer that asks for nothing to a single read on every plan, so
// through the web app and through either extension the file really does go on
// the first read whatever the sender pays. The first version of this block
// treated that as an escape hatch for those pages. It is the opposite: on a
// page about a client that cannot ask for more reads, offering the reader "up
// to 10 reads on Pro" sells something that client will never do. So the pages
// in CLIENT_ONLY below may qualify a claim ONLY by naming the client, and a
// paid read count may appear there only with the API named in the same breath.
//
// One formulation, site-wide: "wiped after the last read the link allows",
// short-formed as "after its last read". A sentence in that shape needs no
// qualification because it names no count; a sentence that says one read does.
// The earlier round left five wordings of the same idea on the page and this
// block now forbids the ones it replaced.
//
// Why the first pattern list missed five true sentences (parasend "opens it
// once and the file is wiped" and "until the read burns it", index "gone after
// it is read", security "Deleted on burn" and "zeroed immediately on
// download"): it was written FROM the sentences the grep had surfaced, so it
// matched those wordings and nothing else. Every miss was a different erase
// verb (zeroed, deleted), a different name for the moment (on burn, not on
// read), or the two halves in the other order. The list below is built from two
// vocabularies crossed against each other instead of from a list of sentences.
//
// The sweep also covers the signed-in screens now. /dashboard and /auth/setup
// are outside publicPages and both carried the flat claim.
//
// Verified by sabotage in every direction:
//   * universalise any rewritten sentence: red, naming page and sentence;
//   * put "up to 10 reads on Pro" back on /parasend: red, because /parasend is
//     about the web app and the count is not the API's there;
//   * tiers.js pro.max_views 10 -> 1: red, the qualification is then false the
//     other way round;
//   * pro 10 -> 12: red, the copy numbers stop matching;
//   * make the web app or either extension send max_views: red, the client
//     formulation loses its ground.
test('every page that promises burn-on-read says which client and which plan it holds for', () => {
  const tiersSrc = read('relay/lib/tiers.js');
  const viewsOf = (tier) => {
    const m = /max_views:\s*(\d+)/.exec(tiersSrc.slice(tiersSrc.indexOf(`${tier}:`)));
    assert.ok(m, `tiers.js ${tier} must declare a literal max_views`);
    return Number(m[1]);
  };
  const reads = {
    community: viewsOf('community'), pro: viewsOf('pro'),
    business: viewsOf('business'), enterprise: viewsOf('enterprise'),
  };
  assert.equal(reads.community, 1,
    'community no longer burns on the first read; the Community qualification this block requires is now the wrong sentence');
  for (const paid of ['pro', 'business', 'enterprise']) {
    assert.ok(reads[paid] > reads.community,
      `${paid} now allows ${reads[paid]} reads, the same as Community: burn-on-read is universal again, and every page that says a paid link buys more reads is promising something the relay does not grant`);
  }

  // The clients that cannot ask for a second read, pinned to the lines that
  // make that true. Any of these changing turns the client sentences false.
  const relaySrc = stripJsComments(read('relay/relay.js'));
  assert.match(relaySrc, /const maxViews = Math\.max\(1, Math\.min\(parseInt\(reqMaxViews \|\| 1\) \|\| 1, _psend\.limits\.max_views \|\| 1\)\)/,
    'relay.js no longer defaults a transfer that asks for no max_views to a single read; every page that says the web app or an extension goes on the first read has lost its ground');
  assert.match(relaySrc, /apiKey: null, max_views: 1, views_remaining: 1/,
    'the anonymous inbound path no longer pins a single read');
  assert.match(read('frontend/js/parashare.page.js'), /hash, payload: toB64\(padded\), ttl_ms: ttlMs,/,
    'the ParaSend web app upload body changed shape; check it still asks for no read count before trusting the sentences that say so');
  assert.match(read('extensions/shared/paramant-core.js'), /const body = JSON\.stringify\(\{ hash, payload: toBase64\(padded\), ttl_ms: ttlMs, meta \}\);/,
    'the extension upload body changed shape; both extension pages promise the file goes on the first read on every plan because this body carries no max_views');
  const jsUnder = (dir) => fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true }).flatMap((e) => {
    if (e.isDirectory()) return e.name === 'node_modules' ? [] : jsUnder(`${dir}/${e.name}`);
    return e.isFile() && /\.(js|mjs|ts)$/.test(e.name) ? [`${dir}/${e.name}`] : [];
  });
  const asks = [
    ...['frontend/js/parashare.page.js'].filter((f) => /max_views/.test(stripJsComments(read(f)))),
    ...jsUnder('extensions').filter((f) => /max_views/.test(stripJsComments(read(f)))),
  ];
  assert.deepEqual(asks, [],
    `${asks.join(', ')} now asks the relay for a read count; the pages about that client may no longer say the file goes on the first read on every plan`);

  // What a visitor reads, body only. /docs ships no <body> tag at all, so fall
  // back to the end of the head rather than scanning the JSON-LD and the meta
  // descriptions, which this batch deliberately does not touch.
  const bodyOf = (html) => {
    const i = html.search(/<body[\s>]/i);
    const j = i >= 0 ? i : html.indexOf('</head>');
    let body = html.slice(j >= 0 ? j : 0)
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ');
    // Tier-card feature lists out: scoped by their card, pinned separately.
    return body.replace(/<ul[^>]*>[\s\S]*?<\/ul>/gi, (m, off, src) =>
      /tier-name|tier-card/.test(src.slice(Math.max(0, off - 500), off)) ? ' ' : m);
  };
  const flatten = (s) => s
    .replace(/<[^>]+>/g, ' ')
    .replace(/&rsquo;/g, "'").replace(/&nbsp;/g, ' ').replace(/&mdash;/g, '-')
    .replace(/&euro;/g, 'EUR').replace(/&middot;/g, '.').replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ').trim();
  // One paragraph = the text between two block starts. Rows and preformatted
  // blocks count as paragraphs; table cells do not, so a value cell may be
  // qualified by the label cell beside it.
  const paragraphs = (body) => {
    const cut = /<p[\s>]|<li[\s>]|<tr[\s>]|<h[1-6][\s>]|<pre[\s>]|<\/pre>|<section[\s>]|<div class="faq-item"|<div class="k">|<span class="badge"/gi;
    const at = [0];
    let m;
    while ((m = cut.exec(body))) at.push(m.index);
    at.push(body.length);
    return at.slice(0, -1).map((start, i) => flatten(body.slice(start, at[i + 1]))).filter(Boolean);
  };

  // Two vocabularies. A claim is an erase verb standing next to a moment that
  // names ONE read, in either order, plus the handful of phrases that say it
  // without a verb. "after its last read" and "after the last read the link
  // allows" are deliberately not moments: they name no count, which is the
  // whole point of the site using one formulation for this.
  const ERASE = 'burn(?:s|ed|ing)?|destroy(?:s|ed|ing)?|wipe(?:s|d)?|erase[sd]?|delete[sd]?|zeroe?[sd]?|remove[sd]?|gone|vanish(?:es)?';
  const MOMENT = [
    'on (?:read|burn|download|opening)',
    'on (?:the )?first (?:read|open|opening|download)',
    'after (?:the )?(?:first|one|a single)(?: successful)? (?:read|open|opening|download)',
    'after one read',
    'after (?:it is|being|it has been) read',
    'until (?:the|its|a) read\\b',
    'once (?:it is|it has been) read',
    'opens? (?:it|the link|the file) once',
    'downloads it once',
  ].join('|');
  const CLAIM = [
    new RegExp(`\\b(?:${ERASE})\\b[^.<]{0,40}\\b(?:${MOMENT})`, 'i'),
    new RegExp(`\\b(?:${MOMENT})\\b[^.<]{0,60}\\b(?:${ERASE})\\b`, 'i'),
    /\bgone the moment\b/i,
    /\bexactly one opening\b/i,
    /\bsingle-use guarantee\b/i,
    /\bone (?:download|retrieval|read|opening) only\b/i,
    /\bburn-on-first-read\b/i,
    /\buntil (?:the )?first (?:read|download|open)\b/i,
  ];

  // The screens a customer reaches after signing in are not in publicPages, and
  // both of them carried the flat claim. /get, /ontvang and /parashare are the
  // share flow, which anyone with a link opens without an account.
  const SIGNED_IN = ['dashboard', 'auth/setup', 'get', 'ontvang', 'parashare'];
  const everyPage = [...publicPages(), ...SIGNED_IN];
  // Pages about a client that never sends max_views. Naming a plan is not a
  // qualification here; naming the client is.
  const CLIENT_ONLY = new Set([
    'parasend', 'get', 'ontvang', 'parashare', 'dashboard', 'auth/setup',
    'help/gmail-extension', 'help/outlook-extension',
  ]);
  const CLIENT = /\bweb app\b|\bextensions?\b|\badd-in\b/i;
  const PLAN = [/\bCommunity\b/, new RegExp(`up to ${reads.pro} reads`, 'i')];

  const unqualified = [];
  const mentioning = new Set();
  for (const slug of everyPage) {
    const clientOnly = CLIENT_ONLY.has(slug);
    for (const para of paragraphs(bodyOf(page(slug)))) {
      if (/^burn[- ]on[- ]read$/i.test(para)) continue; // the feature's name, used as a heading
      if (/\bburn|last read|deletes itself|first read|wiped after|destroyed after\b/i.test(para)) mentioning.add(slug);
      const hit = CLAIM.find((re) => re.test(para));
      if (!hit) continue;
      const ok = clientOnly ? CLIENT.test(para) : (CLIENT.test(para) || PLAN.some((re) => re.test(para)));
      if (ok) continue;
      unqualified.push(clientOnly
        ? `${slug}: "${hit.exec(para)[0]}" is a page about a client that never sends max_views, so it must name that client, not a plan. Paragraph: ${para.slice(0, 160)}`
        : `${slug}: "${hit.exec(para)[0]}" states burn-on-read for every plan, and tiers.js gives Pro ${reads.pro} reads per link. Paragraph: ${para.slice(0, 160)}`);
    }
  }
  assert.deepEqual(unqualified, [], `\n  ${unqualified.join('\n  ')}\n`);
  assert.ok(mentioning.size >= 10,
    `only ${mentioning.size} pages still describe how long a transfer lives; the patterns above have stopped matching the site and this block is measuring nothing`);

  // A paid read count on a client page has to say where it comes from. Without
  // "through the API" the sentence sells the reader something the client he is
  // reading about will never ask for.
  const sold = [];
  for (const slug of everyPage) {
    if (!CLIENT_ONLY.has(slug)) continue;
    for (const para of paragraphs(bodyOf(page(slug)))) {
      const m = /up to (\d+)(?: reads?)? on (?:Pro|Business|Enterprise)/i.exec(para);
      if (m && !/through the API/i.test(para)) {
        sold.push(`${slug}: says "${m[0]}", and the client this page is about never sends max_views. Name the API in the same paragraph or drop the number.`);
      }
    }
  }
  assert.deepEqual(sold, [], `\n  ${sold.join('\n  ')}\n`);

  // Every read count the site names is the one tiers.js grants.
  const BY_NAME = { community: 'community', pro: 'pro', business: 'business', enterprise: 'enterprise' };
  const drifted = [];
  for (const slug of everyPage) {
    const text = flatten(bodyOf(page(slug)));
    for (const m of text.matchAll(/up to (\d+) reads? on (Community|Pro|Business|Enterprise)/gi)) {
      const want = reads[BY_NAME[m[2].toLowerCase()]];
      if (Number(m[1]) !== want) drifted.push(`${slug}: says "${m[0]}", tiers.js grants ${want}`);
    }
  }
  assert.deepEqual(drifted, [], `\n  ${drifted.join('\n  ')}\n`);

  // One formulation. These are the wordings it replaced, and they may not come
  // back beside it: five ways of saying the same thing is how the site drifted
  // into saying it wrong in the first place.
  const stale = [];
  for (const slug of everyPage) {
    const m = /once the reads[^.<]{0,30}spent|when the last read is spent/i.exec(flatten(bodyOf(page(slug))));
    if (m) stale.push(`${slug}: says "${m[0]}"; the site says this one way, "after the last read the link allows"`);
  }
  assert.deepEqual(stale, [], `\n  ${stale.join('\n  ')}\n`);

  // The sentence itself, on the pages that have to carry it whole, with the
  // numbers written off tiers.js so a policy change moves the copy with it.
  const unified = `The web app and the extensions delete the file after the first read on every plan. Through the API a paid link can allow more reads: up to ${reads.pro} reads on Pro, ${reads.business} on Business and ${reads.enterprise} on Enterprise.`;
  for (const slug of ['parasend', 'pricing', 'help/gmail-extension', 'help/outlook-extension']) {
    assert.ok(flatten(bodyOf(page(slug))).includes(unified),
      `${slug}: must carry the client-and-plan sentence in full: "${unified}"`);
  }
  // And the buyer has to be told why more reads is worth paying for, or the
  // honest version reads as a downgrade next to "burns on the first read".
  for (const slug of ['parasend', 'pricing']) {
    assert.ok(flatten(bodyOf(page(slug))).includes('one link a whole team can open'),
      `${slug}: more reads has to be sold as a feature, not confessed as a weaker promise`);
  }

  // The ParaSend tier cards, which are where a buyer reads the number before he
  // pays for it. Community's card is the one page element allowed to say "Burn
  // on first read" flat, because the card it sits in is the plan.
  const pricingSrc = page('pricing');
  assert.ok(pricingSrc.includes('<li>Burn on first read</li>'),
    'pricing: the ParaSend Community card must still say the link burns on the first read');
  assert.ok(pricingSrc.includes(`<li>Up to ${reads.pro} reads per link</li>`),
    `pricing: the ParaSend Pro card must offer the ${reads.pro} reads per link tiers.js grants`);
  assert.ok(pricingSrc.includes(`<li>Up to ${reads.enterprise} reads per link</li>`),
    `pricing: the ParaSend Enterprise card must offer the ${reads.enterprise} reads per link tiers.js grants`);
  assert.ok(page('parasend').includes('<li>Burn on first read</li>'),
    'parasend: the Community card must still say the link burns on the first read');
  assert.ok(flatten(bodyOf(page('index'))).includes(`up to ${reads.pro} reads per link`),
    `index: the ParaSend Pro price line must name the ${reads.pro} reads per link tiers.js grants`);

  // The two pages that spell all four plans out on their own terms.
  const spelled = [
    ['architecture', `after the last read the link allows: one on Community, up to ${reads.pro} on Pro, ${reads.business} on Business and ${reads.enterprise} on Enterprise`],
    ['docs', `Community gets 1 hour and 1 read, Pro 24 hours and up to ${reads.pro} reads, Business 7 days and ${reads.business} reads, Enterprise 7 days and ${reads.enterprise} reads`],
  ];
  for (const [slug, sentence] of spelled) {
    assert.ok(flatten(bodyOf(page(slug))).includes(sentence),
      `${slug}: must spell the per-plan read counts as "${sentence}", the numbers tiers.js sets`);
  }
});
