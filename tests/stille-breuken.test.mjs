// The failures a user meets in silence.
//
// Measured on production on 2026-09-08 with two real Community accounts, in a
// browser, all the way from sign-up to account deactivation. Every flow the
// product sells worked. What did not work was the moment a flow refused: the
// refusal did not reach the person. Four cases, one shape:
//
//   1. The backup-code page. /auth/login carries the address the visitor just
//      typed; the link to /auth/backup did not, so that field was empty. The
//      field is `required`, so the form never submitted: no request, no error
//      text, nothing. Pressing the button did nothing at all, on the one page
//      someone only opens when their phone is gone.
//   2. A file over 5 MB on the link stand. It got a green tick ("✓ file (5.7
//      MB)") and a live button, and the refusal existed only as a console line.
//   3. The monthly signature allowance. The 402 arrives after the document,
//      the seal, the name and the six-digit code, with the envelope already
//      created server side. Nothing before the click said how many were left.
//   4. "Developer settings" in the account menu, shown to every signed-in
//      visitor while /developer answers 404 to everyone off the allowlist.
//      Hiding the surface is deliberate; advertising it to everyone was not.
//
// Plus the rate limit underneath 1 and 3: the whole /api/user/ prefix sat in
// the auth throttle at burst=5 while /account alone opens six calls at once, so
// a first visit printed "Could not load passkeys (HTTP 429)" and a 429 on
// /api/user/session/verify rendered a signed-in visitor as signed out.
//
// These assertions fail if any of those repairs is undone. They read the
// shipped files, so they cannot pass by finding nothing: each one first proves
// its subject exists.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => {
  const full = join(ROOT, p);
  assert.ok(existsSync(full), `${p} is missing: this suite guards a file that has moved or gone`);
  return readFileSync(full, 'utf8');
};

test('the sign-in page hands the typed address to the recovery pages', () => {
  const js = read('frontend/js/auth-login.js');
  assert.match(js, /paramant:recovery-email/,
    'auth-login.js no longer remembers the address for the recovery pages');
  assert.match(js, /a\[href\^="\/auth\/backup"\]/,
    'the backup-code link is no longer wired to carry the address');
});

test('the backup-code form lets its own handler do the validating', () => {
  // This is what actually made the button dead. Without `novalidate` the
  // browser's `required` check cancels the submit event, so the page's handler
  // never runs and never gets to say what is missing: no request, no sentence,
  // nothing. The sign-in and sign-up forms already carried it; this one did
  // not, and it is the page people only open when their phone is gone.
  const html = read('frontend/auth/backup.html');
  assert.match(html, /<form id="backup-form"[^>]*\bnovalidate\b/,
    'the backup form validates in the browser again, which silences its own error messages');
});

test('the backup-code page fills that address in and says what is missing', () => {
  const js = read('frontend/js/auth-backup.js');
  assert.match(js, /sessionStorage\.getItem\('paramant:recovery-email'\)/,
    'auth-backup.js no longer prefills the address');
  // The point is not that a check exists, but that a missing field produces a
  // sentence on the page. The browser's own bubble for a `required` field was
  // what left the button looking dead.
  assert.match(js, /if \(!email\)[\s\S]{0,120}fail\(/,
    'a missing email no longer produces a message on the page');
  assert.match(js, /if \(!code\)[\s\S]{0,120}fail\(/,
    'a missing backup code no longer produces a message on the page');
});

test('the link stand refuses an oversized file when it is chosen, not after the click', () => {
  const js = read('frontend/js/parashare.page.js');
  assert.match(js, /function linkSizeRefusal/,
    'the up-front size check is gone');
  // It has to be wired into both the moment of choosing and the button state,
  // or the green tick and the live button come back.
  assert.match(js, /const tooBig = linkSizeRefusal\(files\)/,
    'onFileSelect no longer consults the size check');
  assert.match(js, /linkSizeRefusal\(selectedFiles\) !== null/,
    'the send button no longer goes dead for a file that cannot be sent');
  // And the real sentence must survive to the screen if it is ever thrown.
  assert.match(js, /err\.userFacing = true/,
    'the size refusal is no longer marked as the user\'s own, so it falls back to "something went wrong on our side"');
  assert.match(js, /e\.userFacing && e\.message/,
    'the seal failure handler no longer prints a user-facing message');
});

test('the review step says how many signatures are left before the ceremony', () => {
  const js = read('frontend/sign-flow.js');
  assert.match(js, /async function showRemainingSignatures/,
    'the allowance is no longer read on the review step');
  assert.match(js, /showRemainingSignatures\(\)/,
    'showRemainingSignatures is defined but never called');
  // The banner ships hidden. Writing into it without unhiding it is exactly the
  // bug this file is about, so the repair has to include the unhide.
  assert.match(js, /host\.hidden = false/,
    'the allowance notice is written into a hidden banner and stays invisible');
});

test('developer settings is offered only to accounts that may open it', () => {
  const server = read('admin/server.js');
  assert.match(server, /developer: isDeveloper\(s\.email\)/,
    'the session check no longer tells the page whether this account is a developer');

  const nav = read('frontend/js/nav-auth.js');
  assert.match(nav, /isDeveloper \? '<a href="\/developer"/,
    'the account menu offers /developer to everyone again');

  // The links that live in the pages themselves ship hidden and are revealed by
  // the same verdict. If either half goes, a normal account gets a dead link.
  assert.match(nav, /\[data-developer-only\]/,
    'nav-auth.js no longer reveals the in-page developer links');
  for (const page of ['frontend/account.html', 'frontend/dashboard.html']) {
    const html = read(page);
    const links = html.match(/<a[^>]*href="\/developer"[^>]*>/g) || [];
    assert.ok(links.length > 0, `${page} no longer links to /developer at all`);
    for (const link of links) {
      assert.match(link, /data-developer-only/, `${page} has a /developer link that is not gated: ${link}`);
      assert.match(link, /\bhidden\b/, `${page} has a /developer link that is not hidden by default: ${link}`);
    }
  }
});

test('only the credential endpoints sit in the auth throttle', () => {
  const conf = read('deploy/nginx-paramant-live.conf');

  // The narrow location has to exist, and it has to be the one carrying the
  // auth zone.
  const authLocRe = /location ~ (\^\/api\/user\/\S+) \{([\s\S]*?)\n    \}/;
  const authLoc = authLocRe.exec(conf);
  assert.ok(authLoc, 'the credential-only location is gone from the live nginx conf');
  assert.match(authLoc[2], /limit_req\s+zone=relay_auth/,
    'the credential endpoints are no longer in the auth throttle');

  // Which paths that pattern actually catches, checked against the real ones.
  // The near-miss that matters: /api/user/sign/* is an already-signed-in
  // account signing a document, and it must NOT land in the credential bucket,
  // or the signing flow throttles itself. "signup" and "sign" share a prefix,
  // so this is a genuine trap rather than a hypothetical one.
  const pattern = new RegExp(authLoc[1]);
  const mustMatch = [
    '/api/user/login', '/api/user/login-with-backup', '/api/user/signup',
    '/api/user/signup/verify/abc123', '/api/user/setup/abc123',
    '/api/user/setup/abc123/confirm', '/api/user/auth/webauthn/login/options',
    '/api/user/auth/request-totp-reset',
  ];
  const mustNotMatch = [
    '/api/user/sign/activation', '/api/user/sign/submit', '/api/user/session/verify',
    '/api/user/account', '/api/user/account/signing-key', '/api/user/dashboard/overview',
    '/api/user/parasign-keys', '/api/user/documents', '/api/user/envelopes',
    '/api/user/billing/status', '/api/user/logout',
  ];
  for (const p of mustMatch) {
    assert.ok(pattern.test(p), `${p} is a credential endpoint but falls outside the auth throttle`);
  }
  for (const p of mustNotMatch) {
    assert.ok(!pattern.test(p), `${p} is not a credential endpoint but got swept into the auth throttle`);
  }

  // And the broad prefix must NOT be, or every signed-in read shares the
  // credential bucket again and /account goes back to printing 429.
  const prefixLoc = /\n    location \/api\/user\/ \{([\s\S]*?)\n    \}/.exec(conf);
  assert.ok(prefixLoc, 'the /api/user/ prefix location is gone from the live nginx conf');
  assert.doesNotMatch(prefixLoc[1], /zone=relay_auth/,
    'the whole /api/user/ prefix is back in the auth throttle, which is what made /account answer 429');
  assert.match(prefixLoc[1], /limit_req\s+zone=api/,
    'the signed-in reads are no longer rate limited at all');
});

test('the signed-in polls stop while the tab is in the background', () => {
  // Twelve requests a minute from a forgotten tab drained the same bucket every
  // other signed-in call draws from.
  for (const [file, fn] of [['frontend/js/dashboard.js', 'pull'], ['frontend/js/developer.js', 'loadSnapshot']]) {
    const js = read(file);
    assert.match(js, new RegExp(`visibilityState === 'visible'\\) ${fn}\\(\\)`),
      `${file} polls without checking whether the tab is visible`);
    assert.match(js, /addEventListener\('visibilitychange'/,
      `${file} never refreshes when the tab comes back to the front`);
    assert.doesNotMatch(js, /setInterval\([^)]*,\s*(5000|10000)\)/,
      `${file} is back on its old fast interval`);
  }
});

test('the pages tell the truth about the verification link and who sends the mail', () => {
  // The token is written with EX: 86400 in admin/server.js. The mail said 24
  // hours, the page said 2 days.
  const server = read('admin/server.js');
  assert.match(server, /EX: 86400/, 'the signup token no longer lives for 86400 seconds; check the pages again');
  const signup = read('frontend/signup.html');
  assert.match(signup, /The link works for 24 hours\./, 'the signup page is back to promising 2 days');

  // Mail goes out as hello@paramant.app; four pages told people to look for
  // noreply@, so filtering on the sender found nothing.
  const templates = read('admin/lib/email-templates.js');
  assert.match(templates, /const FROM_ADDR = 'Paramant <hello@paramant\.app>'/,
    'the from address changed; the pages that name it have to change with it');
  for (const page of ['frontend/signup/verified.html', 'frontend/auth/reset-confirm.html', 'frontend/js/auth-request-reset.js']) {
    assert.doesNotMatch(read(page), /noreply@paramant\.app/,
      `${page} names a sender address that account mail does not come from`);
  }
});

test('the review card does not name a recipe version it cannot know', () => {
  // The card printed "recipe_version 3" while the relay writes 5 into the
  // envelope the signer downloads a minute later. The recipe is chosen server
  // side, so before the envelope exists there is no number to print: the same
  // preview already says "<set on sign>" for the fields in that position.
  const js = read('frontend/sign-flow.js');
  assert.doesNotMatch(js, /recipe_version 3\)/,
    'the review card is back to promising recipe_version 3');
  assert.doesNotMatch(js, /^\s*recipe_version: 3,\s*$/m,
    'the envelope preview is back to a hardcoded recipe_version 3');
  assert.match(js, /recipe_version: '<set on sign>'/,
    'the envelope preview no longer marks the recipe as decided on signing');
});

test('a refused account deactivation says so', () => {
  // `if (res.ok)` and nothing else: a refusal left the page sitting there while
  // the account quietly still existed.
  const js = read('frontend/js/account.inline1.js');
  const block = /delete-account'\)\.addEventListener\([\s\S]*?\n  \}\);/.exec(js);
  assert.ok(block, 'the deactivate handler is gone from the account page');
  assert.match(block[0], /was NOT deactivated/,
    'a failed deactivation is silent again');
  assert.match(block[0], /res\.status === 401/,
    'an expired session during deactivation is not named');
});

test('verify asks for the copy that actually validates', () => {
  const html = read('frontend/verify.html');
  assert.doesNotMatch(html, /Choose the original document/,
    'the verify page asks for the original again, which is the copy that fails for a PDF');
  assert.match(html, /Choose the signed document/, 'the verify page no longer names the file to pick');

  const js = read('frontend/parasign-verify.js');
  // The near-miss worth naming: the file from before the seal.
  assert.match(js, /env\.original_hash === docHashHex/,
    'the verifier no longer recognises the pre-signature copy');
  // And the signer line must not print its own brackets around a placeholder.
  // Only code counts here: the comment above the repair says the old string out
  // loud on purpose, and matching that would make this assertion meaningless.
  const code = js.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
  assert.doesNotMatch(code, /['"`][^'"`]*\(unverified\)/,
    'the signer line is back to printing "((unverified))" around a missing address');
  assert.match(code, /no address published for this key/,
    'the signer line no longer says why an address is missing');
});

// ── Doodlopende wegen ────────────────────────────────────────────────────────
// Dezelfde familie, een verdieping lager: niet een melding die niet aankomt,
// maar een uitgang die er niet is. Gemeten op 390x844.

test('the vault page is not a dead end on a phone', () => {
  const html = read('frontend/vault.html');
  // Both links in the bar point at /dashboard and the page has no menu button
  // and no drawer, so this was the one page you could not leave except by
  // going back. It stays script-free on purpose: this page makes no network
  // call at all, and the shared navigation would add one.
  // Match the script tag, not the word: the comment in the page names
  // nav-auth.js on purpose, to say why it is absent.
  assert.doesNotMatch(html, /<script[^>]+nav-auth\.js/,
    'the vault page now loads the shared navigation, which costs it its network silence');
  assert.match(html, /class="vt-elsewhere"/,
    'the vault page has no way out other than the dashboard again');
  for (const href of ['/verify', '/gereedschap', '/']) {
    assert.ok(html.includes(`<a href="${href}">`), `the vault page no longer links to ${href}`);
  }
  assert.match(html, /<footer class="legal-strip">/,
    'the vault page dropped the legal strip, so privacy, DPA and terms are unreachable from it');
});

test('the ct-log skip link lands somewhere', () => {
  const html = read('frontend/ct-log.html');
  assert.match(html, /href="#main-content" class="skip-link"/,
    'the skip link is gone from /ct-log');
  // It pointed at an id that did not exist: pressing it set the hash and moved
  // nothing. tabindex is what actually moves the focus.
  assert.match(html, /<main id="main-content"[^>]*tabindex="-1"/,
    'the skip link on /ct-log points at a target that cannot take focus');
});

test('both ct-log search fields have a name', () => {
  const html = read('frontend/ct-log.html');
  // A placeholder disappears the moment you type, so it is not a label. These
  // two were the only unlabelled inputs on the site.
  for (const id of ['verify-input', 'search']) {
    const tag = new RegExp(`<input id="${id}"[^>]*>`).exec(html);
    assert.ok(tag, `input #${id} is gone from /ct-log`);
    assert.match(tag[0], /aria-label="/, `input #${id} has no accessible name, only a placeholder`);
  }
});

test('the legal strip is a finger-sized target', () => {
  const css = read('frontend/design-system.css');
  // 17 to 19px tall, on every auth, account and download page: the smallest
  // target on the site.
  const rule = /\.legal-strip a \{([\s\S]*?)\}/.exec(css);
  assert.ok(rule, '.legal-strip a is gone from the design system');
  assert.match(rule[1], /min-height:\s*44px/,
    'the legal strip links are back under the 44px a thumb needs');
});

// ── Zinnen die zichzelf tegenspreken ─────────────────────────────────────────

test('the SLA does not promise coverage its own section 5 withdraws', () => {
  const html = read('frontend/sla.html');
  // Section 1 said "All five sector relays are covered" while section 5 said
  // the four sector relays are not measured and the monitor for the fifth is
  // switched off. Both sentences were on the same page.
  assert.doesNotMatch(html, /All five sector relays \([^)]*\) are covered/,
    'the SLA promises coverage in section 1 that section 5 takes back');
  assert.match(html, /their uptime is not measured/,
    'section 5 no longer says which relays are not monitored; check section 1 again');
  assert.match(html, /Read section 5 before you rely on a number here/,
    'section 1 no longer points at the section that qualifies it');

  // And the page describes itself as covering plans it does not list. Only
  // Community and Enterprise have rows.
  assert.doesNotMatch(html, /every Paramant plan, from Community to Enterprise/,
    'the SLA describes itself as covering every plan while it lists two');
});

test('the status page does not call one look a day of uptime', () => {
  const js = read('frontend/js/status.inline1.js');
  // A first visit made one check, found it up, and printed "uptime 24h 100.0%".
  assert.match(js, /function uptimeStat/,
    'the uptime figure no longer carries its sample count');
  assert.match(js, /stat\.n < 5/,
    'a percentage is printed again before there are enough samples to mean one');

  const html = read('frontend/status.html');
  assert.doesNotMatch(html, /uptime % calculated from last 24h of checks/,
    'the note under the page claims 24 hours of checks again');
  assert.doesNotMatch(html, /Uptime is calculated from the last 24 hours of checks/,
    'the page description still claims a 24-hour calculation');
  assert.match(html, /checks this browser has made/,
    'the note no longer says whose checks these are');
});

test('the ct-log counters add up to the window they describe', () => {
  const js = read('frontend/js/ct-log.page.js');
  const html = read('frontend/ct-log.html');

  // Three counts sat under a total that came from a different dataset: the
  // total is the whole log, the counts covered the 1000 entries the relay
  // returns in one request. Nothing said so, so 4798 sat above 0 + 37 + 957.
  assert.match(js, /stat-scope/, 'the page no longer says which entries the counts cover');
  assert.match(js, /allEntries\.length < logSize/,
    'the scope line no longer distinguishes a window from the whole log');
  assert.match(html, /id="stat-scope"/, 'the scope line has no place in the page');

  // And signing work fell between the categories, counted by nobody. Any type
  // added later lands in the same remainder.
  assert.match(js, /var otherCount/, 'the remainder counter is gone');
  assert.match(js, /countedTypes\.indexOf\(e\.type\) === -1/,
    'the remainder no longer catches types the other counters do not claim');
  assert.match(html, /id="stat-other"/, 'the remainder has no counter in the page');

  // signing_pk_enrolled is what a key registration is actually called in the
  // log; counting only 'key_reg' is what made that counter read 0.
  assert.match(js, /e\.type === 'signing_pk_enrolled'/,
    'key registrations are counted under a type name the log does not use');
});

test('the docs do not offer an authentication form the relay refuses', () => {
  const html = read('frontend/docs.html');
  // ?k= was removed from the relay after the April 2026 review. The docs kept
  // offering it, with a worked example, so anyone following them got
  // "API key must be sent in the X-Api-Key header, not as a query parameter."
  assert.doesNotMatch(html, /check-key\?k=pgp_your_key_here/,
    'the docs demonstrate ?k= again, which the relay rejects');
  assert.match(html, /There is no query-parameter\s*\n?\s*form/,
    'the docs no longer say that the query-parameter form does not exist');
});

test('the docs name the version the hosted relays actually answer', () => {
  const html = read('frontend/docs.html');
  // Production answers 3.1.0; the self-host release the install script pins is
  // v3.0.0. The page named 3.0.0 for both, including in the /health example.
  assert.match(html, /"version": "3\.1\.0"/,
    'the /health example is back on a version the hosted relay does not answer');
  // As a JSON field, not as the word: the note under the example names it on
  // purpose, to say it is gone.
  assert.doesNotMatch(html, /"uptime_s"\s*:/,
    'the /health example shows a field the relay does not return');
  assert.doesNotMatch(html, /docs for Paramant v3\.0\.0/,
    'the page describes itself as the docs for one version while it covers two');
  // The history stays: "What's new in 3.0.0" is about 3.0.0 and must not be
  // renumbered by a search and replace.
  assert.match(html, /What's new in 3\.0\.0/,
    'the release notes for 3.0.0 have been renumbered, which rewrites history');
});

test('the audits table does not report a finding as closed that SECURITY.md keeps open', () => {
  const security = read('SECURITY.md');
  const docs = read('frontend/docs.html');

  // SECURITY.md keeps its own "Open findings" table. As long as it has rows,
  // the audits table on /docs cannot report every audit as fully resolved.
  // This is the one claim on that page a buyer's security officer reads first.
  const openSection = /## Open findings\s*\n([\s\S]*?)\n---/.exec(security);
  assert.ok(openSection, 'SECURITY.md no longer has an "Open findings" section; check the /docs table again');
  const openRows = openSection[1].split('\n').filter((l) => /^\|\s*\d+\s*\|/.test(l));

  const table = /<h2 id="audits">[\s\S]*?<\/table>/.exec(docs);
  assert.ok(table, 'the audits table is gone from /docs');

  if (openRows.length > 0) {
    // Name the audit those rows belong to, so this fails loudly rather than
    // quietly passing on a table that has been reworded.
    assert.doesNotMatch(table[0], /Smart Cyber Solutions<\/td><td>[^<]*<\/td><td>All resolved/,
      `SECURITY.md lists ${openRows.length} open finding(s) while /docs reports that audit as fully resolved`);
    assert.match(docs, /One finding is still open/,
      '/docs no longer tells the reader that a finding is open');
  }

  // The commit hash 0db3ef0 belongs to the Zwarts review in SECURITY.md. It was
  // copied onto the Smart Cyber Solutions row as well, which credited a fix to
  // an audit it did not close.
  assert.doesNotMatch(table[0], /Smart Cyber Solutions[\s\S]*?0db3ef0/,
    'the Smart Cyber Solutions row carries a commit hash that belongs to another audit');
});
