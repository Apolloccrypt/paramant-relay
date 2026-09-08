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
