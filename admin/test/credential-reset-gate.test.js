'use strict';
// THE CREDENTIAL RESET GATE. A path that resets or replaces a login factor must
// invalidate the sessions that factor authorised, and the link it mails out must
// have one lifetime, written down once.
//
// WHY THIS EXISTS. Finding 15 of the 2026-09-05 hostile review, and it is two
// faults wearing one name.
//
//   THE LIFETIME. `14 * 86400` was hand-typed at seven separate sites. For an
//   account whose TOTP is not yet active, the setup link IS the account: it
//   hands over the TOTP secret and, one code later, a session, with no other
//   proof. Two weeks of mailbox access is two weeks of account takeover, and an
//   unauthenticated login attempt against such an account minted a FRESH link
//   and mailed it on every try, never clearing the last. Seven copies of a
//   number is also how the mail came to promise a fortnight.
//
//   THE REVOCATION. Four of the seven paths revoked nothing. The sharpest was
//   /admin/resend-setup, which deletes the account's TOTP state and its backup
//   codes -- tearing down the second factor -- and left every live session
//   standing. The logged-in reset DID revoke, the public one did not, and the
//   reset an attacker drives is precisely the one without a session.
//
// The class is: a credential reset that leaves the credential's sessions alive.
// Asserting it about four named routes catches the case; the fifth route is
// written by copying one of the four. So this scans for the shape.
//
// WHAT IT REQUIRES
//   C1  no literal TTL beside a setup-token write. One constant.
//   C2  every setup token is minted through issueSetupToken, which clears the
//       previous one and revokes the account's sessions.
//   C3  a handler that tears down a factor (deletes totp / totp_active /
//       backup_codes) also revokes, directly or through issueSetupToken.
//   C4  the mail's promise comes from the same constant as the TTL.
//
// Runs anywhere: no redis, plain fs.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const TEMPLATES = fs.readFileSync(path.join(__dirname, '..', 'lib', 'email-templates.js'), 'utf8');
const LINES = SRC.split('\n');

// Deleting one of these is tearing a login factor down.
const TEARDOWN = /del\(`paramant:user:(totp|totp_active|backup_codes|backup_codes_plaintext):/;
// What counts as revoking. Either directly, or through the minting helper,
// which does it on the caller's behalf.
const REVOKES = /userSessions\.revokeAll\(|issueSetupToken\(/;

function handlers() {
  const out = [];
  const open = /^\s*api\.(get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]/;
  LINES.forEach((l, i) => {
    const m = open.exec(l);
    if (!m) return;
    let d = 0; let end = LINES.length - 1;
    for (let j = i; j < LINES.length; j++) {
      d += (LINES[j].match(/\(/g) || []).length - (LINES[j].match(/\)/g) || []).length;
      if (j > i && d <= 0) { end = j; break; }
    }
    out.push({ name: `${m[1].toUpperCase()} ${m[2]}`, line: i + 1, body: LINES.slice(i, end + 1).join('\n') });
  });
  return out;
}

test('the setup-token lifetime is one constant, never a literal', () => {
  const offenders = [];
  LINES.forEach((l, i) => {
    if (!/setup_token/.test(l)) return;
    if (/EX:\s*\d/.test(l) || /\d+\s*\*\s*86_?400/.test(l)) offenders.push(`admin/server.js:${i + 1} ${l.trim().slice(0, 110)}`);
  });
  assert.deepStrictEqual(offenders, [], `a hand-typed lifetime next to a setup token:\n  ${offenders.join('\n  ')}`);
  assert.match(SRC, /const SETUP_TOKEN_TTL_S = /, 'the shared constant is gone');
  // And it is short. Fourteen days was the finding; anything past a week is the
  // finding again under a different number.
  const decl = /const SETUP_TOKEN_TTL_S = ([^;]+);/.exec(SRC);
  assert.ok(decl, 'SETUP_TOKEN_TTL_S is no longer a simple declaration');
  // eslint-disable-next-line no-new-func
  const value = Function(`"use strict"; const process = { env: {} }; return (${decl[1]});`)();
  assert.ok(value <= 7 * 86400, `the default setup-link lifetime is ${Math.round(value / 86400)} days`);
});

test('every setup token is minted through the one helper', () => {
  // A token written by hand skips both halves: the previous one is not cleared,
  // and the account's sessions survive a factor reset.
  const bare = [];
  LINES.forEach((l, i) => {
    if (!/redis\(\)\.set\(`paramant:user:setup_token:/.test(l)) return;
    bare.push(`admin/server.js:${i + 1} ${l.trim().slice(0, 110)}`);
  });
  // The helper's own write is the exception, and it is identified by being
  // inside issueSetupToken rather than by its line number.
  const helper = SRC.slice(SRC.indexOf('async function issueSetupToken('), SRC.indexOf('\n}', SRC.indexOf('async function issueSetupToken(')));
  const inHelper = bare.filter((b) => helper.includes(b.split(' ').slice(1).join(' ')));
  assert.strictEqual(inHelper.length, 1, 'issueSetupToken no longer writes the token itself');
  assert.deepStrictEqual(bare.filter((b) => !inHelper.includes(b)), [],
    `a setup token minted outside issueSetupToken:\n  ${bare.join('\n  ')}`);
});

test('the minting helper clears the previous link and revokes the sessions', () => {
  const at = SRC.indexOf('async function issueSetupToken(');
  assert.ok(at > 0, 'issueSetupToken is gone');
  const helper = SRC.slice(at, SRC.indexOf('\n}', at));
  assert.match(helper, /dropSetupTokenFor\(/, 'the previous link is no longer cleared');
  assert.match(helper, /userSessions\.revokeAll\(/, 'the sessions are no longer revoked');
  assert.match(helper, /SETUP_TOKEN_TTL_S/, 'the helper no longer uses the shared lifetime');
});

test('a handler that tears a factor down also revokes the sessions it let through', () => {
  const offenders = [];
  for (const h of handlers()) {
    if (!TEARDOWN.test(h.body)) continue;
    if (REVOKES.test(h.body)) continue;
    offenders.push(`admin/server.js:${h.line} ${h.name}`);
  }
  assert.deepStrictEqual(offenders, [], `a factor is torn down and its sessions live on:\n  ${offenders.join('\n  ')}`);
});

test('the mail does not promise a lifetime of its own', () => {
  assert.doesNotMatch(TEMPLATES, /valid for 14 days/, 'the setup mail still promises fourteen days');
  assert.match(TEMPLATES, /validFor/, 'the setup mail no longer takes the lifetime as a parameter');
  assert.match(SRC, /function setupTokenValidFor\(/, 'nothing turns the constant into the phrase the mail prints');
  assert.match(SRC, /validFor: setupTokenValidFor\(\)/, 'a caller of setupEmail does not pass the lifetime');
  // Every caller, not just one.
  const calls = SRC.match(/emailTemplates\.setupEmail\(\{/g) || [];
  const withValid = SRC.match(/emailTemplates\.setupEmail\(\{[^}]*validFor:/g) || [];
  assert.strictEqual(withValid.length, calls.length, `${calls.length - withValid.length} setupEmail call(s) print the template default instead of the real lifetime`);
});

test('self-test: the teardown and revoke patterns actually separate', () => {
  const torn = handlers().filter((h) => TEARDOWN.test(h.body));
  assert.ok(torn.length >= 2, `only ${torn.length} handlers tear a factor down; the pattern has drifted`);
  const broken = [
    'api.post("/x", async (req, res) => {',
    '  await redis().del(`paramant:user:totp_active:${user_id}`);',
    '  res.json({ ok: true });',
    '});',
  ].join('\n');
  assert.strictEqual(TEARDOWN.test(broken), true, 'the teardown pattern misses a plain delete');
  assert.strictEqual(REVOKES.test(broken), false, 'the revoke pattern matches a handler that revokes nothing');
});
