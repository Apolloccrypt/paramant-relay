import assert from 'node:assert/strict';
import fs from 'node:fs';

function read(file) { return fs.readFileSync(new URL('../' + file, import.meta.url), 'utf8'); }

const account = read('frontend/account.html');
const accountJs = read('frontend/js/account.inline1.js');
const adminHtml = read('admin/public/index.html') + read('frontend/admin.html');
const adminJs = read('admin/public/app.js') + read('frontend/js/admin.page.js');
const email = read('admin/lib/email-templates.js');
const paraid = read('frontend/paraid-document.html') + read('frontend/js/paraid-document.js') + read('frontend/js/paraid-app.js');

assert.doesNotMatch(account + accountJs + adminHtml + adminJs, /Delete account permanently|Account deleted|permanent, cannot undo/i);
assert.match(account, /makes its API key unusable/i);
assert.match(account, /sessions and TOTP setup are removed/i);
assert.match(account, /account record is retained/i);
assert.doesNotMatch(account, /Stub mode|No real payments are charged|Mollie integration pending/i);
assert.match(adminHtml, /blocks the account key and removes active sessions and TOTP/i);
assert.match(adminHtml, /Type DEACTIVATE to confirm/);
assert.match(adminJs, /Account deactivated/);
// Deletion now erases the personal data itself, so the mail has to say so.
// It used to promise the opposite, because deletion only revoked the key and
// left the address in users.json (audit finding 5 of 2026-07-21). A mail that
// undersells an erasure is as untrue as one that oversells it, which is what
// this file exists to catch.
assert.match(email, /Personal data removed from our systems/);
assert.match(email, /Billing records kept for as long as tax law requires/);
assert.doesNotMatch(email, /Account record and audit entries retained/);
assert.doesNotMatch(email, /sign up again|Files already relayed are not affected/i);

assert.doesNotMatch(paraid, /live person \+ passport document check|document tier \(substantial\)|Prove your age from your passport/);
// The wording moved when the assurance rung was renamed from the eIDAS word
// 'substantial' to 'mrz-unverified'. What the page must keep saying is the
// same thing: the check digits add up and nothing about the document itself
// was verified. Matched on the claim, not on one exact sentence.
assert.match(paraid, /check digits add up/i);
assert.match(paraid, /never seen or authenticated/i);
assert.doesNotMatch(paraid, /MRZ check-digit consistency, document authenticity not checked/);
assert.match(paraid, /does not verify the document, its chip, its holder or a live person/);
assert.match(paraid, /MRZ internally consistent/);

console.log('ui-truthfulness: deactivation and MRZ scope are stated honestly');


// ── The signing page now that /sign is served to everyone ────────────────────
// Two things must stay true, and both cost trust if they slip.
const signHtml = read('frontend/sign.html');
const signJs = read('frontend/sign-flow.js');
// What a visitor actually reads. Comments explain the code to us and routinely
// quote the very phrasing they exist to forbid ("no verified signer"), so a
// no-overclaim check that scans the raw file fails on its own explanation.
const signVisible = signHtml.replace(/<!--[\s\S]*?-->/g, '');

// 1. An open-mode signature must never be presented as a verified signer.
// Recipe version 4 binds the signer's PUBLIC KEY into the signed message, so
// the proof commits to "key K signed slot i of document D" and to nothing about
// who holds K. This is the same overclaim that renamed the ParaID assurance
// rung from 'substantial' to 'mrz-unverified'.
assert.match(signHtml, /Signer not verified/i,
  'sign.html must state that an open-mode signer is not verified');
assert.match(signHtml, /does not\s+show who holds that key/i,
  'sign.html must say the proof does not identify the holder of the key');
assert.doesNotMatch(signVisible, /identity verified|verified signer|signer verified|legally binding/i,
  'sign.html must not claim a verified identity or legal effect it cannot deliver');

// The scope notice is driven by what the SERVER reported, never by the mode the
// visitor picked in the UI. A label that guesses is worse than no label: it
// would read as a verdict on evidence nobody checked.
assert.match(signJs, /function showProofScope/,
  'sign-flow.js must have the proof-scope control');
assert.doesNotMatch(signJs, /showProofScope\([^)]*signingMode/,
  'the proof scope must not be derived from the UI signing mode');

// 2. A visitor without a session is told what signing needs BEFORE picking a
// file, not after. The page used to be behind an nginx auth_request; moving the
// dead end to the last step would be worse than the redirect it replaced.
assert.match(signHtml, /Signing a document needs an account/i,
  'sign.html must state the account requirement up front');
assert.match(signHtml, /open a signing request someone sent you/i,
  'sign.html must say what an invited signer can still do without an account');
assert.match(signJs, /function showSessionRequirement/,
  'sign-flow.js must have the session-requirement control');
