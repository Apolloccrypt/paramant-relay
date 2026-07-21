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
assert.match(email, /Account record and audit entries retained/);
assert.doesNotMatch(email, /Personal data removed from our systems/);
assert.doesNotMatch(email, /sign up again|Files already relayed are not affected/i);

assert.doesNotMatch(paraid, /live person \+ passport document check|document tier \(substantial\)|Prove your age from your passport/);
assert.match(paraid, /MRZ check-digit consistency, document authenticity not checked/);
assert.match(paraid, /does not verify the document, its chip, its holder or a live person/);
assert.match(paraid, /MRZ internally consistent/);

console.log('ui-truthfulness: deactivation and MRZ scope are stated honestly');
