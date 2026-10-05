// Acceptatie r4, A4: a resent signing link opens the request, not the
// document. Three places gave three different pieces of advice: the mail to
// the signer ("vraag om de volledige link"), the page ("vraag om een nieuwe
// uitnodiging") and the mail to the sender ("kopieer de link, anders
// intrekken"). One story now:
//   signer: vraag de afzender om de link opnieuw te sturen
//   sender: kopieer de link uit uw dashboard (in de browser waarmee u
//           verstuurde), anders intrekken en opnieuw sturen
// Run: node --test tests/acceptatie-r4-link-opnieuw.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const require = createRequire(import.meta.url);
const SIGNER_NL = /vraag de afzender (dan )?om de link opnieuw te sturen/i;
const SIGNER_EN = /ask the sender to send you the link again/i;
const OLD = /om de volledige link|om een nieuwe uitnodiging|for their complete link|for a new invitation|for the complete link|for the full link/i;

test('the mail to the signer, for a link without the key, gives the one advice', () => {
  const t = require(path.join(ROOT, 'admin/lib/email-templates.js'));
  const m = t.signingInviteEmail({ inviteUrl: 'https://paramant.app/co-sign?env=abcdefghijklmnopqrst&p=1&t=' + 'a'.repeat(43), recipientLabel: 'Ayse', senderLabel: 'afzender@example.com', expiresAt: '2026-10-12T10:00:00Z', envelopeId: 'abcdefghijklmnopqrst', partyIndex: 1 });
  assert.match(m.text, SIGNER_NL, m.text);
  assert.match(m.text, SIGNER_EN, m.text);
  assert.doesNotMatch(m.text, OLD, m.text);
});

test('the page and the dashboard note say the same to the signer', () => {
  const page = read('frontend/co-sign.js');
  const keyless = page.slice(page.indexOf('async function fetchAndOpenCapsule'), page.indexOf('const capsule = new Uint8Array(await r.arrayBuffer());'));
  assert.match(keyless, SIGNER_NL);
  assert.match(keyless, SIGNER_EN);
  assert.doesNotMatch(keyless, OLD);
  const dash = read('frontend/js/dashboard.js');
  const note = dash.slice(dash.indexOf('body.opens_document === false'), dash.indexOf("note.className") + 400);
  assert.match(note, /de link opnieuw te sturen/);
  assert.doesNotMatch(note, OLD);
});

test('the mail to the sender: copy it from the dashboard in the browser you sent from, else withdraw and resend', () => {
  const relay = read('relay/relay.js');
  const fn = relay.slice(relay.indexOf('async function notifySenderLinkRequested'), relay.indexOf('function senderLabelOf'));
  assert.match(fn, /Kopieer de link uit uw dashboard, in de browser waarmee u het verzoek verstuurde/);
  assert.match(fn, /trek het verzoek dan in en stuur een nieuw verzoek/);
  assert.match(fn, /Copy the link from your dashboard, in the browser you sent the request from/);
  // And the dashboard, where that copy happens, agrees: copy it there, else withdraw.
  const dash = read('frontend/js/dashboard.js');
  assert.match(dash, /open dit verzoek dan in die browser en kopieer de link daar\. Lukt dat niet, trek dit verzoek dan in en stuur een nieuw verzoek\./);
});
