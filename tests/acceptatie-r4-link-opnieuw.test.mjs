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

test('the page says the one advice; the dashboard note says the sender was asked', () => {
  const page = read('frontend/co-sign.js');
  const keyless = page.slice(page.indexOf('async function fetchAndOpenCapsule'), page.indexOf('const capsule = new Uint8Array(await r.arrayBuffer());'));
  assert.match(keyless, SIGNER_NL);
  assert.match(keyless, SIGNER_EN);
  assert.doesNotMatch(keyless, OLD);
  // COSIGN-46-A (2026-10-05): "Stuur mij de link opnieuw" no longer mails a
  // link that opens only the request; the sender is asked to resend.
  const dash = read('frontend/js/dashboard.js');
  const fn = dash.slice(dash.indexOf('function resendInvitation'), dash.indexOf('function wireDocumentFilters'));
  assert.match(fn, /We hebben de afzender gevraagd u de uitnodiging opnieuw te sturen\./);
  assert.match(fn, /We have asked the sender to send you the invitation again\./);
  assert.doesNotMatch(fn, /opent het verzoek, niet het document/);
  assert.doesNotMatch(fn, OLD);
});

test('the mail to the sender: one button to the resend action, else withdraw and resend', () => {
  const relay = read('relay/relay.js');
  const fn = relay.slice(relay.indexOf('async function notifySenderLinkRequested'), relay.indexOf('function senderLabelOf'));
  assert.match(fn, /'\/dashboard\?herzend=' \+ encodeURIComponent\(String\(envelopeId\)\)/);
  assert.match(fn, /knopHtml\('Uitnodiging opnieuw sturen'\)/);
  assert.match(fn, /Open deze link in de browser waarmee u het verzoek verstuurde en klik op Uitnodiging opnieuw sturen/);
  assert.match(fn, /Trek het verzoek dan in en stuur het opnieuw\./);
  assert.doesNotMatch(fn, /Link kopiëren/, 'no more copy-it-yourself as the way');
  // And the dashboard, where the resend happens, agrees.
  const dash = read('frontend/js/dashboard.js');
  assert.match(dash, /Open het verzoek in de browser waarmee u het verstuurde, of trek het in en stuur opnieuw\./);
  assert.match(dash, /data-pa-action="document-resend-invite"/);
});
