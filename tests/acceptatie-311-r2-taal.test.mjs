// Acceptatie 3.1.1 ronde 2: de taalpunten die DEELS waren, plus de kleine
// afwijkingen uit de uitslag. Elk blok noemt het nummer uit taal/BEVINDINGEN.md.
//
// Run: node --test tests/acceptatie-311-r2-taal.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const require = createRequire(import.meta.url);

test('#59: "Heeft u", nergens meer "Hebt u" in klanttekst', () => {
  for (const p of ['frontend/js/passkey.js', 'frontend/js/ophalen.page.js']) {
    assert.doesNotMatch(read(p), /Hebt u/, p);
  }
  assert.match(read('frontend/js/passkey.js'), /Heeft u zelf afgebroken\?/);
});

test('#37: de platte tekst van de bestandsmail zegt hetzelfde als de HTML-voet', () => {
  const relay = read('relay/relay.js');
  assert.doesNotMatch(relay, /Paramant bewaart het bestand versleuteld/);
  assert.doesNotMatch(relay, /Paramant keeps the file encrypted/);
  assert.match(relay, /Het bestand staat versleuteld klaar tot het is opgehaald of de link verloopt\. Daarna is het weg\. Deze link bewaren wij niet\./);
});

test('#12 en N6: de mail aan de afzender opent geen knop, en de sleutelloze uitnodiging stuurt niet in een kringetje', () => {
  const relay = read('relay/relay.js');
  assert.doesNotMatch(relay, /Open deze knop|Open this button/);
  const { signingInviteEmail } = require('../admin/lib/email-templates.js');
  const m = signingInviteEmail({ inviteUrl: 'https://paramant.app/co-sign?id=x', senderLabel: 'demo@example.com', expiresAt: Date.UTC(2026, 9, 12, 18, 0) });
  assert.doesNotMatch(m.text, /Vraag de afzender dan om de link opnieuw te sturen/);
  assert.match(m.text, /Vraag de afzender dan om de uitnodiging opnieuw te sturen vanuit zijn overzicht\. Die uitnodiging opent het document wel\./);
  assert.match(m.text, /ask the sender to send the invitation again from their overview/);
});

test('#42: een verlopen verzoek heet verlopen, niet ingetrokken door de afzender', () => {
  const { requestStoppedPartyEmail } = require('../admin/lib/email-templates.js');
  const exp = requestStoppedPartyEmail({ reason: 'expired', envelopeId: 'env_demo' });
  assert.equal(exp.subject, 'Verzoek verlopen / Request expired');
  assert.doesNotMatch(exp.text, /ingetrokken|withdrew/);
  assert.match(exp.text, /De termijn om te tekenen is voorbij/);
  assert.equal(requestStoppedPartyEmail({ reason: 'declined', envelopeId: 'e' }).subject, 'Verzoek gestopt / Request stopped');
  assert.equal(requestStoppedPartyEmail({ reason: 'withdraw', envelopeId: 'e' }).subject, 'Verzoek ingetrokken / Request withdrawn');
});

test('#10 en N3: na afronding zegt /co-sign niet meer "Bekijk wat u ondertekent" en "hieronder"', () => {
  const js = read('frontend/co-sign.js');
  assert.doesNotMatch(js, /Hieronder downloadt u het complete document|Download hieronder het complete document en het bewijs|Below you can download the complete document|Download the complete document and the proof below/);
  const fn = js.slice(js.indexOf('function retitleForResult'), js.indexOf('async function showResultForParty'));
  assert.match(fn, /'Het document', 'The document'/);
  assert.match(fn, /'Uw handtekening', 'Your signature'/);
  assert.match(js.slice(js.indexOf('async function showResultForParty')), /^async function showResultForParty[\s\S]*?retitleForResult\(false\)/);
  assert.match(js.slice(js.indexOf('async function initOwner')), /retitleForResult\(true\)/);
  for (const p of ['frontend/co-sign.html', 'frontend/en/co-sign.html']) {
    const html = read(p);
    assert.match(html, /id="review-title"/, p);
    assert.match(html, /id="sign-title"/, p);
  }
});

test('c: datums op het dashboard en /verify in Nederlandse tijd, niet als UTC-slice', () => {
  assert.doesNotMatch(read('frontend/parasign-verify.js'), /signed_at\)\.slice\(0, 10\)/);
  const fd = read('frontend/js/format-date.js');
  assert.match(fd, /timeZone: 'Europe\/Amsterdam'/);
  assert.doesNotMatch(fd.slice(fd.indexOf('function day('), fd.indexOf('function moment(')), /getUTCDate\(\) \+ ' ' \+ MONTHS/);
});
