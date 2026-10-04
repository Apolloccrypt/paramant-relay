// Hertest ronde 2, twee kleine dingen op /co-sign die de klant op het verkeerde
// been zetten:
//   T3-4  elke 403 werd "Deze uitnodiging hoort bij een ander e-mailadres",
//         ook doc_hash_mismatch, een kapotte uitnodiging en account_mismatch.
//   K1    de laatste ondertekenaar las "Zodra iedereen heeft getekend..." onder
//         "Door iedereen getekend".
// Run: node --test tests/cosign-meldingen-kloppen.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');
const cosign = read('frontend/co-sign.js');
const admin = read('admin/server.js');

test('"ander e-mailadres" staat alleen bij de echte e-mailcode', () => {
  const lines = cosign.split('\n').filter((l) => /ander e-mailadres/.test(l));
  assert.ok(lines.length >= 2, 'de melding bestaat nog');
  for (const l of lines) {
    assert.match(l, /not_authorized|recipient_mismatch/, 'een "ander e-mailadres"-regel zonder de e-mailcode: ' + l.trim().slice(0, 160));
  }
  // De overige 403's hebben een eigen tekst, en de rest een algemene zonder e-mailadres.
  for (const code of ['doc_hash_mismatch', 'invite_invalid', 'account_mismatch']) {
    assert.match(cosign, new RegExp(`status === 403 && reason === '${code}'\\) msg = L\\('(?![^']*ander e-mailadres)`), code);
  }
  assert.match(cosign, /else if \(e && e\.status === 403\) msg = L\('Ondertekenen werd geweigerd/);
});

test('de activatie onderscheidt een kapotte uitnodiging van een ander e-mailadres', () => {
  assert.match(admin, /if \(r\.status !== 200\) return res\.status\(403\)\.json\(\{ error: "invite_invalid" \}\);/);
  assert.match(admin, /env\.party\.email_hash !== sessionEmailHash\) return res\.status\(403\)\.json\(\{ error: "not_authorized" \}\);/);
});

test('de tekst onder "Uw handtekening is gezet" volgt de status', () => {
  for (const f of ['frontend/co-sign.html', 'frontend/en/co-sign.html']) assert.match(read(f), /<p class="sub" id="done-sub">/, f);
  const block = cosign.slice(cosign.indexOf("const sub = $('done-sub')"), cosign.indexOf("$('done-env-id').textContent"));
  assert.match(block, /data\.status === 'complete'\s*\n?\s*\? L\('Uw handtekening is vastgelegd\. Iedereen heeft nu getekend/);
  assert.match(block, /: L\('Uw handtekening is vastgelegd\. Zodra iedereen heeft getekend/);
});
