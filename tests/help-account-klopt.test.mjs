// De account-hulppagina's beschrijven wat het product echt doet (matrix
// ACCT-39). Elke regel hieronder staat naast de bron die hem bepaalt:
//   - inloggen = e-mailadres + passkey of code; geen API-sleutelveld
//     (auth/login.html heeft #email en #totp, geen sleutelveld);
//   - back-upcode: aparte pagina /auth/backup (auth/backup.html);
//   - sessie: een uur zonder activiteit, twaalf uur hoogstens
//     (admin/lib/session-client.js USER_SESSION_IDLE_S / MAX_AGE);
//   - instellink: /auth/setup/<token> (admin/server.js setupUrl), twee dagen
//     (SETUP_TOKEN_TTL_S);
//   - de accountsleutel gaat in de X-Api-Key-header (de relay leest die header).
// Run: node --test tests/help-account-klopt.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(REPO, p), 'utf8');
const body = (p) => { const s = read(p); const m = s.match(/<main[\s\S]*?<\/main>/); return (m ? m[0] : s).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' '); };
const PAGES = ['backup-codes', 'api-key-vs-totp', 'session-issues', 'lost-authenticator', 'authenticator-setup'];

test('de bronnen zeggen nog wat deze toets aanneemt', () => {
  const login = read('frontend/auth/login.html');
  assert.match(login, /id="totp"/);
  assert.doesNotMatch(login, /id="api-key"|name="api_key"/);
  assert.match(read('frontend/auth/backup.html'), /id="code"/);
  const sc = read('admin/lib/session-client.js');
  assert.match(sc, /3600|60 \* 60/);
  assert.match(sc, /12 \* 60 \* 60|12 \* 3600|43200/);
  assert.match(read('admin/server.js'), /\$\{SITE_URL\}\/auth\/setup\/\$\{setupToken\}/);
  assert.match(read('admin/server.js'), /SETUP_TOKEN_TTL_S[^\n]*2 \* 86400/);
});

for (const lang of ['', 'en/']) {
  for (const name of PAGES) {
    const p = `frontend/${lang}help/${name}.html`;
    test(`${p} belooft niets dat het product niet doet`, () => {
      const t = body(p);
      // Geen API-sleutel bij het inloggen.
      assert.doesNotMatch(t, /e-mailadres en API-sleutel|email and API key|Vul uw API-sleutel in|Enter your API key/i, p);
      // Geen tekstveld onder het TOTP-veld: het is een aparte pagina.
      assert.doesNotMatch(t, /wordt dan een tekstveld|switches from a 6-digit field/i, p);
      // Geen sessie van precies een uur vanaf het inloggen.
      assert.doesNotMatch(t, /duurt 1 uur|1 uur vanaf|last 1 hour|expire after 1 hour|expires \(1 hour\)|verloopt \(1 uur\)/i, p);
      // Geen ?token= en geen veertien dagen voor de instellink.
      assert.doesNotMatch(t, /setup\?token=|14 dagen|14 days/i, p);
      // Geen Authorization-header en geen Dashboard > API-sleutels voor de accountsleutel.
      assert.doesNotMatch(t, /Authorization-header|Authorization header|Dashboard → API|Dashboard &rarr; API/i, p);
      // Geen herstel door een teamlid vanuit het dashboard.
      assert.doesNotMatch(t, /namens u een herstel|start a recovery for you/i, p);
    });
  }
}

test('de echte routes staan erin', () => {
  assert.match(body('frontend/help/backup-codes.html'), /\/auth\/backup/);
  assert.match(body('frontend/en/help/backup-codes.html'), /\/en\/auth\/backup/);
  assert.match(body('frontend/help/session-issues.html'), /twaalf uur/);
  assert.match(body('frontend/en/help/session-issues.html'), /twelve hours/);
  assert.match(body('frontend/help/authenticator-setup.html'), /\/auth\/setup\/XXXXXXXX/);
  assert.match(body('frontend/en/help/api-key-vs-totp.html'), /X-Api-Key/);
});
