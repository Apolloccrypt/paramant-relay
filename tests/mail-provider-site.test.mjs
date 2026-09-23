// Welke mailprovider de site noemt, gelegd naast wat productie gebruikt.
//
// Op 22 september 2026 kwam op elke pagina te staan dat mail via Mailjet in
// Parijs liep. Mailjet was nooit aangezet: geen account, geen sleutels in de
// prod-.env, en de relay viel terug op Resend Inc. in de VS. De code kende
// Mailjet, dus de site klonk geloofwaardig, en niets legde de tekst naast wat
// er echt draaide.
//
// deploy/mail-provider.json is die bevestiging: de drager die productie
// gebruikt en de sleutels die daar staan. Deze toets eist drie dingen:
//   1. de code kent de actieve drager en kiest hem zelf als alleen de
//      prod-sleutels er zijn (geen MAIL_PROVIDER, zoals productie draait);
//   2. /privacy en /dpa noemen hem, in beide talen;
//   3. geen enkele pagina, NL of /en, noemt een andere drager. Een andere naam
//      mag alleen binnen een element met data-mail-historie, voor een zin die
//      expliciet over vroeger gaat.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const afspraak = JSON.parse(fs.readFileSync(path.join(ROOT, 'deploy/mail-provider.json'), 'utf8'));
const mail = require(path.join(ROOT, 'relay/lib/mail.js'));

// Hoofdlettergevoelig en als heel woord: zo telt RESEND_API_KEY in de
// installatiedocs niet mee, de merknaam wel.
const DRAGERS = {
  mailjet: /\bMailjet\b/,
  scaleway: /\bScaleway\b/,
  brevo: /\bBrevo\b/,
  flowmailer: /\bFlowmailer\b/,
  resend: /\bResend\b/,
};

function paginas(dir = path.join(ROOT, 'frontend'), pre = '') {
  const uit = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) uit.push(...paginas(path.join(dir, e.name), pre + e.name + '/'));
    else if (e.name.endsWith('.html')) uit.push(pre + e.name);
  }
  return uit.sort();
}

function zichtbaar(html) {
  return html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<(\w+)\b[^>]*\bdata-mail-historie\b[^>]*>[\s\S]*?<\/\1>/g, ' ')
    .replace(/<[^>]+>/g, ' ');
}

test('de afspraak noemt een drager die de code kent', () => {
  assert.ok(Object.hasOwn(DRAGERS, afspraak.actief), `onbekende drager in deploy/mail-provider.json: ${afspraak.actief}`);
  assert.ok(mail.PROVIDERS.includes(afspraak.actief), `relay/lib/mail.js kent ${afspraak.actief} niet`);
  assert.ok(Array.isArray(afspraak.prod_sleutels) && afspraak.prod_sleutels.length, 'prod_sleutels ontbreekt');
});

test('met alleen de prod-sleutels kiest de code zelf de actieve drager', () => {
  const env = {};
  for (const k of afspraak.prod_sleutels) env[k] = 'x';
  const cfg = mail.config(env);
  assert.equal(cfg.provider, afspraak.actief,
    `de code kiest ${cfg.provider} met ${afspraak.prod_sleutels.join(', ')}; de site noemt ${afspraak.actief}`);
});

test('/privacy en /dpa noemen de actieve drager, in beide talen', () => {
  for (const p of ['privacy.html', 'dpa.html', 'en/privacy.html', 'en/dpa.html']) {
    const tekst = zichtbaar(fs.readFileSync(path.join(ROOT, 'frontend', p), 'utf8'));
    assert.match(tekst, DRAGERS[afspraak.actief], `${p} noemt ${afspraak.naam} niet`);
  }
});

test('geen pagina noemt een andere drager dan de actieve', () => {
  const lijst = paginas();
  assert.ok(lijst.includes('index.html') && lijst.includes('en/index.html'), 'de veeg vindt de pagina\'s niet meer');
  const fout = [];
  for (const p of lijst) {
    const tekst = zichtbaar(fs.readFileSync(path.join(ROOT, 'frontend', p), 'utf8'));
    for (const [naam, re] of Object.entries(DRAGERS)) {
      if (naam === afspraak.actief) continue;
      const m = re.exec(tekst);
      if (m) fout.push(`${p}: noemt ${m[0]}, maar productie mailt via ${afspraak.naam}`);
    }
  }
  assert.deepEqual(fout, [], `\n  ${fout.join('\n  ')}\n`);
});
