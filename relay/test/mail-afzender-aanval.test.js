'use strict';

// DE AFZENDERREGEL, en wat de klantnaam ermee kan.
//
// `"<naam> via Paramant" <adres>` wordt gebouwd door mail.afzenderNamens en
// relay.js roept die aan met de basis op `undefined`:
//
//   relay.js:4732   uitnodiging   afzenderNamens(undefined, wieRuw)
//   relay.js:4885   herinnering   afzenderNamens(undefined, wie3)
//   relay.js:7176   ophaalcode    afzenderNamens(undefined, wie2)
//
// Dit bestand doet twee dingen: het toont wat die undefined kost, en het valt
// de naam zelf aan met CR/LF, quotes, tienduizend tekens, NUL en unicode.
//
// Alles unit, met een neppe fetch: er gaat geen byte naar een provider.

const assert = require('node:assert/strict');
const { test } = require('node:test');
const mail = require('../lib/mail');

// Een fetch die niets verstuurt en alles onthoudt.
function vangFetch(antwoord) {
  const calls = [];
  const f = async (url, opts) => {
    calls.push({ url, body: JSON.parse(opts.body), headers: opts.headers });
    return antwoord || { ok: true, status: 200,
                         json: async () => ({ Messages: [{ Status: 'success' }] }),
                         text: async () => '{}' };
  };
  f.calls = calls;
  return f;
}

const MJ = { MAIL_PROVIDER: 'mailjet', MAILJET_API_KEY: 'k', MAILJET_SECRET_KEY: 's',
             MAIL_FROM: 'PARAMANT <noreply@paramant.app>' };

// ── GAT 1 ──────────────────────────────────────────────────────────────────
test('afzenderNamens valt terug op MAIL_FROM, ook zonder basis', () => {
  // Dit is letterlijk wat relay.js aanroept: zonder basis.
  //
  // Het gaf `"Zorggroep De Linde via Paramant" <>`. Een leeg haakjespaar is
  // geen adres: ontleedAfzender eist ([^>]+), dus de HELE regel viel in het
  // adresveld en elke mailserver weigert dat. De uitnodiging, de ophaalcode en
  // de herinnering: alle drie, voor elk account met een label, dus iedereen.
  // Onzichtbaar tot een echte verzending.
  const from = mail.afzenderNamens(undefined, 'Zorggroep De Linde');
  const terug = mail.ontleedAfzender(from);
  assert.match(terug.email, /^[^@\s]+@[^@\s]+$/,
    'het adresveld moet een adres bevatten, kreeg: ' + terug.email);
  assert.equal(terug.email, 'noreply@paramant.app');
  assert.equal(terug.name, 'Zorggroep De Linde via Paramant',
    'en de naam hoort in het naamveld, niet in het adres');
});

test('Mailjet krijgt een echt adres in From.Email', async () => {
  const f = vangFetch();
  const r = await mail.stuur({
    to: ['partner0@extern.test'],
    from: mail.afzenderNamens(undefined, 'Zorggroep De Linde'),
    subject: 'Zorggroep De Linde heeft u een bestand gestuurd',
    text: 'hoi',
  }, { fetch: f, env: MJ });
  assert.equal(r.ok, true, 'de neppe provider zegt ja; een echte niet');

  const bericht = f.calls[0].body.Messages[0];
  assert.equal(bericht.From.Email, 'noreply@paramant.app',
    'From.Email moet een adres zijn, niet de hele afzenderregel');
  assert.equal(bericht.From.Name, 'Zorggroep De Linde via Paramant',
    'en de naam van de klant hoort in het naamveld');
});

test('Resend krijgt dezelfde correcte regel', async () => {
  const f = vangFetch();
  await mail.stuur({
    to: ['partner0@extern.test'],
    from: mail.afzenderNamens(undefined, 'Zorggroep De Linde'),
    subject: 'x', text: 'y',
  }, { fetch: f, env: { MAIL_PROVIDER: 'resend', RESEND_API_KEY: 'r',
                        MAIL_FROM: 'PARAMANT <noreply@paramant.app>' } });
  assert.equal(f.calls[0].body.from, '"Zorggroep De Linde via Paramant" <noreply@paramant.app>');
});

test('zonder label komt de gewone afzender terug, niet undefined', async () => {
  const f = vangFetch();
  // Geeft nu de geconfigureerde afzender terug in plaats van undefined: de
  // functie lost de standaard zelf op, zodat geen enkele aanroeper hem nog
  // kan vergeten.
  assert.equal(mail.afzenderNamens(undefined, ''), 'PARAMANT <noreply@paramant.app>');
  await mail.stuur({ to: ['a@b.test'], from: undefined, subject: 'x', text: 'y' },
                   { fetch: f, env: MJ });
  assert.deepEqual(f.calls[0].body.Messages[0].From,
                   { Email: 'noreply@paramant.app', Name: 'PARAMANT' },
    'alleen een account ZONDER label mailt vanaf een geldig adres');
});

test('met de juiste basis klopt de regel wel: dat is de fix', async () => {
  const goed = mail.afzenderNamens('PARAMANT <noreply@paramant.app>', 'Zorggroep De Linde');
  assert.equal(goed, '"Zorggroep De Linde via Paramant" <noreply@paramant.app>');
  const f = vangFetch();
  await mail.stuur({ to: ['a@b.test'], from: goed, subject: 'x', text: 'y' },
                   { fetch: f, env: MJ });
  assert.deepEqual(f.calls[0].body.Messages[0].From,
    { Email: 'noreply@paramant.app', Name: 'Zorggroep De Linde via Paramant' });
});

// ── DE NAAM ZELF ───────────────────────────────────────────────────────────
const AANVALLEN = [
  ['CRLF + kop',   'Anna\r\nBcc: stil@aanvaller.test'],
  ['LF alleen',    'Anna\nBcc: stil@aanvaller.test'],
  ['CR alleen',    'Anna\rSubject: iets anders'],
  ['quotes',       'Anna" <mallory@aanvaller.test> "'],
  ['angle',        'Anna <mallory@aanvaller.test>'],
  ['backslash',    'Anna\\" x'],
  ['tab/vform',    'Anna\tde\vVries\fx'],
  ['NUL',          'Anna\u0000Bcc: stil@aanvaller.test'],
  ['LS/PS',        'Anna\u2028Bcc: x@y.test\u2029'],
  ['10k tekens',   'A'.repeat(10000)],
  // Als escapes, niet als letterlijke tekens: de repo-stijl houdt de bron
    // ASCII, en de bytes die de test verstuurt zijn precies dezelfde.
    ['unicode',      'Zorggroep \u00c5ngstr\u00f6m \u65e5\u672c\u8a9e \ud83c\udfe5'],
];

test('geen enkel label breekt de kopregel', async () => {
  for (const [naam, label] of AANVALLEN) {
    const schoon = mail.veiligeNaam(label);
    const from = mail.afzenderNamens('PARAMANT <noreply@paramant.app>', label);

    assert.ok(!/[\r\n]/.test(from), naam + ': CR/LF in from');
    assert.ok(!/[\r\n]/.test(schoon), naam + ': CR/LF in de naam');
    assert.ok(schoon.length <= 60, naam + ': naam langer dan 60 (' + schoon.length + ')');
    assert.ok(!/bcc/i.test(from) || !/[\r\n]/.test(from), naam + ': kopinjectie');

    // Het adres blijft van ons, wat er ook in het label stond.
    const f = vangFetch();
    await mail.stuur({ to: ['a@b.test'], from, subject: 'x', text: 'y' },
                     { fetch: f, env: MJ });
    const From = f.calls[0].body.Messages[0].From;
    assert.equal(From.Email, 'noreply@paramant.app',
      naam + ': het afzenderadres werd gekaapt -> ' + From.Email);
  }
});

test('BEVINDING: NUL blijft staan en unicode gaat onversleuteld de kop in', () => {
  // \u0000 zit niet in \s en niet in ["\\<>], dus veiligeNaam laat hem door.
  // Geen kopinjectie (het is geen CRLF), wel een byte die sommige MTA-parsers
  // als string-einde lezen. Waard om af te vangen, niet urgent.
  assert.ok(mail.veiligeNaam('Anna\u0000x').includes('\u0000'),
    'als dit faalt is de NUL alsnog gestript en is deze bevinding weg');

  // Een non-ASCII display name hoort RFC 2047-gecodeerd (=?UTF-8?B?...?=).
  // Dat gebeurt hier niet; bij mailjet/resend/scaleway mag dat, want de naam
  // gaat als JSON-veld mee en de provider codeert zelf. Bij een toekomstige
  // SMTP-carrier is dit een kapotte kop.
  assert.equal(mail.veiligeNaam('Ångström 日本語'), 'Ångström 日本語');
});

test('de naam wordt op 60 tekens afgekapt, dus 10k is geen geheugenaanval', () => {
  assert.equal(mail.veiligeNaam('A'.repeat(10000)).length, 60);
  assert.equal(mail.afzenderNamens('PARAMANT <noreply@paramant.app>', 'A'.repeat(10000)),
    '"' + 'A'.repeat(60) + ' via Paramant" <noreply@paramant.app>');
});
