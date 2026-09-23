'use strict';
// admin/lib/email-policy.js: wie een account kan openen, en wie nooit getoetst
// wordt. Geen redis, geen netwerk: de DNS-antwoorden komen van een nep-resolver.
//
// Het beleid in een zin: de lijst geldt voor aanmelden en verzenden, nooit voor
// een ontvanger en nooit voor de cliënt van een Veilig gesprek. Die helft van
// het beleid staat hier net zo hard vast als de weigering zelf.
//
// Run: node --test admin/test/email-policy.test.js

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { domainToUnicode } = require('url');
const policy = require('../lib/email-policy');

const ROOT = path.join(__dirname, '..', '..');
const data = JSON.parse(fs.readFileSync(policy.BESTAND, 'utf8'));

const zonderDns = { mx: false, log: () => {} };
const WEGWERP = ['mailinator.com', 'yopmail.com', 'guerrillamail.com', '10minutemail.com', 'trashmail.com'];

// Nep-resolver: per methode een antwoord of een fout met een code.
function resolver(antwoorden) {
  const r = {};
  for (const m of ['resolveMx', 'resolve4', 'resolve6']) {
    r[m] = async () => {
      const a = antwoorden[m];
      if (a === 'hangt') return new Promise(() => {});
      if (typeof a === 'string') throw Object.assign(new Error(a), { code: a });
      if (a === undefined) throw Object.assign(new Error('ENODATA'), { code: 'ENODATA' });
      return a;
    };
  }
  return r;
}

test('bekende wegwerpdomeinen worden bij aanmelden geweigerd', async () => {
  for (const d of WEGWERP) {
    const u = await policy.toets(`iemand@${d}`, 'aanmelden', zonderDns);
    assert.equal(u.ok, false, `${d} kwam erdoor bij aanmelden`);
    assert.equal(u.categorie, 'wegwerp');
    assert.equal(u.melding.nl, 'Dit e-mailadres kunnen we niet gebruiken voor een account. Gebruik een adres dat u blijvend leest.');
    assert.ok(u.melding.en.length > 20);
  }
});

test('wie zonder account verzendt, wordt ook getoetst', async () => {
  const u = await policy.toets('iemand@mailinator.com', 'verzenden', { log: () => {} });
  assert.equal(u.ok, false);
  assert.equal(u.categorie, 'wegwerp');
});

test('dezelfde adressen zijn als ontvanger en als cliënt van een Veilig gesprek altijd welkom', async () => {
  // Een resolver die ontploft bewijst dat er niet eens naar DNS gekeken wordt.
  const ontploft = { resolveMx: () => { throw new Error('mag niet'); } };
  for (const doel of ['ontvanger', 'gesprek-client']) {
    for (const d of [...WEGWERP, 'example.com', 'bestaat-niet.invalid']) {
      const u = await policy.toets(`iemand@${d}`, doel, { resolver: ontploft, log: () => { throw new Error('geen log voor een ontvanger'); } });
      assert.deepEqual(u, { ok: true, getoetst: false }, `${d} geweigerd als ${doel}`);
    }
    // Ook een adres dat nergens op lijkt: een ontvanger wordt hier niet beoordeeld.
    assert.equal((await policy.toets('', doel)).ok, true);
  }
  assert.equal(policy.DOELEN.ontvanger, null);
  assert.equal(policy.DOELEN['gesprek-client'], null);
});

test('een onbekend doel is een fout, geen stille doorlaat', async () => {
  await assert.rejects(() => policy.toets('a@mailinator.com', 'ontvangst'), /onbekend doel/);
});

test('subdomeinen van een wegwerpdomein vallen er ook onder, de tld alleen niet', async () => {
  assert.equal((await policy.toets('a@post.mailinator.com', 'aanmelden', zonderDns)).categorie, 'wegwerp');
  assert.equal((await policy.toets('a@x.y.yopmail.com', 'aanmelden', zonderDns)).categorie, 'wegwerp');
  assert.deepEqual(policy.achtervoegsels('a.b.com'), ['a.b.com', 'b.com']);
  assert.equal(policy.opLijst('com'), null);
});

test('hoofdletters, een punt aan het eind en IDN vallen op dezelfde sleutel', async () => {
  assert.equal((await policy.toets('A@MailInator.COM.', 'aanmelden', zonderDns)).ok, false);
  // Een eigen lijst met een punycode-domein, aangeboden in unicode.
  const lijst = policy.bouw({ categorieen: { wegwerp: { domeinen: ['xn--bcher-kva.example-wegwerp.nl'] } }, uitzonderingen: [] });
  const u = await policy.toets('a@BÜCHER.example-wegwerp.nl', 'aanmelden', { ...zonderDns, lijst });
  assert.equal(u.ok, false);
  assert.equal(u.domein, 'xn--bcher-kva.example-wegwerp.nl');
  // En een IDN-domein uit de echte lijst, in zijn unicode-vorm getypt.
  const idn = data.categorieen.wegwerp.domeinen.find((d) => d.startsWith('xn--'));
  assert.ok(idn, 'de lijst heeft geen enkel punycode-domein meer; kies een ander voorbeeld');
  const uni = domainToUnicode(idn);
  assert.notEqual(uni, idn);
  assert.equal((await policy.toets(`a@${uni}`, 'aanmelden', zonderDns)).ok, false, `${uni} (${idn}) kwam erdoor`);
});

test('de uitzondering wint, ook als een update de aanbieder op de lijst zet', async () => {
  const lijst = policy.bouw({
    categorieen: { wegwerp: { domeinen: ['proton.me', 'tuta.com', 'mailinator.com'] } },
    uitzonderingen: [{ domein: 'proton.me' }, { domein: 'tuta.com' }],
  });
  assert.equal((await policy.toets('a@proton.me', 'aanmelden', { ...zonderDns, lijst })).ok, true);
  assert.equal((await policy.toets('a@tuta.com', 'aanmelden', { ...zonderDns, lijst })).ok, true);
  assert.equal((await policy.toets('a@mailinator.com', 'aanmelden', { ...zonderDns, lijst })).ok, false);
});

test('privacyvriendelijke en grote aanbieders komen er met de echte lijst altijd door', async () => {
  const nooit = ['proton.me', 'protonmail.com', 'pm.me', 'tuta.com', 'tutanota.com', 'tutanota.de', 'tutamail.com',
    'keemail.me', 'mailbox.org', 'posteo.de', 'posteo.net', 'disroot.org', 'riseup.net', 'startmail.com',
    'mailfence.com', 'runbox.com', 'fastmail.com', 'gmail.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'yahoo.com'];
  const ontploft = { resolveMx: () => { throw new Error('een uitzondering hoeft niet langs DNS'); } };
  for (const d of nooit) {
    const u = await policy.toets(`iemand@${d}`, 'aanmelden', { resolver: ontploft, log: () => {} });
    assert.equal(u.ok, true, `${d} geweigerd`);
  }
});

test('gereserveerde namen blijven geweigerd, zoals in de oude lijst', async () => {
  for (const a of ['a@example.com', 'a@test.com', 'a@host.test', 'a@x.invalid', 'a@printer.local', 'a@localhost', 'a@cool.fr.nf']) {
    assert.equal((await policy.toets(a, 'aanmelden', zonderDns)).ok, false, `${a} kwam erdoor`);
  }
});

test('MX: een domein zonder MX, A en AAAA wordt bij aanmelden geweigerd', async () => {
  const r = resolver({ resolveMx: 'ENOTFOUND', resolve4: 'ENOTFOUND', resolve6: 'ENOTFOUND' });
  const u = await policy.toets('a@verzonnen-domein-zonder-dns.nl', 'aanmelden', { resolver: r, log: () => {}, env: {} });
  assert.equal(u.ok, false);
  assert.equal(u.categorie, 'geen-mx');
  // Null MX (RFC 7505): het domein zegt zelf dat er geen mail aankomt.
  const nullMx = resolver({ resolveMx: [{ exchange: '', priority: 0 }] });
  assert.equal((await policy.toets('a@geen-mail.nl', 'aanmelden', { resolver: nullMx, log: () => {}, env: {} })).categorie, 'geen-mx');
});

test('MX: geen MX maar wel een A-record is genoeg (RFC 5321)', async () => {
  const r = resolver({ resolveMx: 'ENODATA', resolve4: ['192.0.2.1'] });
  assert.equal((await policy.toets('a@alleen-a.nl', 'aanmelden', { resolver: r, log: () => {}, env: {} })).ok, true);
  const mx = resolver({ resolveMx: [{ exchange: 'mx.alleen-mx.nl', priority: 10 }] });
  assert.equal((await policy.toets('a@alleen-mx.nl', 'aanmelden', { resolver: mx, log: () => {}, env: {} })).ok, true);
});

test('MX: bij een DNS-fout of een time-out wordt niemand geweigerd', async () => {
  for (const fout of ['ESERVFAIL', 'ETIMEOUT', 'ECONNREFUSED', 'EREFUSED']) {
    const r = resolver({ resolveMx: fout });
    assert.equal((await policy.toets('a@storing.nl', 'aanmelden', { resolver: r, log: () => {}, env: {} })).ok, true, fout);
  }
  // MX weg, A-record kwijt door een storing: onbekend, dus niet weigeren.
  const half = resolver({ resolveMx: 'ENODATA', resolve4: 'ESERVFAIL', resolve6: 'ENODATA' });
  assert.equal((await policy.toets('a@half.nl', 'aanmelden', { resolver: half, log: () => {}, env: {} })).ok, true);
  // Een resolver die nooit antwoordt: de eigen time-out vangt hem.
  const t0 = Date.now();
  const hangt = resolver({ resolveMx: 'hangt' });
  assert.equal((await policy.toets('a@traag.nl', 'aanmelden', { resolver: hangt, timeoutMs: 100, log: () => {}, env: {} })).ok, true);
  assert.ok(Date.now() - t0 < 2000, 'de time-out werkte niet');
});

test('MX: uit met EMAIL_MX_CHECK=0, en nooit bij verzenden', async () => {
  const r = resolver({ resolveMx: 'ENOTFOUND', resolve4: 'ENOTFOUND', resolve6: 'ENOTFOUND' });
  assert.equal((await policy.toets('a@weg.nl', 'aanmelden', { resolver: r, log: () => {}, env: { EMAIL_MX_CHECK: '0' } })).ok, true);
  assert.equal((await policy.toets('a@weg.nl', 'verzenden', { resolver: r, log: () => {}, env: {} })).ok, true);
  assert.equal(policy.mxAan({}), true);
  assert.equal(policy.mxAan({ EMAIL_MX_CHECK: 'false' }), false);
});

test('het log noemt het domein en de categorie, nooit het adres', async () => {
  const regels = [];
  await policy.toets('geheime.naam+tag@mailinator.com', 'aanmelden', { mx: false, log: (m) => regels.push(m) });
  const r = resolver({ resolveMx: 'ESERVFAIL' });
  await policy.toets('geheime.naam@storing.nl', 'aanmelden', { resolver: r, log: (m) => regels.push(m), env: {} });
  assert.equal(regels.length, 2);
  for (const m of regels) {
    assert.ok(!m.includes('geheime'), `het adres staat in het log: ${m}`);
    assert.ok(!m.includes('@'), `een @ in het log: ${m}`);
  }
  assert.match(regels[0], /categorie=wegwerp/);
  assert.match(regels[0], /domein=mailinator\.com/);
});

test('het antwoord van een route: 422-vorm met de rustige melding in beide talen', async () => {
  const u = await policy.toets('a@mailinator.com', 'aanmelden', zonderDns);
  const a = policy.antwoord(u);
  assert.equal(a.error, 'invalid_email');
  assert.equal(a.reason, 'domain_not_allowed');
  assert.equal(a.message_nl, policy.MELDING.aanmelden.nl);
  assert.equal(a.message_en, policy.MELDING.aanmelden.en);
  for (const t of [a.message_nl, a.message_en]) {
    assert.ok(!/misbruik|abuse|spam|fraud|fraude|verdacht|suspicious|nep|fake|echt/i.test(t), `beschuldigende taal: ${t}`);
    assert.ok(!t.includes('!'), 'geen uitroepteken');
  }
  // De site toont dezelfde zin.
  const js = fs.readFileSync(path.join(ROOT, 'frontend/js/signup.inline1.js'), 'utf8');
  assert.ok(js.includes(policy.MELDING.aanmelden.nl) && js.includes(policy.MELDING.aanmelden.en),
    'frontend/js/signup.inline1.js toont bij 422 niet de melding uit admin/lib/email-policy.js');
});

// Het beleid in de routes. Elke aanroep van emailPolicy.toets in admin/server.js
// hoort bij een route op deze lijst, met dit doel. Een nieuwe aanroep op een
// ontvangersroute laat deze toets vallen.
test('alleen aanmeld- en verzendroutes toetsen; geen ontvangersroute, en de relay nergens', () => {
  const src = fs.readFileSync(path.join(ROOT, 'admin/server.js'), 'utf8');
  const gevonden = [];
  for (const m of src.matchAll(/emailPolicy\.toets\([^,]+,\s*'([a-z-]+)'/g)) {
    const voor = src.slice(0, m.index);
    const routes = [...voor.matchAll(/api\.(?:post|get|put|delete)\(\s*['"]([^'"]+)['"]/g)];
    gevonden.push(`${routes[routes.length - 1][1]} ${m[1]}`);
  }
  assert.deepEqual(gevonden.sort(), [
    '/drop/upload verzenden',
    '/keys/all aanmelden',
    '/keys/sectors aanmelden',
    '/user/signup aanmelden',
  ]);
  // Geen enkele andere weg naar de lijst in de admin.
  assert.ok(!/(require|readFileSync)\([^)]*email-blocklist/.test(src), 'admin/server.js leest de lijst zelf; ga via admin/lib/email-policy.js');
  // Ontvangers leven in de relay (/v2/pickup, /ontvang, groepsverzending) en
  // in de uitnodigingsroutes van de admin. Geen van beide mag de lijst kennen.
  const relayBestanden = ['relay/relay.js', ...fs.readdirSync(path.join(ROOT, 'relay/lib')).filter((f) => f.endsWith('.js')).map((f) => `relay/lib/${f}`)];
  for (const f of relayBestanden) {
    const s = fs.readFileSync(path.join(ROOT, f), 'utf8');
    assert.ok(!/email-policy|email-blocklist/.test(s), `${f} kent de e-mailblocklist; ontvangers worden nooit getoetst`);
  }
  for (const route of ['/user/envelopes/:id/invitations', '/user/sends/:id/reinvite', '/user/parasign/inbox/:id/resend']) {
    const at = src.indexOf(`api.post("${route}"`);
    assert.ok(at > 0, `route ${route} niet gevonden; werk deze toets bij`);
    const eind = src.indexOf('\napi.', at + 10);
    assert.ok(!src.slice(at, eind).includes('emailPolicy'), `${route} toetst een ontvanger`);
  }
});
