'use strict';

// DE TWEEDE CARRIER, en wat hij opnieuw verstuurt.
//
// MAIL_FALLBACK_PROVIDER vuurt als de eerste weigert (lib/mail.js:373-389).
// De vraag die nooit gesteld is: WAT stuurt hij dan opnieuw. `stuur` bewaart
// een enkel resultaat per bericht, dus een provider die DEELS slaagde -- 29
// van de 30 adressen aangenomen, een geweigerd -- komt terug als ok:false, en
// de hele boodschap gaat bij de tweede carrier nog een keer de deur uit. Naar
// alle dertig.
//
// Alles met een neppe fetch. Er gaat geen byte naar een provider.

const assert = require('node:assert/strict');
const { test } = require('node:test');
const mail = require('../lib/mail');

const DERTIG = Array.from({ length: 30 }, (_, i) => `partner${i}@extern.test`);

const BERICHT = {
  to: DERTIG,
  subject: 'Zorggroep De Linde sent you a file',
  text: 'Zorggroep De Linde sent you a file through Paramant.',
};

// Telt per provider wie er post kreeg.
function bouwFetch(regels) {
  const bezorgd = { mailjet: [], scaleway: [], resend: [] };
  const f = async (url, opts) => {
    const body = JSON.parse(opts.body);
    if (url.includes('mailjet')) {
      const adressen = body.Messages.map(m => m.To[0].Email);
      const uit = regels.mailjet(adressen);
      // Mailjet neemt ALLES aan wat niet expliciet geweigerd wordt: de
      // geslaagde regels zijn echte bezorgingen, ook als er een faalt.
      for (const a of adressen) if (!uit.weiger.includes(a)) bezorgd.mailjet.push(a);
      if (uit.http) return { ok: false, status: uit.http, text: async () => 'stuk' };
      return { ok: true, status: 200,
               json: async () => ({ Messages: adressen.map(a => ({
                 Status: uit.weiger.includes(a) ? 'error' : 'success', Email: a })) }),
               text: async () => '{}' };
    }
    if (url.includes('scaleway')) {
      const a = body.to[0].email;
      const uit = regels.scaleway(a, bezorgd.scaleway.length);
      if (!uit) return { ok: false, status: 500, text: async () => 'stuk' };
      bezorgd.scaleway.push(a);
      return { ok: true, status: 200, json: async () => ({}), text: async () => '{}' };
    }
    for (const a of body.to) bezorgd.resend.push(a);
    return { ok: true, status: 200, json: async () => ({}), text: async () => '{}' };
  };
  f.bezorgd = bezorgd;
  return f;
}

const ALLES_GOED = { mailjet: () => ({ weiger: [] }), scaleway: () => true };

// ── GAT 1: EEN geweigerd adres kost 29 mensen een dubbele mail ────────────
test('een halve bezorging gaat NIET opnieuw de deur uit', async () => {
  const slecht = DERTIG[17];
  const f = bouwFetch({
    mailjet: () => ({ weiger: [slecht] }),
    scaleway: () => true,
  });

  const r = await mail.stuur(BERICHT, {
    fetch: f,
    env: { MAIL_PROVIDER: 'mailjet', MAILJET_API_KEY: 'k', MAILJET_SECRET_KEY: 's',
           MAIL_FALLBACK_PROVIDER: 'scaleway', SCALEWAY_SECRET_KEY: 'x',
           SCALEWAY_PROJECT_ID: 'p' },
  });

  // Mailjet nam er 29 aan en weigerde er een, en meldt dat als ok:false.
  assert.equal(f.bezorgd.mailjet.length, 29, 'mailjet bezorgde er 29');
  assert.ok(!f.bezorgd.mailjet.includes(slecht));

  // En de reserve houdt zich stil. Dit deed hij wel, en dan kregen die
  // negenentwintig een TWEEDE uitnodiging voor een vertrouwelijk bestand:
  // dertig gevraagd, negenenvijftig bezorgd, en het antwoord zei dertig.
  assert.equal(f.bezorgd.scaleway.length, 0,
    'de fallback stuurt naar ALLE dertig, niet naar de ene die faalde');

  const dubbel = f.bezorgd.scaleway.filter(a => f.bezorgd.mailjet.includes(a));
  assert.equal(dubbel.length, 0, 'niemand krijgt dezelfde uitnodiging twee keer');

  // En het blijft een mislukking, met de reden erbij: de afzender moet weten
  // dat er een adres niet bereikt is, niet denken dat alles goed ging.
  assert.equal(r.ok, false);
  assert.equal(r.fallback, 'skipped_partial_delivery');
  assert.equal(r.reason, 'rejected', 'de reden van de eerste carrier blijft staan');
  assert.equal(r.count, 29,
    'het getal moet zeggen hoeveel er ECHT weg zijn, niet hoeveel er gevraagd werden');
});

// ── GAT 2: hetzelfde bij een carrier die per adres verstuurt ──────────────
test('GAT: scaleway valt halverwege om, de fallback herhaalt de eerste 14', async () => {
  const f = bouwFetch({
    mailjet: () => ({ weiger: [] }),
    scaleway: (_a, gedaan) => gedaan < 14,   // vanaf de 15e is de API stuk
  });

  const r = await mail.stuur(BERICHT, {
    fetch: f,
    env: { MAIL_PROVIDER: 'scaleway', SCALEWAY_SECRET_KEY: 'x', SCALEWAY_PROJECT_ID: 'p',
           MAIL_FALLBACK_PROVIDER: 'mailjet', MAILJET_API_KEY: 'k', MAILJET_SECRET_KEY: 's' },
  });

  assert.equal(f.bezorgd.scaleway.length, 14,
    'scaleway (lib/mail.js:183-212) stopt bij het eerste adres dat faalt');
  assert.equal(f.bezorgd.mailjet.length, 30, 'mailjet doet alle dertig');
  const dubbel = f.bezorgd.mailjet.filter(a => f.bezorgd.scaleway.includes(a));
  assert.equal(dubbel.length, 14, 'veertien mensen krijgen hem twee keer');
  assert.equal(r.ok, true);
  assert.equal(r.fallback_used, true);
});

// ── WAT WEL GOED GAAT ─────────────────────────────────────────────────────
test('een harde weigering: de fallback neemt over en verstuurt PRECIES een keer', async () => {
  const f = bouwFetch({
    mailjet: () => ({ weiger: [], http: 503 }),   // niets aangenomen
    scaleway: () => true,
  });
  // http:503 betekent hierboven dat mailjet niets bezorgt.
  f.bezorgd.mailjet.length = 0;

  const r = await mail.stuur({ to: ['partner0@extern.test'], subject: 's', text: 't' }, {
    fetch: f,
    env: { MAIL_PROVIDER: 'mailjet', MAILJET_API_KEY: 'k', MAILJET_SECRET_KEY: 's',
           MAIL_FALLBACK_PROVIDER: 'scaleway', SCALEWAY_SECRET_KEY: 'x',
           SCALEWAY_PROJECT_ID: 'p' },
  });
  assert.equal(r.ok, true);
  assert.equal(r.provider, 'scaleway');
  assert.equal(r.fallback_used, true);
  assert.equal(r.primary, 'mailjet');
  assert.equal(r.primary_reason, 'http_503');
  assert.equal(f.bezorgd.scaleway.length, 1, 'precies een keer bezorgd');
});

test('de fallback vuurt NIET als de eerste het gewoon deed', async () => {
  const f = bouwFetch(ALLES_GOED);
  const r = await mail.stuur(BERICHT, {
    fetch: f,
    env: { MAIL_PROVIDER: 'mailjet', MAILJET_API_KEY: 'k', MAILJET_SECRET_KEY: 's',
           MAIL_FALLBACK_PROVIDER: 'scaleway', SCALEWAY_SECRET_KEY: 'x',
           SCALEWAY_PROJECT_ID: 'p' },
  });
  assert.equal(r.ok, true);
  assert.equal(r.fallback_used, undefined);
  assert.equal(f.bezorgd.scaleway.length, 0, 'geen tweede ronde');
  assert.equal(f.bezorgd.mailjet.length, 30);
});

test('een ongeldig bericht gaat niet naar de tweede carrier', async () => {
  const f = bouwFetch(ALLES_GOED);
  const r = await mail.stuur({ to: [], subject: 's', text: 't' }, {
    fetch: f,
    env: { MAIL_PROVIDER: 'mailjet', MAILJET_API_KEY: 'k', MAILJET_SECRET_KEY: 's',
           MAIL_FALLBACK_PROVIDER: 'scaleway', SCALEWAY_SECRET_KEY: 'x',
           SCALEWAY_PROJECT_ID: 'p' },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'invalid');
  assert.equal(f.bezorgd.scaleway.length, 0);
});

// ── WAAROM DE ROUTE HIER VANDAAG NOG NET ONDERUIT KOMT ────────────────────
test('de route mailt per persoon, dus vandaag raakt dit gat een mail tegelijk', async () => {
  // relay.js:4724-4730 loopt per ontvanger en zet `to: adres`. Dat is een
  // string, dus normaliseer maakt er een lijst van een. Het gat hierboven
  // bijt pas bij een caller die meerdere adressen in een `to` zet -- of zodra
  // iemand de lus optimaliseert naar een batch, wat precies het soort
  // wijziging is dat "sneller" heet en 29 dubbele mails kost.
  const m = mail.normaliseer({ to: 'partner0@extern.test', subject: 's', text: 't' });
  assert.deepEqual(m.to, ['partner0@extern.test']);

  // Maar EEN adres dat faalt, faalt dan ook volledig, en de fallback doet dat
  // ene bericht opnieuw. Dat is wel correct.
  const f = bouwFetch({ mailjet: (a) => ({ weiger: a }), scaleway: () => true });
  f.bezorgd.mailjet.length = 0;
  const r = await mail.stuur({ to: 'partner0@extern.test', subject: 's', text: 't' }, {
    fetch: f,
    env: { MAIL_PROVIDER: 'mailjet', MAILJET_API_KEY: 'k', MAILJET_SECRET_KEY: 's',
           MAIL_FALLBACK_PROVIDER: 'scaleway', SCALEWAY_SECRET_KEY: 'x',
           SCALEWAY_PROJECT_ID: 'p' },
  });
  assert.equal(r.ok, true);
  assert.equal(f.bezorgd.scaleway.length, 1);
});
