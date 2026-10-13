'use strict';
// Welk e-mailadres mag een account openen, en wie wordt nooit getoetst.
//
// De lijst staat in deploy/email-blocklist.json (bijgewerkt door
// scripts/update-email-blocklist.mjs). Deze module leest hem en beslist per
// DOEL. Het doel is geen detail: het is het beleid.
//
//   aanmelden        een account of sleutel aanvragen (/api/user/signup, de
//                    admin-routes die een sleutel op een adres zetten). Lijst
//                    en, standaard, een MX-controle.
//   verzenden        wie iets verstuurt zonder account (/api/drop/upload).
//                    Alleen de lijst.
//   ontvanger        wie iets ontvangt: groepsverzending, /ontvang, een
//                    ophaalcode, een uitnodiging om te tekenen. NOOIT getoetst.
//   gesprek-client   de cliënt van een Veilig gesprek. NOOIT getoetst.
//
// Waarom ontvangers nooit: iemand die hulp zoekt gebruikt soms een los
// wegwerpadres omdat het eigen adres wordt meegelezen. Die persoon weigeren
// is precies de verkeerde kant op. Een ontvanger vraagt ook geen account aan;
// de lijst is er om aanmeldingen tegen te houden, niet om mensen te bereiken.
//
// Loggen: alleen het domein, de categorie en het doel. Nooit het adres.

const fs = require('fs');
const path = require('path');
const dns = require('dns');
const { domainToASCII } = require('url');

const BESTAND = path.join(__dirname, '..', '..', 'deploy', 'email-blocklist.json');

const DOELEN = Object.freeze({
  aanmelden: Object.freeze({ lijst: true, mx: true }),
  verzenden: Object.freeze({ lijst: true, mx: false }),
  ontvanger: null,
  'gesprek-client': null,
});

const MELDING = Object.freeze({
  aanmelden: Object.freeze({
    nl: 'Dit e-mailadres kunnen we niet gebruiken voor een account. Gebruik een adres dat u blijvend leest.',
    en: 'We cannot use this email address for an account. Please use an address you will keep reading.',
  }),
  verzenden: Object.freeze({
    nl: 'Dit e-mailadres kunnen we hiervoor niet gebruiken. Gebruik een adres dat u blijvend leest.',
    en: 'We cannot use this email address for this. Please use an address you will keep reading.',
  }),
});

// Kleine letters, geen punt aan het eind, en IDN naar punycode, zodat
// "Mailinator.COM." en een unicode-schrijfwijze op dezelfde sleutel vallen.
function normaliseerDomein(domein) {
  const d = String(domein || '').trim().toLowerCase().replace(/\.+$/, '');
  if (!d || d.length > 253) return '';
  const ascii = domainToASCII(d);
  return ascii || '';
}

function domeinVan(email) {
  const s = String(email || '').trim();
  const at = s.lastIndexOf('@');
  if (at < 1) return '';
  return normaliseerDomein(s.slice(at + 1));
}

// sub.wegwerp.tld -> [sub.wegwerp.tld, wegwerp.tld]. De losse tld zelf nooit:
// die hoort alleen bij de gereserveerde tld's.
function achtervoegsels(domein) {
  const delen = domein.split('.');
  const uit = [];
  for (let i = 0; i < delen.length - 1; i++) uit.push(delen.slice(i).join('.'));
  return uit;
}

function bouw(data) {
  const blok = new Map();
  const cats = data.categorieen || {};
  for (const [categorie, c] of Object.entries(cats)) {
    for (const d of c.domeinen || []) blok.set(normaliseerDomein(d), categorie);
    for (const h of c.handmatig || []) blok.set(normaliseerDomein(h.domein), categorie);
  }
  const tlds = new Map();
  for (const [categorie, c] of Object.entries(cats)) {
    for (const t of c.tlds || []) tlds.set(normaliseerDomein(t.tld || t), categorie);
  }
  const uitzonderingen = new Set((data.uitzonderingen || []).map((u) => normaliseerDomein(u.domein)));
  blok.delete('');
  return { blok, tlds, uitzonderingen };
}

let _standaard = null;
function standaardLijst() {
  if (!_standaard) _standaard = bouw(JSON.parse(fs.readFileSync(BESTAND, 'utf8')));
  return _standaard;
}

// Alleen de lijst, zonder DNS. { categorie } of null.
function opLijst(domein, lijst = standaardLijst()) {
  const d = normaliseerDomein(domein);
  if (!d) return { categorie: 'ongeldig' };
  const suf = achtervoegsels(d);
  // De uitzondering wint, ook van een automatische update die er toch een
  // aanbieder in zou zetten.
  if (suf.some((s) => lijst.uitzonderingen.has(s))) return null;
  for (const s of suf) {
    const categorie = lijst.blok.get(s);
    if (categorie) return { categorie };
  }
  if (!d.includes('.') && lijst.blok.has(d)) return { categorie: lijst.blok.get(d) };
  const tld = d.split('.').pop();
  if (lijst.tlds.has(tld)) return { categorie: lijst.tlds.get(tld) };
  return null;
}

function metTijdslimiet(p, ms) {
  let t;
  return Promise.race([
    p.finally(() => clearTimeout(t)),
    new Promise((_, rej) => { t = setTimeout(() => rej(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })), ms); }),
  ]);
}

const GEEN_ANTWOORD = new Set(['ENODATA', 'ENOTFOUND']);

// Kan dit domein mail ontvangen? 'ja', 'nee' of 'onbekend'. Alleen 'nee' telt:
// een DNS-storing of een trage server mag nooit iemand weigeren.
async function kanMailOntvangen(domein, { resolver, timeoutMs = 1500 } = {}) {
  const r = resolver || new dns.promises.Resolver({ timeout: timeoutMs, tries: 1 });
  try {
    const mx = await metTijdslimiet(r.resolveMx(domein), timeoutMs + 250);
    if (Array.isArray(mx) && mx.length) {
      // RFC 7505: een enkele MX "." zegt uitdrukkelijk: hier komt geen mail aan.
      if (mx.every((m) => !m.exchange || m.exchange === '.')) return 'nee';
      return 'ja';
    }
  } catch (e) {
    if (!GEEN_ANTWOORD.has(e && e.code)) return 'onbekend';
  }
  // Geen MX: RFC 5321 valt dan terug op het A- of AAAA-record.
  let onzeker = false;
  for (const soort of ['resolve4', 'resolve6']) {
    try {
      const a = await metTijdslimiet(r[soort](domein), timeoutMs + 250);
      if (Array.isArray(a) && a.length) return 'ja';
    } catch (e) {
      if (!GEEN_ANTWOORD.has(e && e.code)) onzeker = true;
    }
  }
  return onzeker ? 'onbekend' : 'nee';
}

function mxAan(env = process.env) {
  return !/^(0|false|nee|uit|off)$/i.test(String(env.EMAIL_MX_CHECK || '').trim());
}

// De enige ingang voor routes.
//   doel      een sleutel uit DOELEN; een onbekend doel is een programmeerfout
//   opts.mx   false zet de MX-controle voor deze aanroep uit
//   opts.lijst, opts.resolver, opts.log, opts.env: voor tests
// Uit: { ok: true } of { ok: false, domein, categorie, melding }.
async function toets(email, doel, opts = {}) {
  if (!Object.prototype.hasOwnProperty.call(DOELEN, doel)) {
    throw new Error(`email-policy: onbekend doel "${doel}"`);
  }
  const regel = DOELEN[doel];
  if (!regel) return { ok: true, getoetst: false };
  const log = opts.log || ((m) => console.warn(m));
  const domein = domeinVan(email);
  const weiger = (categorie) => {
    log(`[email-policy] geweigerd doel=${doel} categorie=${categorie} domein=${domein || '-'}`);
    return { ok: false, domein, categorie, melding: MELDING[doel] };
  };
  if (!domein) return weiger('ongeldig');
  const hit = opLijst(domein, opts.lijst || standaardLijst());
  if (hit) return weiger(hit.categorie);
  const env = opts.env || process.env;
  if (regel.mx && opts.mx !== false && mxAan(env)) {
    const lijst = opts.lijst || standaardLijst();
    const vrij = achtervoegsels(domein).some((s) => lijst.uitzonderingen.has(s));
    if (!vrij) {
      const oordeel = await kanMailOntvangen(domein, { resolver: opts.resolver, timeoutMs: opts.timeoutMs });
      if (oordeel === 'nee') return weiger('geen-mx');
      if (oordeel === 'onbekend') log(`[email-policy] dns onbekend, niet geweigerd doel=${doel} domein=${domein}`);
    }
  }
  return { ok: true, getoetst: true };
}

// Het antwoord dat een route geeft bij een weigering. 422, zoals de oude
// denylist, zodat de site hem blijft herkennen.
function antwoord(uitslag) {
  return {
    error: 'invalid_email',
    reason: 'domain_not_allowed',
    message: uitslag.melding.en,
    message_nl: uitslag.melding.nl,
    message_en: uitslag.melding.en,
  };
}

module.exports = {
  BESTAND, DOELEN, MELDING,
  normaliseerDomein, domeinVan, achtervoegsels, bouw, opLijst, kanMailOntvangen, mxAan, toets, antwoord,
};
