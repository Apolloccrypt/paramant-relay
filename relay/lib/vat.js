'use strict';
// Which VAT a sale carries: 21% Dutch VAT, or none because it is reverse
// charged to a business in another EU member state.
//
// THE RULE. A service a Dutch business supplies to a business established in
// another member state is taxed where that customer is, and the customer
// accounts for the VAT (Directive 2006/112/EC art. 44 and 196). The invoice
// then carries no VAT, says "Btw verlegd" / "VAT reverse charged", and states
// the VAT identification numbers of both parties (art. 226; Wet OB art. 35a).
// A Dutch business and a private buyer pay the 21% the catalog prices include.
//
// KNOWN GAP, NOT THE RULE: a business outside the EU is charged 21% too. The
// place of supply is where that business is established (Wet OB art. 6 lid 1),
// so no Dutch VAT is due, and VAT on the invoice is owed anyway and cannot be
// deducted by the customer. Issue #519.
//
// REVERSE CHARGE ONLY WHEN ALL OF THESE HOLD, and 21% in every other case:
//   - the seller's own VAT id is configured (BILLING_SELLER_VAT). Without it
//     the document is a payment receipt, which cannot carry the mentions above;
//   - the buyer's VAT id starts with the code of a member state other than the
//     Netherlands. That code is the member state that issued the number, which
//     is what "the buyer's country" means for this rule, and it is the country
//     VIES is asked about;
//   - the account carries a company name and an address. Implementing
//     Regulation (EU) 282/2011 art. 18(1)(a) asks for the validity of the
//     number AND of the associated name and address, and both belong on the
//     invoice (Directive art. 226 point 5);
//   - the address does not name another country, and VIES does not name a
//     clearly different company or country for that number;
//   - VIES answers that the number is valid, at the moment of the checkout, and
//     hands back a consultation number: the proof that the check was made.
// VIES unreachable, slow, or answering anything else: 21%, and a log line that
// names the country and the reason, never the number. That is the safe side
// for the seller. VAT charged that turns out not to be due is corrected with a
// credit note; VAT not charged that was due is owed by the seller.
//
// THE PROOF IS KEPT. What VIES answered (date, consultation number, and the
// name and address it holds for the number) is stored at the checkout under the
// consultation number, and copied onto the invoice (vat_check). A checkout that
// cannot store it is a 21% checkout. It is stored for thirty days first: most
// checkouts are never paid, and their proof then belongs to nothing. Once the
// payment is in and its invoice exists, the proof loses its TTL and is kept
// like every other bookkeeping record.
//
// WHERE THE DECISION LIVES AFTERWARDS. On the payment itself: the checkout puts
// the terms in the Mollie metadata, and Mollie hands them back on every fetch.
// The webhook's amount check, the invoice and every renewal of the
// subscription read them from there, so all of them agree with what the buyer
// was actually charged, without a second VIES call and without a store that
// could be flushed. The metadata is written by this server with its own API
// key; a buyer cannot set it.
//
// KNOWN GAPS IN THE RECURRING LAYER, to close before BILLING_MODE is switched
// on: a renewal follows the VIES check of the first payment and does not ask
// again, and an older 21% subscription is not replaced after a later
// reverse-charged purchase. Issue #520.

const https = require('https');
const invoice = require('./invoice');

// The proof of one VIES check, by its consultation number. No TTL: it is part
// of the documents that must be kept seven years (AWR art. 52).
const PROOF_KEY = (consultation) => `paramant:billing:vat:proof:${consultation}`;
// How long the proof of a checkout that is never paid is kept. /privacy says
// this number; test/vat-reverse-charge.test.js holds the two together.
const PROOF_TTL_DAYS = 30;

// Hard-coded, as lib/mollie.js hard-codes api.mollie.com: the caller never
// supplies a URL, so there is no SSRF surface here.
const VIES_HOST = 'ec.europa.eu';
const VIES_PATH = '/taxation_customs/vies/rest-api/check-vat-number';
// The checkout waits for this, so it is short. A slow VIES is an unavailable
// VIES: the buyer pays 21% and the checkout goes ahead.
const VIES_TIMEOUT_MS = 6000;

const HOME = 'NL';

// The member states, by the prefix of their VAT numbers. Greece is EL, not GR.
// XI (Northern Ireland) is left out on purpose: it is not a member state, and
// VIES knows XI numbers for trade in goods only.
const EU_PREFIXES = Object.freeze([
  'AT', 'BE', 'BG', 'CY', 'CZ', 'DE', 'DK', 'EE', 'EL', 'ES', 'FI', 'FR', 'HR', 'HU',
  'IE', 'IT', 'LT', 'LU', 'LV', 'MT', 'NL', 'PL', 'PT', 'RO', 'SE', 'SI', 'SK',
]);

const REVERSE_CHARGE = 'reverse_charge';

// "be 0123.456.789" and "BE0123456789" are the same number. Spaces, dots,
// dashes and slashes are how people write it, not part of it. GR is read as EL
// because that is the prefix a Greek number carries.
function parseVatId(raw) {
  const s = String(raw == null ? '' : raw).toUpperCase().replace(/[\s.\-_/]/g, '');
  const m = /^([A-Z]{2})([0-9A-Z+*]{2,12})$/.exec(s);
  if (!m) return null;
  const country = m[1] === 'GR' ? 'EL' : m[1];
  return { country, number: m[2], id: country + m[2] };
}

const isEuAbroad = (country) => country !== HOME && EU_PREFIXES.includes(country);

function isReverseCharge(terms) {
  return !!(terms && terms.treatment === REVERSE_CHARGE);
}

// ── VIES ─────────────────────────────────────────────────────────────────────
// POST check-vat-number, JSON in and out. The request function is injectable so
// the unit tests never open a socket; this is the one the relay uses. `port`
// and `transport` exist only so a test can point the real timeout at a local
// server that never answers.
function httpsJson({ host, path, body, timeoutMs, port = 443, transport = https }) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body || {});
    const req = transport.request({
      host, port, method: 'POST', path,
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: timeoutMs,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(Buffer.concat(chunks).toString('utf8') || 'null'); } catch { /* not JSON */ }
        resolve({ status: res.statusCode, body: json });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('vies_timeout')));
    req.write(payload);
    req.end();
  });
}

// One question to VIES. Never throws. Returns
//   { result: 'valid', requestDate, requestIdentifier, countryCode, name, address }
//   { result: 'invalid', detail }
//   { result: 'unavailable', detail }
// VIES answers HTTP 200 for a failure too, with
// { actionSucceed: false, errorWrappers: [{ error: 'MS_UNAVAILABLE' }] } in the
// body (checked against its test service on 2026-09-25), so the status code
// says little. Only `valid === true` is a valid number.
async function checkVies(query, deps = {}) {
  const request = typeof deps.request === 'function' ? deps.request : httpsJson;
  let res;
  try {
    res = await request({ host: VIES_HOST, path: VIES_PATH, body: query, timeoutMs: deps.timeoutMs || VIES_TIMEOUT_MS });
  } catch (e) {
    return { result: 'unavailable', detail: `request_failed:${e.message}` };
  }
  const b = res && res.body;
  if (!res || res.status !== 200 || !b || typeof b !== 'object') {
    return { result: 'unavailable', detail: `http_${res ? res.status : 'none'}` };
  }
  if (b.valid === true) {
    return {
      result: 'valid',
      requestDate: String(b.requestDate || ''),
      requestIdentifier: String(b.requestIdentifier || ''),
      countryCode: String(b.countryCode || ''),
      // '---' is how VIES says a member state does not disclose it.
      name: String(b.name || ''),
      address: String(b.address || ''),
    };
  }
  if (b.valid === false) return { result: 'invalid', detail: 'not_valid' };
  const code = (Array.isArray(b.errorWrappers) && b.errorWrappers[0] && b.errorWrappers[0].error) || 'no_answer';
  // VIES saying the input cannot be a number of that member state at all.
  if (code === 'INVALID_INPUT') return { result: 'invalid', detail: code };
  return { result: 'unavailable', detail: String(code) };
}

// ── names and countries ──────────────────────────────────────────────────────
// Legal forms, filler and the words half of all company names share carry no
// identity: "Acme BE SRL" and "ACME" are the same company, "Acme" and "Globex
// NV" are not, and neither are "Global Consulting" and "SMITH CONSULTING BV".
const NAME_NOISE = new Set([
  // legal forms
  'ab', 'ad', 'ag', 'aps', 'as', 'asbl', 'ay', 'bt', 'bv', 'bvba', 'co', 'cie', 'comm',
  'commv', 'corp', 'cv', 'cvba', 'dd', 'doo', 'ead', 'eeig', 'ek', 'eood', 'eurl', 'ewiv',
  'gie', 'gmbh', 'hb', 'inc', 'kb', 'kft', 'kg', 'kkt', 'limited', 'llc', 'ltd', 'mbh',
  'nv', 'nyrt', 'ohg', 'oy', 'oyj', 'ood', 'ou', 'plc', 'sa', 'sapa', 'sarl', 'sas',
  'sasu', 'sc', 'sca', 'scrl', 'scs', 'se', 'sia', 'sl', 'sll', 'slu', 'snc', 'sp',
  'spa', 'sprl', 'spzoo', 'sro', 'srl', 'ss', 'uab', 'ug', 'vof', 'vzw', 'zoo', 'zrt',
  // filler
  'and', 'de', 'der', 'die', 'en', 'et', 'het', 'la', 'le', 'les', 'of', 'the', 'und', 'van',
  // words many unrelated companies share
  'company', 'companies', 'consult', 'consultancy', 'consultants', 'consulting', 'digital',
  'enterprise', 'enterprises', 'group', 'groep', 'groupe', 'gruppe', 'grupo', 'handel',
  'holding', 'holdings', 'industries', 'international', 'management', 'partners',
  'service', 'services', 'software', 'solution', 'solutions', 'systems', 'technologies',
  'technology', 'trading',
]);

function plain(raw) {
  return String(raw || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
}

// Dots go first, so "B.V." and "S.R.L." read as the legal forms they are; a
// single letter left on its own is not a word.
function nameTokens(raw) {
  return plain(raw).replace(/\./g, '').replace(/[^a-z0-9]+/g, ' ').trim().split(' ')
    .filter((t) => t.length > 1 && !NAME_NOISE.has(t));
}

// Whether a name or an address holds at least one word that says something:
// not a legal form, not filler, not punctuation. ".", "-", "BV" and "NV" hold
// none, and a number with nothing but those next to it can be anyone's.
function hasWord(raw) {
  return nameTokens(raw).length > 0;
}

// Whether VIES names a clearly different company than the account does. Only
// when VIES discloses a name at all: several member states answer '---', and
// then there is nothing to compare, which is not a difference. A VIES name in
// a script this cannot read is not compared either. An account name without a
// word never matches a name VIES does give. One name containing the other, or
// one shared word of three letters or more, is the same company; nothing in
// common is a clear difference.
function namesClearlyDiffer(accountName, viesName) {
  const v = String(viesName || '').trim();
  if (!v || /^-+$/.test(v)) return false;
  const a = nameTokens(accountName);
  const b = nameTokens(v);
  if (!b.length) return false;
  if (!a.length) return true;
  const ca = a.join('');
  const cb = b.join('');
  if (ca.includes(cb) || cb.includes(ca)) return false;
  return !a.some((t) => t.length >= 3 && b.includes(t));
}

// The country an address names on its last line, or after the last comma of
// that line: "...\n1000 Brussels\nBelgium" and "..., Belgique" both say BE. An
// address that names no country this knows says nothing, and nothing is not a
// difference.
const COUNTRY_NAMES = (() => {
  const byCode = {
    AT: ['austria', 'oostenrijk', 'osterreich'], BE: ['belgium', 'belgie', 'belgique', 'belgien'],
    BG: ['bulgaria', 'bulgarije'], CY: ['cyprus'], CZ: ['czech republic', 'czechia', 'tsjechie', 'cesko', 'ceska republika'],
    DE: ['germany', 'duitsland', 'deutschland'], DK: ['denmark', 'denemarken', 'danmark'], EE: ['estonia', 'estland', 'eesti'],
    EL: ['greece', 'griekenland', 'hellas', 'ellada', 'gr'], ES: ['spain', 'spanje', 'espana'], FI: ['finland', 'suomi'],
    FR: ['france', 'frankrijk'], HR: ['croatia', 'kroatie', 'hrvatska'], HU: ['hungary', 'hongarije', 'magyarorszag'],
    IE: ['ireland', 'ierland', 'eire'], IT: ['italy', 'italie', 'italia'], LT: ['lithuania', 'litouwen', 'lietuva'],
    LU: ['luxembourg', 'luxemburg', 'letzebuerg'], LV: ['latvia', 'letland', 'latvija'], MT: ['malta'],
    NL: ['netherlands', 'the netherlands', 'nederland', 'holland', 'pays bas', 'niederlande'],
    PL: ['poland', 'polen', 'polska'], PT: ['portugal'], RO: ['romania', 'roemenie'], SE: ['sweden', 'zweden', 'sverige'],
    SI: ['slovenia', 'slovenie', 'slovenija'], SK: ['slovakia', 'slowakije', 'slovensko'],
    GB: ['united kingdom', 'uk', 'great britain', 'england', 'scotland', 'wales', 'verenigd koninkrijk'],
    CH: ['switzerland', 'zwitserland', 'schweiz', 'suisse', 'svizzera'], NO: ['norway', 'noorwegen', 'norge'],
    US: ['united states', 'united states of america', 'usa', 'verenigde staten'],
  };
  const map = {};
  for (const [code, names] of Object.entries(byCode)) {
    map[code.toLowerCase()] = code;
    for (const n of names) map[n] = code;
  }
  return Object.freeze(map);
})();

function countryInAddress(address) {
  const lines = String(address || '').split('\n').map((l) => l.trim()).filter(Boolean);
  if (!lines.length) return null;
  const last = lines[lines.length - 1];
  const tail = last.includes(',') ? last.slice(last.lastIndexOf(',') + 1) : last;
  const key = plain(tail).replace(/[^a-z]+/g, ' ').trim();
  return COUNTRY_NAMES[key] || null;
}

// ── the decision ─────────────────────────────────────────────────────────────
// Returns the terms of one sale:
//   { treatment: 'standard', reason, country?, level, detail? }
//   { treatment: 'reverse_charge', reason: 'vies_valid', vatId, country,
//     checkedAt, consultation, viesName, viesAddress, level }
// reason: no_vat_id, unreadable, dutch, outside_eu, no_seller_vat,
// incomplete_profile, country_mismatch, vies_invalid, vies_unavailable,
// vies_no_consultation, name_mismatch, vies_valid. level is how loud the caller
// should log it: 'warn' when a buyer who entered an EU number pays 21% after
// all, 'error' when VIES refused our own VAT number as the requester. detail
// never holds a VAT number or a name.
//
// deps.check(query) asks VIES; it defaults to checkVies and the tests pass a
// fake. It is only called for a number that could be reverse charged.
async function decide({ buyerVat, buyerCompany, buyerAddress, sellerVat, now }, deps = {}) {
  const check = typeof deps.check === 'function' ? deps.check : (q) => checkVies(q);
  const standard = (reason, country, level, detail) => Object.assign(
    { treatment: 'standard', reason, level: level || 'info' },
    country ? { country } : {},
    detail ? { detail } : {});

  if (!String(buyerVat || '').trim()) return standard('no_vat_id');
  const buyer = parseVatId(buyerVat);
  if (!buyer) return standard('unreadable');
  if (buyer.country === HOME) return standard('dutch', buyer.country);
  if (!isEuAbroad(buyer.country)) return standard('outside_eu', buyer.country);
  const seller = parseVatId(sellerVat);
  if (!seller) return standard('no_seller_vat', buyer.country, 'warn');

  // Before VIES is asked anything: without a name and an address there is
  // nothing to hold its answer against, and a number alone can be anyone's.
  // "." or "BV" is not a name, and "-" is not an address.
  const company = String(buyerCompany || '').trim();
  const address = String(buyerAddress || '').trim();
  if (!hasWord(company) || !hasWord(address)) return standard('incomplete_profile', buyer.country, 'warn');
  const stated = countryInAddress(address);
  if (stated && stated !== buyer.country) return standard('country_mismatch', buyer.country, 'warn', `address_${stated}`);

  let answer;
  try {
    answer = await check({
      countryCode: buyer.country,
      vatNumber: buyer.number,
      // Asking as ourselves is what makes VIES hand back a consultation number:
      // the proof, for the tax office, that this number was checked on this day.
      requesterMemberStateCode: seller.country,
      requesterNumber: seller.number,
    });
  } catch (e) {
    answer = { result: 'unavailable', detail: `check_failed:${e.message}` };
  }
  if (answer && answer.result === 'valid') {
    // Valid without the proof is not accepted in silence.
    if (!String(answer.requestIdentifier || '').trim()) return standard('vies_no_consultation', buyer.country, 'warn');
    const said = String(answer.countryCode || '').trim().toUpperCase();
    const viesCountry = said ? (said === 'GR' ? 'EL' : said) : buyer.country;
    if (viesCountry !== buyer.country) return standard('country_mismatch', buyer.country, 'warn', `vies_${viesCountry}`);
    if (namesClearlyDiffer(company, answer.name)) return standard('name_mismatch', buyer.country, 'warn');
    const at = now instanceof Date ? now : new Date();
    return {
      treatment: REVERSE_CHARGE, reason: 'vies_valid', level: 'info',
      vatId: buyer.id, country: buyer.country,
      checkedAt: answer.requestDate || at.toISOString(),
      consultation: String(answer.requestIdentifier).trim(),
      viesName: answer.name || '',
      viesAddress: answer.address || '',
    };
  }
  if (answer && answer.result === 'invalid') return standard('vies_invalid', buyer.country, 'warn', answer.detail);
  const detail = (answer && answer.detail) || 'no_answer';
  return standard('vies_unavailable', buyer.country, detail === 'INVALID_REQUESTER_INFO' ? 'error' : 'warn', detail);
}

// ── the proof ────────────────────────────────────────────────────────────────
// Written at the checkout, before the payment exists, under the consultation
// number the payment then carries in its metadata. Read back by the webhook for
// the invoice of the first payment and of every renewal. `redis` is anything
// with get and set, as lib/invoice.js takes.
const CONSULTATION_RE = /^[A-Za-z0-9_-]{1,64}$/;

function proofOf(terms, who = {}) {
  return {
    source: 'VIES',
    consultation: terms.consultation,
    checked_at: terms.checkedAt || '',
    vat_id: terms.vatId,
    country: terms.country,
    name: terms.viesName || '',
    address: terms.viesAddress || '',
    // What the account said at that moment: what VIES was held against.
    account_id: who.accountId || '',
    account_company: who.company || '',
    account_address: who.address || '',
  };
}

// At the checkout: with the thirty-day TTL.
async function saveProof(terms, redis, who) {
  if (!isReverseCharge(terms) || !CONSULTATION_RE.test(String(terms.consultation || ''))) return { ok: false, reason: 'no_consultation' };
  if (!redis) return { ok: false, reason: 'no_redis' };
  try { await redis.set(PROOF_KEY(terms.consultation), JSON.stringify(proofOf(terms, who)), { EX: PROOF_TTL_DAYS * 86400 }); }
  catch (e) { return { ok: false, reason: `store_failed:${e.message}` }; }
  return { ok: true };
}

// Once the invoice exists: the TTL goes, and the proof is kept with it.
// Idempotent, so every renewal may call it again.
async function keepProof(consultation, redis) {
  if (!redis || !CONSULTATION_RE.test(String(consultation || ''))) return { ok: false, reason: 'no_consultation' };
  try { await redis.persist(PROOF_KEY(consultation)); }
  catch (e) { return { ok: false, reason: `persist_failed:${e.message}` }; }
  return { ok: true };
}

async function loadProof(consultation, redis) {
  if (!redis || !CONSULTATION_RE.test(String(consultation || ''))) return null;
  try { return JSON.parse((await redis.get(PROOF_KEY(consultation))) || 'null'); } catch { return null; }
}

// ── the amount and the payment ───────────────────────────────────────────────
// What the buyer is charged. Catalog prices include 21% VAT; a reverse-charged
// sale is charged the net, split exactly the way the invoice splits it, so the
// amount paid and the invoice total are the same number.
function chargeAmount(order, terms) {
  if (!isReverseCharge(terms)) return order.amount;
  const split = invoice.splitVat(order.amount, invoice.CATALOG_VAT_RATE);
  return split ? invoice.money(split.net_cents) : null;
}

// The fields the checkout adds to the Mollie metadata. Nothing at all for a
// standard sale, so that payload stays exactly what it was.
function metadataOf(terms) {
  if (!isReverseCharge(terms)) return {};
  return {
    vat: REVERSE_CHARGE,
    vatId: terms.vatId,
    vatCheckedAt: terms.checkedAt || '',
    vatConsultation: terms.consultation || '',
  };
}

// The terms a payment was sold under, read back from its metadata. Anything
// that is not a complete reverse-charge marker reads as standard, which makes
// a net amount on such a payment fail the amount check loudly instead of
// being granted.
function termsFromMetadata(md) {
  const m = md || {};
  if (m.vat !== REVERSE_CHARGE) return { treatment: 'standard' };
  const buyer = parseVatId(m.vatId);
  if (!buyer || !isEuAbroad(buyer.country)) return { treatment: 'standard' };
  return {
    treatment: REVERSE_CHARGE,
    vatId: buyer.id,
    country: buyer.country,
    checkedAt: String(m.vatCheckedAt || ''),
    consultation: String(m.vatConsultation || ''),
  };
}

module.exports = {
  VIES_HOST, VIES_PATH, VIES_TIMEOUT_MS, EU_PREFIXES, REVERSE_CHARGE, PROOF_KEY, PROOF_TTL_DAYS,
  parseVatId, isReverseCharge, httpsJson, checkVies, decide,
  hasWord, namesClearlyDiffer, countryInAddress, saveProof, keepProof, loadProof,
  chargeAmount, metadataOf, termsFromMetadata,
};
