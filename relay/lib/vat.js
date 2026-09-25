'use strict';
// Which VAT a sale carries: 21% Dutch VAT, or none because it is reverse
// charged to a business in another EU member state.
//
// THE RULE. A service a Dutch business supplies to a business established in
// another member state is taxed where that customer is, and the customer
// accounts for the VAT (Directive 2006/112/EC art. 44 and 196). The invoice
// then carries no VAT, says "Btw verlegd" / "VAT reverse charged", and states
// the VAT identification numbers of both parties (art. 226; Wet OB art. 35a).
// Everyone else pays the 21% the catalog prices include: a Dutch business, a
// private buyer, and a business outside the EU.
//
// REVERSE CHARGE ONLY WHEN ALL OF THESE HOLD, and 21% in every other case:
//   - the seller's own VAT id is configured (BILLING_SELLER_VAT). Without it
//     the document is a payment receipt, which cannot carry the mentions above;
//   - the buyer's VAT id starts with the code of a member state other than the
//     Netherlands. That code is the member state that issued the number, which
//     is what "the buyer's country" means for this rule, and it is the country
//     VIES is asked about;
//   - VIES answers that the number is valid, at the moment of the checkout.
// VIES unreachable, slow, or answering anything but valid: 21%, and a log line.
// That is the safe side for the seller. VAT charged that turns out not to be
// due is corrected with a credit note; VAT not charged that was due is owed by
// the seller.
//
// WHERE THE DECISION LIVES AFTERWARDS. On the payment itself: the checkout puts
// the terms in the Mollie metadata, and Mollie hands them back on every fetch.
// The webhook's amount check, the invoice and every renewal of the
// subscription read them from there, so all of them agree with what the buyer
// was actually charged, without a second VIES call and without a store that
// could be flushed. The metadata is written by this server with its own API
// key; a buyer cannot set it.

const https = require('https');
const invoice = require('./invoice');

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
// the unit tests never open a socket; this is the one the relay uses.
function httpsJson({ host, path, body, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body || {});
    const req = https.request({
      host, port: 443, method: 'POST', path,
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
//   { result: 'valid', requestDate, requestIdentifier }
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
    return { result: 'valid', requestDate: String(b.requestDate || ''), requestIdentifier: String(b.requestIdentifier || '') };
  }
  if (b.valid === false) return { result: 'invalid', detail: 'not_valid' };
  const code = (Array.isArray(b.errorWrappers) && b.errorWrappers[0] && b.errorWrappers[0].error) || 'no_answer';
  // VIES saying the input cannot be a number of that member state at all.
  if (code === 'INVALID_INPUT') return { result: 'invalid', detail: code };
  return { result: 'unavailable', detail: String(code) };
}

// ── the decision ─────────────────────────────────────────────────────────────
// Returns the terms of one sale:
//   { treatment: 'standard', reason, country?, level, detail? }
//   { treatment: 'reverse_charge', reason: 'vies_valid', vatId, country,
//     checkedAt, consultation, level }
// reason: no_vat_id, unreadable, dutch, outside_eu, no_seller_vat,
// vies_invalid, vies_unavailable, vies_valid. level is how loud the caller
// should log it: 'warn' when a buyer who entered an EU number pays 21% after
// all, 'error' when VIES refused our own VAT number as the requester.
//
// deps.check(query) asks VIES; it defaults to checkVies and the tests pass a
// fake. It is only called for a number that could be reverse charged.
async function decide({ buyerVat, sellerVat, now }, deps = {}) {
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
    const at = now instanceof Date ? now : new Date();
    return {
      treatment: REVERSE_CHARGE, reason: 'vies_valid', level: 'info',
      vatId: buyer.id, country: buyer.country,
      checkedAt: answer.requestDate || at.toISOString(),
      consultation: answer.requestIdentifier || '',
    };
  }
  if (answer && answer.result === 'invalid') return standard('vies_invalid', buyer.country, 'warn', answer.detail);
  const detail = (answer && answer.detail) || 'no_answer';
  return standard('vies_unavailable', buyer.country, detail === 'INVALID_REQUESTER_INFO' ? 'error' : 'warn', detail);
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
  VIES_HOST, VIES_PATH, VIES_TIMEOUT_MS, EU_PREFIXES, REVERSE_CHARGE,
  parseVatId, isReverseCharge, checkVies, decide,
  chargeAmount, metadataOf, termsFromMetadata,
};
