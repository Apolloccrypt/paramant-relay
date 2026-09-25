'use strict';
// The collecting half of billing. billing.js decides what a payment BOUGHT;
// this decides whether the buyer will be asked again, and when.
//
// Why it is a separate file: billing.js is pure w.r.t. its dependencies and
// runs on every webhook, including ones that grant nothing. Subscription
// management is a different question with different failure modes (a network
// call that may fail without costing the buyer his entitlement), so it lives
// next to it rather than inside it, and the relay calls it after a grant.
//
// The whole point is one date. A first payment already covers the first period,
// so a subscription created without an explicit startDate collects again
// immediately and charges twice for a month the buyer has paid for. Every
// function here exists to make that impossible to get wrong by accident.

const catalog = require('./billing-catalog');
const vat = require('./vat');
// Labels, dates and the bilingual mail shape, so the failed-collection mail
// reads like the reminders a customer already gets.
const planExpiry = require('./plan-expiry');

// One Mollie customer per Paramant account, and one subscription per SOLD LINE.
// Per line, because the ParaSign and ParaSend plans that predate Firm are
// bought separately and cancelled separately; a single subscription field would
// make cancelling one silently stop collecting for the other. Firm is one line
// that covers both products, so it gets its own field: cancelling Firm stops
// one collection, and it is the only collection there is.
const CUSTOMER_FIELD = 'mollie_customer_id';
const PRODUCT_SUBSCRIPTION_FIELD = Object.freeze({
  parasend: 'mollie_subscription_parasend',
  parasign: 'mollie_subscription_parasign',
  firm: 'mollie_subscription_firm',
});

function subscriptionFieldOf(product) {
  return PRODUCT_SUBSCRIPTION_FIELD[product] || null;
}

// Which payment created the subscription on file, per line. It is what tells a
// NEW purchase (whose period ends later, so the subscription on file would
// start one period too early) apart from the same payment arriving twice (which
// must leave the subscription alone).
function subscriptionPaymentFieldOf(product) {
  const field = subscriptionFieldOf(product);
  return field ? `${field}_payment` : null;
}

// Which Mollie customer the subscription on file hangs under, per line. Mollie
// knows a subscription only under its own customer: a cancel sent to another
// one answers 404, and that 404 used to count as "already gone" while the
// subscription went on collecting. The customer on the account is not good
// enough, because it changes: two checkouts at once make two customers.
function subscriptionCustomerFieldOf(product) {
  const field = subscriptionFieldOf(product);
  return field ? `${field}_customer` : null;
}

// Every field this layer writes onto an account record. users.json carries them,
// and keys-table.parseAccountFields reads them back at boot: without that a
// restart (every deploy) forgot which customer and which subscription an
// account has, so the cancel button found nothing while Mollie kept collecting.
const POINTER_FIELDS = Object.freeze([
  CUSTOMER_FIELD,
  ...Object.values(PRODUCT_SUBSCRIPTION_FIELD),
  ...Object.keys(PRODUCT_SUBSCRIPTION_FIELD).map(subscriptionPaymentFieldOf),
  ...Object.keys(PRODUCT_SUBSCRIPTION_FIELD).map(subscriptionCustomerFieldOf),
]);

// Stop one subscription at Mollie. A 404 means "already gone" only when the
// customer it was asked under is the subscription's own (customerKnown): under
// any other customer Mollie answers 404 for a subscription that is very much
// alive. Returns { ok, gone?, reason? } and never throws.
async function stopSubscription(m, mode, customerId, subscriptionId, customerKnown) {
  try {
    await m.cancelSubscription(mode, customerId, subscriptionId);
    return { ok: true };
  } catch (e) {
    if (e && e.status === 404) {
      return customerKnown
        ? { ok: true, gone: true }
        : { ok: false, reason: 'not_found_under_account_customer' };
    }
    return { ok: false, reason: (e && e.message) || 'cancel_failed' };
  }
}

// The subscription lines that pay for any of these entitlement products: the
// line of the product itself and every bundle that includes it. A Firm
// subscription renews ParaSign as much as a ParaSign one does.
function linesCovering(products) {
  const want = new Set(products || []);
  return Object.keys(PRODUCT_SUBSCRIPTION_FIELD).filter((line) => {
    const bundle = catalog.BUNDLES[line];
    const covers = bundle ? bundle.grants.map((g) => g.product) : [line];
    return covers.some((p) => want.has(p));
  });
}

// Mollie wants YYYY-MM-DD in its own timezone terms. The paid period ends at an
// instant; the subscription starts on that calendar day. Taking the UTC date is
// deliberate: paid_until is computed in UTC by billing.periodEnd, so any other
// reading would shift the first collection by a day.
//
// Two refusals, both of which produce a date that LOOKS fine and bills twice:
//   * null/undefined/empty. `new Date(null)` is not NaN, it is 1 January 1970,
//     so the naive check passes and the subscription starts 56 years ago.
//   * any date not in the future. Mollie collects immediately on a startDate
//     that has passed, which is the double charge this whole file exists to
//     prevent. A period that has already ended cannot be the start of the next
//     one, so this is always a bug upstream, never a case to paper over.
function startDateFor(paidUntil, now) {
  if (paidUntil === null || paidUntil === undefined || paidUntil === '') return null;
  const d = paidUntil instanceof Date ? paidUntil : new Date(paidUntil);
  if (Number.isNaN(d.getTime())) return null;
  const at = now instanceof Date ? now.getTime() : (typeof now === 'number' ? now : Date.now());
  if (d.getTime() <= at) return null;
  return d.toISOString().slice(0, 10);
}

// The payload for POST /v2/customers/:id/subscriptions.
//
// Returns { error } instead of throwing when the order or the date cannot carry
// a subscription, so a caller can refuse to create one rather than create a
// wrong one. There is no default startDate on purpose: a missing paid_until is
// an error, never "start today".
// vatTerms: the terms the first payment was sold under (lib/vat.js). A
// reverse-charged buyer is collected the net every period, and the marker rides
// along in the metadata so each renewal is checked and invoiced the same way.
function subscriptionPayload({ order, paidUntil, accountId, webhookUrl, mollieInterval, now, vatTerms }) {
  if (!order || order.error) return { error: 'bad_order' };
  const interval = mollieInterval(order.interval);
  if (!interval) return { error: `no_interval:${order.interval}` };
  const startDate = startDateFor(paidUntil, now);
  if (!startDate) return { error: 'no_start_date' };
  if (!accountId) return { error: 'no_account' };

  return {
    payload: {
      amount: { currency: order.currency, value: vat.chargeAmount(order, vatTerms) },
      interval,
      startDate,
      description: `Paramant ${catalog.orderLabel(order)} (${order.interval})`,
      webhookUrl,
      // The metadata a renewal webhook is attributed by. A subscription payment
      // carries the subscription's metadata, not the first payment's, so
      // leaving this out would make every renewal land as 'missing_metadata'
      // and grant nothing: the customer would be charged and get nothing.
      metadata: Object.assign({
        accountId,
        product: order.product,
        plan: order.plan,
        interval: order.interval,
      }, vat.metadataOf(vatTerms)),
    },
  };
}

// Is this payment the one that creates the mandate? Mollie marks it, but an
// older payment made before this code existed has no sequenceType at all, and
// those must not be treated as recurring collections.
function isFirstPayment(payment) {
  const seq = payment && payment.sequenceType;
  return seq === 'first' || seq === undefined || seq === null;
}

function isRecurringPayment(payment) {
  return !!(payment && payment.sequenceType === 'recurring');
}

// A collection the subscription tried and did not get. The webhook grants
// nothing for it, which is right, but it used to answer 'ignored' and stop: the
// customer heard nothing until his plan had already fallen back, and the
// reminder he then got promised that nothing is ever charged automatically.
// Not 'canceled': that is what a pending collection becomes when its
// subscription is stopped or replaced, and then nothing went wrong.
const FAILED_COLLECTION_STATUSES = Object.freeze(['failed', 'expired']);

function isFailedCollection(payment) {
  return isRecurringPayment(payment) && FAILED_COLLECTION_STATUSES.includes(payment.status);
}

// The line whose subscription on file made this collection, or null. A
// collection of a subscription that has since been replaced or stopped belongs
// to no line any more, and its customer has a subscription that runs fine.
function currentLineOf(rec, subscriptionId) {
  if (!rec || !subscriptionId) return null;
  return Object.keys(PRODUCT_SUBSCRIPTION_FIELD)
    .find((line) => rec[subscriptionFieldOf(line)] === subscriptionId) || null;
}

// The switch on this whole file. deps.recurring comes from mollie.billingStance()
// and is only true when BILLING_MODE was set by hand. When it is false the relay
// bills exactly as it did on 2026-08-08: a one-off payment, no customer, no
// sequenceType, no subscription. Production has run with BILLING_MODE empty and
// a live key since billing exists, so an inferred 'live' must never be enough
// to start opening mandates against a real account.
function recurringAllowed(deps) {
  return !!(deps && deps.recurring === true);
}

// Before a checkout: the Mollie customer the mandate will hang on. A payment
// without a customerId cannot become a mandate, so this is the first of the
// three things a subscription needs, and the one that decides whether the
// checkout is recurring at all.
//
// deps: { recurring, mode, getAccount(accountId), saveCustomer(accountId, id),
//         mollie: { getCustomer, createCustomer } }
// Returns { customerId: string|null, result, reason? } and NEVER throws: the
// buyer's payment matters more than tidiness in our own records, so a failed
// lookup or create falls through to a one-off checkout and the caller logs it.
async function ensureCustomer(accountId, deps) {
  const d = deps || {};
  const m = d.mollie || {};
  if (!recurringAllowed(d)) return { customerId: null, result: 'skipped', reason: 'recurring_disabled' };
  if (!accountId) return { customerId: null, result: 'skipped', reason: 'no_account' };
  try {
    const rec = typeof d.getAccount === 'function' ? await d.getAccount(accountId) : null;
    // Reuse the stored customer when Mollie still knows it. Only a customer
    // Mollie says is GONE (404, 410) is replaced. Any other failure (a
    // time-out, a 5xx, a 429) says nothing about the customer, and replacing it
    // then used to swap the customer under a running subscription: the next
    // cancel or replacement went to the new customer, got a 404, and the old
    // subscription kept collecting. So a lookup that fails for another reason
    // keeps the stored customer, unverified.
    const stored = rec && rec[CUSTOMER_FIELD];
    if (stored) {
      let c = null;
      let gone = false;
      try { c = await m.getCustomer(d.mode, stored); }
      catch (e) {
        gone = !!(e && (e.status === 404 || e.status === 410));
        if (!gone) {
          return {
            customerId: stored, result: 'reused_unverified', level: 'warn',
            reason: `customer_check_failed:${(e && e.message) || 'error'}`, status: e && e.status,
          };
        }
      }
      if (c && c.id) return { customerId: c.id, result: 'reused' };
      if (!gone) return { customerId: stored, result: 'reused_unverified', level: 'warn', reason: 'customer_check_empty' };
    }
    const created = await m.createCustomer(d.mode, {
      name: (rec && rec.label) || undefined,
      email: (rec && rec.email) || undefined,
      metadata: { accountId },
    });
    if (!created || !created.id) return { customerId: null, result: 'failed', level: 'error', reason: 'no_customer_id' };
    if (typeof d.saveCustomer === 'function') await d.saveCustomer(accountId, created.id);
    return { customerId: created.id, result: 'created' };
  } catch (e) {
    // No customer means no mandate means no renewal. The sale still goes through
    // as a one-off rather than failing in the buyer's face, but this is an
    // alert: money will come in once and never again.
    return { customerId: null, result: 'failed', level: 'error', reason: e.message, status: e.status };
  }
}

// After a grant: make sure the buyer will be asked again when the period ends.
//
// deps: {
//   getAccount(accountId) -> record | null
//   saveSubscription(accountId, product, subscriptionId, meta?) -> void   (async ok)
//     meta on a create: { paymentId, amount, currency, interval, startDate };
//     none when a pointer is cleared
//   mollie: { validMandates, createSubscription, cancelSubscription, mollieInterval }
//   mode, webhookUrl, recurring (from mollie.billingStance(); false = 08-08 behaviour)
// }
// Returns { result, reason, subscriptionId? } and NEVER throws: a failure here
// must not undo an entitlement the buyer has already paid for. The caller logs
// the reason; 'error' level cases are the ones where money will not come in.
// result 'replaced' is a second purchase: the old subscription was cancelled and
// a new one starts where the period now ends.
async function ensureSubscription(payment, grant, deps) {
  const d = deps || {};
  const m = d.mollie || {};
  const accountId = grant && grant.account;
  const product = grant && grant.product;
  if (!accountId || !product) return { result: 'skipped', reason: 'no_grant' };
  // Not a failure and not logged as one: the grant stands, and nothing
  // recurring was promised in this stance.
  if (!recurringAllowed(d)) return { result: 'skipped', reason: 'recurring_disabled' };

  // A renewal collected BY the subscription must never create a second one.
  if (isRecurringPayment(payment)) return { result: 'skipped', reason: 'recurring_collection' };
  if (!isFirstPayment(payment)) return { result: 'skipped', reason: `sequence_${payment && payment.sequenceType}` };

  const field = subscriptionFieldOf(product);
  if (!field) return { result: 'skipped', reason: 'unknown_product' };

  const rec = typeof d.getAccount === 'function' ? await d.getAccount(accountId) : null;
  const existing = (rec && rec[field]) || null;
  if (existing) {
    // Left alone when this very payment made it (a repeat), and when nothing
    // says which payment did (a subscription from before that was recorded).
    // Only a DIFFERENT purchase may replace what is on file.
    const madeBy = rec[subscriptionPaymentFieldOf(product)] || null;
    if (!madeBy || madeBy === (payment && payment.id)) {
      return { result: 'skipped', reason: 'already_subscribed', subscriptionId: existing };
    }
  }

  // The customer id can come from the payment itself (the checkout put it
  // there) or from the account. The payment wins: it is what Mollie actually
  // billed, so a stale account field can never point the subscription at the
  // wrong customer.
  const customerId = (payment && payment.customerId) || (rec && rec[CUSTOMER_FIELD]) || null;
  if (!customerId) {
    // Paid, granted, but nothing will ever be collected again. This is the case
    // that quietly turns a subscription business back into a one-off shop.
    return { result: 'failed', level: 'error', reason: 'no_customer_on_payment' };
  }

  // No mandate means no authority to collect. Creating the subscription anyway
  // gives Mollie a 422 and leaves a broken record behind.
  let mandates = [];
  try { mandates = await m.validMandates(d.mode, customerId); }
  catch (e) { return { result: 'failed', level: 'error', reason: `mandates_failed:${e.message}` }; }
  if (!mandates.length) return { result: 'failed', level: 'error', reason: 'no_valid_mandate' };

  const order = catalog.resolveOrder({
    product,
    plan: (payment && payment.metadata && payment.metadata.plan),
    interval: (payment && payment.metadata && payment.metadata.interval),
  });
  const built = subscriptionPayload({
    order,
    paidUntil: grant.paidUntil,
    accountId,
    webhookUrl: d.webhookUrl,
    mollieInterval: m.mollieInterval,
    now: d.now,
    vatTerms: vat.termsFromMetadata(payment && payment.metadata),
  });
  if (built.error) return { result: 'failed', level: 'error', reason: `payload:${built.error}` };

  // A second purchase. The subscription on file starts on the day the OLD
  // period ended, and this payment has just moved that end, so left alone it
  // collects a period the buyer has already paid for. It may also be the wrong
  // interval now (a month, then a year). Cancel it first and create the new one
  // after: if the create then fails, nothing is collected twice, and the error
  // level says this account will not renew by itself.
  let replaced = null;
  if (existing) {
    // Under ITS customer, which is not necessarily the one on the account or on
    // this payment. A subscription from before its customer was recorded is
    // asked for under the account's customer, and a 404 there proves nothing.
    const ownCustomer = rec[subscriptionCustomerFieldOf(product)] || null;
    const stop = await stopSubscription(m, d.mode, ownCustomer || rec[CUSTOMER_FIELD] || customerId, existing, !!ownCustomer);
    if (!stop.ok) return { result: 'failed', level: 'error', reason: `replace_cancel_failed:${stop.reason}`, subscriptionId: existing };
    try { if (typeof d.saveSubscription === 'function') await d.saveSubscription(accountId, product, null); }
    catch (e) { return { result: 'failed', level: 'error', reason: `replace_save_failed:${e.message}` }; }
    replaced = existing;
  }

  // One subscription per payment, also at Mollie: a create that Mollie saw but
  // whose answer we lost, asked again within Mollie's idempotency window (one
  // hour), gets the subscription the first attempt made. It does not cover a
  // crash between the grant and this call: the repeat webhook then reads
  // 'already_processed' and never gets here.
  const idempotencyKey = payment && payment.id ? `sub-${payment.id}` : undefined;
  let sub;
  try { sub = await m.createSubscription(d.mode, customerId, built.payload, { idempotencyKey }); }
  catch (e) { return { result: 'failed', level: 'error', reason: `create_failed:${e.message}`, replaced: replaced || undefined }; }
  if (!sub || !sub.id) return { result: 'failed', level: 'error', reason: 'no_subscription_id' };

  const meta = {
    paymentId: (payment && payment.id) || null,
    // The customer Mollie filed it under, from its own answer when it gives one.
    customerId: sub.customerId || customerId,
    amount: built.payload.amount.value,
    currency: built.payload.amount.currency,
    interval: order.interval,
    startDate: built.payload.startDate,
  };
  try { if (typeof d.saveSubscription === 'function') await d.saveSubscription(accountId, product, sub.id, meta); }
  catch (e) { return { result: 'created_unsaved', level: 'error', reason: `save_failed:${e.message}`, subscriptionId: sub.id }; }

  return {
    result: replaced ? 'replaced' : 'created', level: 'info', subscriptionId: sub.id,
    startDate: built.payload.startDate, replaced: replaced || undefined,
  };
}

// Cancelling stops the NEXT collection. It must not touch paid_until: the buyer
// paid for the period he is in and keeps it to the end. Anything else would be
// charging for time and then taking it back, which no EU consumer rule allows
// and no customer would forgive.
async function cancelForProduct(accountId, product, deps) {
  const d = deps || {};
  const m = d.mollie || {};
  const field = subscriptionFieldOf(product);
  if (!field) return { result: 'refused', reason: 'unknown_product' };

  const rec = typeof d.getAccount === 'function' ? await d.getAccount(accountId) : null;
  if (!rec) return { result: 'refused', reason: 'unknown_account' };
  const subId = rec[field];
  // The subscription's own customer first. The account's customer is only the
  // fallback for a subscription from before that was recorded, and then a 404
  // is not proof that it is gone (stopSubscription).
  const ownCustomer = rec[subscriptionCustomerFieldOf(product)] || null;
  const customerId = ownCustomer || rec[CUSTOMER_FIELD];
  if (!subId) return { result: 'noop', reason: 'no_subscription' };
  if (!customerId) return { result: 'refused', level: 'error', reason: 'no_customer' };

  const stop = await stopSubscription(m, d.mode, customerId, subId, !!ownCustomer);
  if (!stop.ok) return { result: 'failed', level: 'error', reason: `cancel_failed:${stop.reason}` };

  // Clear the pointer only after Mollie confirmed, so a failed cancel does not
  // leave the account thinking it has nothing to cancel.
  try { if (typeof d.saveSubscription === 'function') await d.saveSubscription(accountId, product, null); }
  catch (e) { return { result: 'cancelled_unsaved', level: 'error', reason: `save_failed:${e.message}` }; }

  return { result: 'cancelled', level: 'info', reason: stop.gone ? 'subscription_already_gone' : 'subscription_cancelled' };
}

// Does the subscription on this line belong to this payment? Yes when the
// payment is one of its collections, or the purchase that created it. A refund
// of an OLD purchase whose subscription was since replaced must not stop the
// subscription a later purchase made. When the record does not say which
// payment made the subscription (one from before that was recorded), the
// answer is yes: stopping a collection is recoverable, charging someone who
// took his money back is not.
function belongsTo(rec, line, payment) {
  const subId = rec && rec[subscriptionFieldOf(line)];
  if (!subId || !payment) return false;
  if (payment.subscriptionId) return payment.subscriptionId === subId;
  const madeBy = rec[subscriptionPaymentFieldOf(line)] || null;
  return !madeBy || madeBy === payment.id;
}

// After a full refund or a chargeback: stop collecting for what was just taken
// back. The revoke floors every product of the order, but it used to leave the
// subscription running, so the next collection charged the customer who had
// asked for his money back, and handed him the plan again. Every line that pays
// for a revoked product is looked at (a ParaSign chargeback can concern a Firm
// subscription), and the subscription on it is stopped when it belongs to the
// reversed payment (belongsTo).
//
// deps: as cancelForProduct. Returns [{ line, result, reason, level? }], one per
// line; 'noop' for a line without a subscription, which is every line when
// BILLING_MODE is empty, and then Mollie is never called; 'kept' for a
// subscription of another payment.
async function cancelOnRevoke(payment, outcome, deps) {
  const d = deps || {};
  if (!outcome || outcome.result !== 'revoked' || !outcome.account) return [];
  const products = (outcome.grants || []).map((g) => g && g.product).filter(Boolean);
  const rec = typeof d.getAccount === 'function' ? await d.getAccount(outcome.account) : null;
  const out = [];
  for (const line of linesCovering(products)) {
    if (rec && rec[subscriptionFieldOf(line)] && !belongsTo(rec, line, payment)) {
      out.push({ line, result: 'kept', level: 'info', reason: 'belongs_to_another_payment' });
      continue;
    }
    const r = await cancelForProduct(outcome.account, line, d);
    out.push(Object.assign({ line }, r));
  }
  return out;
}

// ── The mail for a collection that did not go through ────────────────────────
// Amounts the way the invoice mails write them: currency, then the value.
function moneyOf(amount) {
  const a = amount || {};
  return `${a.currency || 'EUR'} ${a.value || ''}`.trim();
}

// order: catalog.resolveOrder of the payment's metadata. paidUntil: the end of
// the period already paid, which the failed collection was meant to extend.
// amount: what Mollie tried to collect. Returns null when the order is unknown.
//
// Mollie tries a failed subscription payment again by itself: "up to 5 times",
// "once a day, depending on the failure reason", and after the last failed try
// it cancels the subscription (docs.mollie.com, recurring payments). So the mail
// does not send the customer to the checkout, where paying as well can mean
// paying twice. It says what happened, that Mollie usually tries again, and
// what he can check.
function failedCollectionMail({ order, paidUntil, now, siteUrl, amount }) {
  if (!order || order.error) return null;
  const plan = planExpiry.bundleLabel(order.bundle) || planExpiry.planLabel(order.product, order.tier);
  const planNl = planExpiry.bundleLabelNl(order.bundle) || planExpiry.planLabelNl(order.product, order.tier);
  const account = `${String(siteUrl || planExpiry.DEFAULT_SITE_URL).replace(/\/+$/, '')}/account`;
  const at = paidUntil ? Date.parse(paidUntil) : NaN;
  const nowMs = now instanceof Date ? now.getTime() : (typeof now === 'number' ? now : Date.now());
  const running = Number.isFinite(at) && at > nowMs;
  const money = moneyOf(amount && amount.value ? amount : { value: order.amount, currency: order.currency });

  const subjectNl = `De automatische betaling voor uw ${planNl} is niet gelukt`;
  const subjectEn = `The automatic payment for your ${plan} did not go through`;
  const textNl = [
    `De automatische betaling van ${money} voor uw ${planNl} is niet gelukt.`,
    '',
    'In de meeste gevallen probeert Mollie de betaling automatisch opnieuw, tot vijf keer, een keer per dag. U hoeft dan zelf niets te betalen. Kijk wel of uw rekening of kaart nog geldig is.',
    '',
    running
      ? `Uw plan loopt tot ${planExpiry.formatDateNl(at)}.`
      : 'Zodra de betaling binnen is, loopt uw plan weer door.',
    '',
    `Uw plan staat op ${account}`,
    '',
    'Paramant',
  ].join('\n');
  const textEn = [
    `The automatic payment of ${money} for your ${plan} did not go through.`,
    '',
    'In most cases Mollie tries the payment again automatically, up to five times, once a day. You then do not need to pay yourself. Do check that your bank account or card is still valid.',
    '',
    running
      ? `Your plan runs until ${planExpiry.formatDate(at)}.`
      : 'Your plan carries on as soon as the payment comes in.',
    '',
    `Your plan is at ${account}`,
    '',
    'Paramant',
  ].join('\n');
  return {
    subject: planExpiry.bilingualSubject(subjectNl, subjectEn),
    text: planExpiry.bilingualText(textNl, textEn),
    html: planExpiry.htmlBody([[subjectNl, textNl], [subjectEn, textEn]], account),
  };
}

// ── Does this line renew by itself? The answer the reminders need ─────────────
// The pointers above live in users.json on the container that took the payment.
// The paid-term reminder (plan-expiry) runs on whichever container holds its
// lock, and it used to promise "nothing is charged automatically" to a customer
// whose subscription was about to collect. So every pointer change is mirrored
// into one shared hash, member "<accountId>|<line>", and the reminder asks it.
const RENEWALS_HASH = 'paramant:billing:renewals';

function renewalMember(accountId, line) {
  return `${accountId}|${line}`;
}

// info: { subscriptionId, amount, currency, interval, startDate }. Unknown
// fields are stored as null; the reminder then leaves the amount out rather
// than guess one.
async function recordRenewal(redis, accountId, line, info) {
  if (!redis || !accountId || !subscriptionFieldOf(line)) return false;
  const i = info || {};
  await redis.hSet(RENEWALS_HASH, renewalMember(accountId, line), JSON.stringify({
    subscription_id: i.subscriptionId || null,
    amount: i.amount || null,
    currency: i.currency || null,
    interval: i.interval || null,
    start_date: i.startDate || null,
  }));
  return true;
}

async function forgetRenewal(redis, accountId, line) {
  if (!redis || !accountId || !subscriptionFieldOf(line)) return false;
  await redis.hDel(RENEWALS_HASH, renewalMember(accountId, line));
  return true;
}

// The renewal that covers this product for this account, or null. The line of
// the bundle the term was bought as comes first, then every line that covers
// the product. An entry that cannot be read still counts as a renewal: when in
// doubt the reminder must not promise that nothing will be charged.
async function renewalFor(redis, accountId, product, bundle) {
  if (!redis || !accountId) return null;
  const lines = [];
  if (bundle && subscriptionFieldOf(bundle)) lines.push(bundle);
  for (const line of linesCovering([product])) if (!lines.includes(line)) lines.push(line);
  for (const line of lines) {
    const raw = await redis.hGet(RENEWALS_HASH, renewalMember(accountId, line));
    if (!raw) continue;
    let parsed = null;
    try { parsed = JSON.parse(raw); } catch { parsed = null; }
    return Object.assign({ line }, parsed && typeof parsed === 'object' ? parsed : {});
  }
  return null;
}

// Once per container at boot, from the pointers it holds. Adds what the hash
// does not know (after a redis flush, or for a subscription made before this
// hash existed) and never overwrites or removes: a container that holds no
// pointers must not be able to erase what the billing container wrote.
// entries: iterable of { accountId, line, subscriptionId }.
async function seedRenewals(redis, entries) {
  let seeded = 0;
  if (!redis) return { seeded };
  for (const e of entries || []) {
    if (!e || !e.accountId || !e.subscriptionId || !subscriptionFieldOf(e.line)) continue;
    const added = await redis.hSetNX(RENEWALS_HASH, renewalMember(e.accountId, e.line), JSON.stringify({
      subscription_id: e.subscriptionId, amount: null, currency: null, interval: null, start_date: null,
    }));
    if (added === true || added === 1) seeded++;
  }
  return { seeded };
}

module.exports = {
  CUSTOMER_FIELD, PRODUCT_SUBSCRIPTION_FIELD, POINTER_FIELDS, subscriptionFieldOf, subscriptionPaymentFieldOf,
  subscriptionCustomerFieldOf, linesCovering,
  startDateFor, subscriptionPayload, isFirstPayment, isRecurringPayment,
  FAILED_COLLECTION_STATUSES, isFailedCollection, currentLineOf, failedCollectionMail,
  recurringAllowed, ensureCustomer, ensureSubscription, cancelForProduct, belongsTo, cancelOnRevoke,
  RENEWALS_HASH, recordRenewal, forgetRenewal, renewalFor, seedRenewals,
};
