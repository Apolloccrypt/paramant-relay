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

// One Mollie customer per Paramant account, and one subscription per PRODUCT.
// Per product, because ParaSend Pro and ParaSign Pro are bought separately and
// cancelled separately; a single subscription field would make cancelling one
// silently stop collecting for the other.
const CUSTOMER_FIELD = 'mollie_customer_id';
const PRODUCT_SUBSCRIPTION_FIELD = Object.freeze({
  parasend: 'mollie_subscription_parasend',
  parasign: 'mollie_subscription_parasign',
});

function subscriptionFieldOf(product) {
  return PRODUCT_SUBSCRIPTION_FIELD[product] || null;
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
function subscriptionPayload({ order, paidUntil, accountId, webhookUrl, mollieInterval, now }) {
  if (!order || order.error) return { error: 'bad_order' };
  const interval = mollieInterval(order.interval);
  if (!interval) return { error: `no_interval:${order.interval}` };
  const startDate = startDateFor(paidUntil, now);
  if (!startDate) return { error: 'no_start_date' };
  if (!accountId) return { error: 'no_account' };

  return {
    payload: {
      amount: { currency: order.currency, value: order.amount },
      interval,
      startDate,
      description: `Paramant ${order.product} ${order.plan} (${order.interval})`,
      webhookUrl,
      // The metadata a renewal webhook is attributed by. A subscription payment
      // carries the subscription's metadata, not the first payment's, so
      // leaving this out would make every renewal land as 'missing_metadata'
      // and grant nothing: the customer would be charged and get nothing.
      metadata: {
        accountId,
        product: order.product,
        plan: order.plan,
        interval: order.interval,
      },
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
    // Reuse the stored customer when Mollie still knows it. A stale or foreign
    // id must not break a checkout, so a failed lookup creates a new one.
    const stored = rec && rec[CUSTOMER_FIELD];
    if (stored) {
      try { const c = await m.getCustomer(d.mode, stored); if (c && c.id) return { customerId: c.id, result: 'reused' }; }
      catch { /* fall through to create */ }
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
//   saveSubscription(accountId, product, subscriptionId) -> void   (async ok)
//   mollie: { validMandates, createSubscription, mollieInterval }
//   mode, webhookUrl, recurring (from mollie.billingStance(); false = 08-08 behaviour)
// }
// Returns { result, reason, subscriptionId? } and NEVER throws: a failure here
// must not undo an entitlement the buyer has already paid for. The caller logs
// the reason; 'error' level cases are the ones where money will not come in.
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
  if (rec && rec[field]) return { result: 'skipped', reason: 'already_subscribed', subscriptionId: rec[field] };

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
  });
  if (built.error) return { result: 'failed', level: 'error', reason: `payload:${built.error}` };

  let sub;
  try { sub = await m.createSubscription(d.mode, customerId, built.payload); }
  catch (e) { return { result: 'failed', level: 'error', reason: `create_failed:${e.message}` }; }
  if (!sub || !sub.id) return { result: 'failed', level: 'error', reason: 'no_subscription_id' };

  try { if (typeof d.saveSubscription === 'function') await d.saveSubscription(accountId, product, sub.id); }
  catch (e) { return { result: 'created_unsaved', level: 'error', reason: `save_failed:${e.message}`, subscriptionId: sub.id }; }

  return { result: 'created', level: 'info', subscriptionId: sub.id, startDate: built.payload.startDate };
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
  const customerId = rec[CUSTOMER_FIELD];
  if (!subId) return { result: 'noop', reason: 'no_subscription' };
  if (!customerId) return { result: 'refused', level: 'error', reason: 'no_customer' };

  try { await m.cancelSubscription(d.mode, customerId, subId); }
  catch (e) { return { result: 'failed', level: 'error', reason: `cancel_failed:${e.message}` }; }

  // Clear the pointer only after Mollie confirmed, so a failed cancel does not
  // leave the account thinking it has nothing to cancel.
  try { if (typeof d.saveSubscription === 'function') await d.saveSubscription(accountId, product, null); }
  catch (e) { return { result: 'cancelled_unsaved', level: 'error', reason: `save_failed:${e.message}` }; }

  return { result: 'cancelled', level: 'info', reason: 'subscription_cancelled' };
}

module.exports = {
  CUSTOMER_FIELD, PRODUCT_SUBSCRIPTION_FIELD, subscriptionFieldOf,
  startDateFor, subscriptionPayload, isFirstPayment, isRecurringPayment,
  recurringAllowed, ensureCustomer, ensureSubscription, cancelForProduct,
};
