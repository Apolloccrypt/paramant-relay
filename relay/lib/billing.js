'use strict';
// Billing decision + effect for a Mollie payment. Pure w.r.t. its dependencies:
// the relay wires the real effects, tests wire fakes. This is where Mick's four
// hard webhook rules live, in one place:
//   1) Never trust the webhook body. The CALLER already re-fetched the payment
//      from Mollie (GET /v2/payments/:id); processPayment only ever reads that
//      fetched object.
//   2) Check the amount actually paid against the catalog price for the plan in
//      the payment metadata BEFORE granting.
//   3) Idempotent. A payment id that was already handled changes nothing
//      (deps.isProcessed / deps.markProcessed), and setProductPlan is itself
//      idempotent, so a double webhook is safe even without the marker.
//   4) Only status 'paid' grants. failed/expired/canceled do nothing; chargeback
//      revokes to the product floor.

const catalog = require('./billing-catalog');

// deps: {
//   setProductPlan(accountId, product, tier) -> { ok, ... }  (sync or async)
//   isProcessed(paymentId) -> boolean                        (async; optional)
//   markProcessed(paymentId, value) -> void                  (async; optional)
// }
// Returns { result, level, account, product, tier, reason }.
//   result: 'granted' | 'revoked' | 'refused' | 'ignored'
//   level:  log level; 'error' marks the "paid but got nothing" alert cases.
async function processPayment(payment, deps) {
  const d = deps || {};
  const status = payment && payment.status;
  const md = (payment && payment.metadata) || {};
  const { accountId, product, plan, interval } = md;

  // Rule 1 corollary: a payment we cannot attribute (no usable metadata) must
  // never grant anything. Flag it -- someone may have paid.
  if (!accountId || !product || !plan || !interval) {
    return { result: 'refused', level: 'error', reason: 'missing_metadata' };
  }

  const order = catalog.resolveOrder({ product, plan, interval });
  if (order.error) {
    return { result: 'refused', level: 'error', account: accountId, product, reason: `unknown_plan:${order.error}` };
  }

  // Rule 3: idempotency. If we already recorded a terminal outcome, no-op.
  if (typeof d.isProcessed === 'function') {
    let done = false;
    try { done = await d.isProcessed(payment.id); } catch { done = false; }
    if (done) return { result: 'ignored', level: 'info', account: accountId, product, reason: 'already_processed' };
  }

  if (status === 'paid') {
    // Rule 2: the amount + currency actually paid must match the catalog.
    const paid = payment.amount && payment.amount.value;
    const cur = payment.amount && payment.amount.currency;
    if (cur !== order.currency || !catalog.amountsEqual(paid, order.amount)) {
      return {
        result: 'refused', level: 'error', account: accountId, product,
        reason: `amount_mismatch paid=${paid}/${cur} expected=${order.amount}/${order.currency}`,
      };
    }
    // Grant ONLY this product's tier. setProductPlan never touches the other
    // product (rule: product A must not move product B).
    let set;
    try { set = await d.setProductPlan(accountId, product, order.tier); }
    catch (e) { set = { ok: false, reason: e.message }; }
    if (!set || !set.ok) {
      return { result: 'refused', level: 'error', account: accountId, product, reason: `grant_failed:${set && set.reason}` };
    }
    if (typeof d.markProcessed === 'function') { try { await d.markProcessed(payment.id, 'granted'); } catch { /* best effort */ } }
    return { result: 'granted', level: 'info', account: accountId, product, tier: order.tier, reason: `${product}->${order.tier}` };
  }

  if (status === 'chargeback' || status === 'charged_back') {
    // Money reclaimed. Revoke: drop this product to its floor tier.
    const floor = catalog.floorTier(product);
    try { await d.setProductPlan(accountId, product, floor); } catch { /* logged by caller via reason */ }
    if (typeof d.markProcessed === 'function') { try { await d.markProcessed(payment.id, 'revoked'); } catch { /* best effort */ } }
    return { result: 'revoked', level: 'warn', account: accountId, product, tier: floor, reason: 'chargeback' };
  }

  // failed | expired | canceled | open | pending -> no entitlement change.
  return { result: 'ignored', level: 'info', account: accountId, product, reason: `status_${status}` };
}

// A failed re-fetch of the payment is not one thing, and the answer decides
// what Mollie does next. Mollie retries a webhook for about a day, so:
//   - no API key, a rejected key, a 5xx or a timeout -> a retry can still land
//     once the config or Mollie is fixed. Ask for one (503).
//   - 404 / 410 / 422 -> this payment id will never resolve. A retry cannot
//     help, so accept the event and stop the hammering (200).
// Answering 503 for everything did both wrong: it kept Mollie retrying a
// webhook that could never succeed, and it hid a missing MOLLIE_API_KEY behind
// the same body as an id that simply does not exist. The wire body stays
// 'fetch_failed' for every retryable case so a public prober learns nothing
// about our config; the distinction lives in the log, at the right level.
function classifyFetchError(err) {
  const msg = (err && err.message) || '';
  const status = err && err.status;
  if (msg.startsWith('mollie_key_missing')) {
    return { retry: true, level: 'error', reason: 'mollie_key_missing' };
  }
  if (status === 401 || status === 403) {
    return { retry: true, level: 'error', reason: `mollie_key_rejected:${status}` };
  }
  if (status === 404 || status === 410 || status === 422) {
    return { retry: false, level: 'warn', reason: `mollie_permanent:${status}` };
  }
  return { retry: true, level: 'warn', reason: status ? `mollie_${status}` : (msg || 'fetch_error') };
}

module.exports = { processPayment, classifyFetchError };
