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

// How far a paid interval carries the entitlement. Calendar months and years,
// not 30 or 365 days: a customer who pays on the 31st should renew on a date
// they recognise, and the yearly plan must not drift a day per leap year.
// Clamped to the last day of the target month, so 31 January plus one month is
// 28 February and never 3 March.
function periodEnd(from, interval) {
  const start = from instanceof Date ? new Date(from.getTime()) : new Date(from);
  if (Number.isNaN(start.getTime())) return null;
  const months = interval === 'yearly' ? 12 : interval === 'monthly' ? 1 : 0;
  if (!months) return null;
  const day = start.getUTCDate();
  const end = new Date(Date.UTC(
    start.getUTCFullYear(), start.getUTCMonth() + months, 1,
    start.getUTCHours(), start.getUTCMinutes(), start.getUTCSeconds(), start.getUTCMilliseconds(),
  ));
  const lastDay = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth() + 1, 0)).getUTCDate();
  end.setUTCDate(Math.min(day, lastDay));
  return end;
}

// A renewal extends from where the paid period currently ends, not from the day
// the money happened to land. Paying three days early must add a month, not
// throw three days away; a payment after a lapse starts from now, so a gap is
// never retroactively covered.
function extendFrom(currentPaidUntil, now) {
  const cur = currentPaidUntil ? new Date(currentPaidUntil) : null;
  if (!cur || Number.isNaN(cur.getTime())) return now;
  return cur.getTime() > now.getTime() ? cur : now;
}

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

  // Rule 3: idempotency. A payment id we already settled changes nothing when it
  // arrives again SAYING THE SAME THING. It is not "this id is finished
  // forever": a refund or a chargeback reaches us on the very same tr_ id as the
  // payment it reverses, so a flat id check swallowed the revoke and left an
  // account that had taken its money back sitting on the paid tier. What the
  // marker records is the outcome, and only a repeat of that outcome is a no-op.
  const revoking = status === 'chargeback' || status === 'charged_back';
  const wanted = revoking ? 'revoked' : 'granted';
  if (typeof d.isProcessed === 'function') {
    let done = false;
    try { done = await d.isProcessed(payment.id); } catch { done = false; }
    // A truthy non-string (an older marker, or a boolean-shaped dep) is read as
    // 'granted', which is what every marker written before this meant.
    const seen = typeof done === 'string' ? done : (done ? 'granted' : null);
    if (seen === wanted) return { result: 'ignored', level: 'info', account: accountId, product, reason: 'already_processed' };
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
    // The period this payment bought. Without it the grant never ends: Mollie is
    // asked for a one-off payment, so no second collection follows, and the
    // entitlement used to stay on the paid tier forever. An interval we cannot
    // turn into a date is refused rather than granted open-endedly.
    const now = d.now instanceof Date ? d.now : new Date();
    const paidUntil = periodEnd(extendFrom(
      typeof d.currentPaidUntil === 'function' ? await d.currentPaidUntil(accountId, product) : null,
      now,
    ), interval);
    if (!paidUntil) {
      return { result: 'refused', level: 'error', account: accountId, product, reason: `no_period_for_interval:${interval}` };
    }

    // Grant ONLY this product's tier. setProductPlan never touches the other
    // product (rule: product A must not move product B).
    let set;
    try { set = await d.setProductPlan(accountId, product, order.tier, paidUntil); }
    catch (e) { set = { ok: false, reason: e.message }; }
    if (!set || !set.ok) {
      return { result: 'refused', level: 'error', account: accountId, product, reason: `grant_failed:${set && set.reason}` };
    }
    if (typeof d.markProcessed === 'function') { try { await d.markProcessed(payment.id, 'granted'); } catch { /* best effort */ } }
    return {
      result: 'granted', level: 'info', account: accountId, product, tier: order.tier,
      paidUntil: paidUntil.toISOString(),
      reason: `${product}->${order.tier} until ${paidUntil.toISOString().slice(0, 10)}`,
    };
  }

  if (status === 'chargeback' || status === 'charged_back') {
    // Money reclaimed. Revoke: drop this product to its floor tier.
    const floor = catalog.floorTier(product);
    // null clears the period along with the tier: money reclaimed leaves no
    // paid time on record.
    try { await d.setProductPlan(accountId, product, floor, null); } catch { /* logged by caller via reason */ }
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

module.exports = { processPayment, classifyFetchError, periodEnd, extendFrom };
