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
//   4) Only status 'paid' grants, and only when nothing has gone back.
//      failed/expired/canceled do nothing; money returned in full, by chargeback
//      OR by refund, revokes to the product floor.

const catalog = require('./billing-catalog');
const creditNote = require('./credit-note');
const invoice = require('./invoice');

// ── has any money gone back, and was it all of it ────────────────────────────
// The document layer (credit-note.js) and this layer must agree about what
// counts as money returned, or the customer gets a credit note for a plan he
// keeps. Before 2026-09-06 they did not: credit-note.isReversal already read
// both cumulative counters, while this file matched on the STATUS STRING alone
// and only for 'chargeback'. Mollie reports a refund on the very same tr_ id
// with the status still 'paid' and amountRefunded set, so a refund did not even
// reach the fall-through the review pointed at -- it went down the PAID branch,
// and only the idempotency marker stood between a refunded payment and a fresh
// month granted on it.
//
// So the predicate is imported rather than restated. `full` decides revoke
// versus leave-alone, and it is deliberately conservative in the one direction
// that matters: a 'chargeback' status is whole no matter what the counters say,
// which is exactly what this file did before. What is new is that a 'refunded'
// status, and a still-'paid' payment whose counters reach the invoiced amount,
// are whole too. A part-refund revokes nothing and grants nothing.
function reversalOf(payment) {
  const p = payment || {};
  if (!creditNote.isReversal(p)) return null;
  const cents = (v) => { const c = invoice.centsOf(v); return Number.isFinite(c) ? c : 0; };
  const gross = cents(p.amount && p.amount.value);
  const back = cents(p.amountRefunded && p.amountRefunded.value)
             + cents(p.amountChargedBack && p.amountChargedBack.value);
  const status = String(p.status || '');
  const wholeByStatus = status === 'chargeback' || status === 'charged_back' || status === 'refunded';
  const full = wholeByStatus || (back > 0 && gross > 0 && back >= gross);
  return { full, kind: creditNote.reasonOf(p), back, gross };
}

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

// A BUNDLE buys one term for several products at once, so it needs ONE anchor
// for all of them. The anchor is the EARLIEST of the per-product anchors: a
// bundle month must add a month to the product that has the least time left,
// never silently hand a year of the other product to somebody who paid for a
// month. Nobody loses time either, because the term written per product is
// clamped upwards below (keepLonger).
function bundleExtendFrom(currentPaidUntils, now) {
  let anchor = null;
  for (const cur of currentPaidUntils || []) {
    const a = extendFrom(cur, now);
    if (!anchor || a.getTime() < anchor.getTime()) anchor = a;
  }
  return anchor || now;
}

// Never shorten a period that is already on file. A customer holding ParaSign
// Pro until next June who buys one month of Firm gets ParaSend Pro for that
// month and KEEPS his June on ParaSign. Rule 4 of the Firm brief: an existing
// paying customer may not lose a single day by our changing what we sell.
function keepLonger(candidate, currentPaidUntil) {
  const cur = currentPaidUntil ? new Date(currentPaidUntil) : null;
  if (!cur || Number.isNaN(cur.getTime())) return candidate;
  return cur.getTime() > candidate.getTime() ? cur : candidate;
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
  const reversal = reversalOf(payment);
  const revoking = !!(reversal && reversal.full);
  const wanted = revoking ? 'revoked' : 'granted';
  if (typeof d.isProcessed === 'function') {
    let done = false;
    try { done = await d.isProcessed(payment.id); } catch { done = false; }
    // A truthy non-string (an older marker, or a boolean-shaped dep) is read as
    // 'granted', which is what every marker written before this meant.
    const seen = typeof done === 'string' ? done : (done ? 'granted' : null);
    if (seen === wanted) return { result: 'ignored', level: 'info', account: accountId, product, reason: 'already_processed' };
  }

  if (revoking) {
    // Money reclaimed, in full, by chargeback or by refund. Revoke: drop this
    // product to its floor tier.
    // EVERY product the order bought goes back to its floor. A bundle that
    // granted two entitlements and revoked one would leave the customer holding
    // half a plan he has taken the money back for.
    const revoked = [];
    for (const g of order.grants) {
      const floor = catalog.floorTier(g.product);
      // null clears the period along with the tier: money reclaimed leaves no
      // paid time on record.
      try { await d.setProductPlan(accountId, g.product, floor, null, null); } catch { /* logged by caller via reason */ }
      revoked.push({ product: g.product, tier: floor });
    }
    if (typeof d.markProcessed === 'function') { try { await d.markProcessed(payment.id, 'revoked'); } catch { /* best effort */ } }
    return {
      result: 'revoked', level: 'warn', account: accountId, product,
      bundle: order.bundle || null, tier: revoked[0].tier, grants: revoked, reason: reversal.kind,
    };
  }

  // Money went back, but not all of it. A part-refund is not a cancelled sale,
  // so the entitlement stands -- but it must not be read as a fresh purchase
  // either, which is what happened while a refund arrived as a still-'paid'
  // payment and fell into the grant branch above. The credit note is issued by
  // the webhook regardless (it is not gated on this outcome).
  if (reversal) {
    return {
      result: 'ignored', level: 'info', account: accountId, product,
      reason: `partial_${reversal.kind}:${reversal.back}_of_${reversal.gross}`,
    };
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
    //
    // One anchor for the whole order, so a bundle writes ONE term across the
    // products it covers instead of two dates that drift apart on every renewal.
    const now = d.now instanceof Date ? d.now : new Date();
    const currents = [];
    for (const g of order.grants) {
      currents.push(typeof d.currentPaidUntil === 'function' ? await d.currentPaidUntil(accountId, g.product) : null);
    }
    const paidUntil = periodEnd(bundleExtendFrom(currents, now), interval);
    if (!paidUntil) {
      return { result: 'refused', level: 'error', account: accountId, product, reason: `no_period_for_interval:${interval}` };
    }

    // Grant each product in the order. setProductPlan moves ONE product per
    // call and never touches a product this order does not name, so a ParaSign
    // Business holder buying nothing keeps what he has. `bundle` is passed on so
    // the expiry index can tell the customer what he actually bought.
    const granted = [];
    for (let i = 0; i < order.grants.length; i++) {
      const g = order.grants[i];
      const until = keepLonger(paidUntil, currents[i]);
      let set;
      try { set = await d.setProductPlan(accountId, g.product, g.tier, until, order.bundle || null); }
      catch (e) { set = { ok: false, reason: e.message }; }
      if (!set || !set.ok) {
        return {
          result: 'refused', level: 'error', account: accountId, product,
          reason: `grant_failed:${g.product}:${set && set.reason}`,
          granted: granted.slice(),
        };
      }
      granted.push({ product: g.product, tier: g.tier, paidUntil: until.toISOString() });
    }
    if (typeof d.markProcessed === 'function') { try { await d.markProcessed(payment.id, 'granted'); } catch { /* best effort */ } }
    return {
      result: 'granted', level: 'info', account: accountId, product, tier: order.tier,
      bundle: order.bundle || null,
      grants: granted,
      paidUntil: paidUntil.toISOString(),
      reason: `${granted.map((g) => `${g.product}->${g.tier}`).join(' + ')} until ${paidUntil.toISOString().slice(0, 10)}`,
    };
  }


  // authorized | failed | expired | canceled | open | pending -> no entitlement
  // change. Money that went back no longer lands here: it is answered above,
  // whatever status string it arrived under.
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

module.exports = { processPayment, classifyFetchError, reversalOf, periodEnd, extendFrom, bundleExtendFrom, keepLonger };
