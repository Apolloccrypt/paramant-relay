/* The state of one signing request, for every page that shows one.
 *
 * The homepage and /dashboard each carried their own copy of this rule, and
 * the copies drifted: /dashboard learned on acceptatie r4 that a request past
 * its signing window is Verlopen, the homepage did not. On 25 October 2026 the
 * owner's phone showed "Nog open: 1 verzoek wacht op een handtekening" on the
 * homepage and, one tap later, "Lopend 0, Gestopt 1" on /dashboard for the
 * same document. One file now, loaded by both, so they cannot disagree again.
 *
 * The relay keeps status 'pending' or 'sent' on an envelope whose window has
 * closed; expiry is a date, not a stored status. The list route hands back
 * sign_expires_at (created_at + 7 days, email-bound requests, the date
 * /co-sign shows as "Tekenen kan tot") and expires_at (how long the record is
 * kept, the fallback for open envelopes). relay/envelope.js signInviteClosed
 * and _partyWaitingRow apply the same two dates on the server side.
 *
 * States: waiting, in_progress, completed, cancelled, expired.
 * Open = waiting or in_progress. Stopped ("Gestopt") = cancelled or expired.
 */
(function () {
  'use strict';

  function signUntil(doc) {
    return (doc && (doc.sign_expires_at || doc.expires_at)) || '';
  }

  function expired(doc, nowMs) {
    if (!doc) return false;
    if (doc.status === 'expired') return true;
    var t = Date.parse(signUntil(doc));
    var now = typeof nowMs === 'number' ? nowMs : Date.now();
    return !isNaN(t) && t <= now;
  }

  function state(doc, nowMs) {
    if (!doc) return 'waiting';
    if (doc.status === 'complete') return 'completed';
    if (doc.status === 'void') return 'cancelled';
    if (expired(doc, nowMs)) return 'expired';
    return Number(doc.signed_count || 0) > 0 ? 'in_progress' : 'waiting';
  }

  function isOpen(doc, nowMs) {
    var s = state(doc, nowMs);
    return s === 'waiting' || s === 'in_progress';
  }

  function isStopped(doc, nowMs) {
    var s = state(doc, nowMs);
    return s === 'cancelled' || s === 'expired';
  }

  // The filter names /dashboard uses on its buttons and in ?filter=.
  var FILTERS = ['open', 'completed', 'cancelled', 'all'];

  window.paramantDocState = {
    signUntil: signUntil,
    expired: expired,
    state: state,
    isOpen: isOpen,
    isStopped: isStopped,
    FILTERS: FILTERS
  };
})();
