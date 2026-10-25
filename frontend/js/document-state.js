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
 *
 * Since "Je documenten" (25 October 2026) one screen shows three kinds of
 * work side by side: signing requests, files sent by name (/api/user/sends)
 * and requests for documents (/api/user/opvragen). Each kind maps onto the
 * same five states here, and tally() is the one count of Open and Klaar, so
 * the tab, the list and anything that quotes a number read the same figure.
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

  // A file sent by name: open while somebody has not collected it and the
  // sending has not run out; then everyone has it, or the file is gone.
  function sendState(s, nowMs) {
    if (!s) return 'waiting';
    if (s.status === 'expired') return 'expired';
    var t = Date.parse(s.expires_at || '');
    var now = typeof nowMs === 'number' ? nowMs : Date.now();
    if (!isNaN(t) && t <= now) return 'expired';
    if (Number(s.outstanding) === 0) return 'completed';
    return Number(s.collected || 0) > 0 ? 'in_progress' : 'waiting';
  }

  // A request for documents (relay/lib/opvraag.js summary): open until every
  // document came in, closed when the office closed it or it ran out.
  function requestState(r, nowMs) {
    if (!r) return 'waiting';
    if (r.state === 'complete') return 'completed';
    if (r.state === 'closed') return 'cancelled';
    var now = typeof nowMs === 'number' ? nowMs : Date.now();
    if (typeof r.expires_at === 'number' && r.expires_at <= now) return 'expired';
    return Number(r.received || 0) > 0 ? 'in_progress' : 'waiting';
  }

  function stateOf(kind, item, nowMs) {
    if (kind === 'send') return sendState(item, nowMs);
    if (kind === 'request') return requestState(item, nowMs);
    if (kind === 'inbox') return 'waiting';
    return state(item, nowMs);
  }
  function openState(st) { return st === 'waiting' || st === 'in_progress'; }

  // The one count. lists = { documents, sends, requests, inbox }, any of them
  // may be missing. Something waiting on your own signature is open work too.
  function tally(lists, nowMs) {
    var out = { open: 0, klaar: 0, completed: 0, stopped: 0 };
    var kinds = { documents: 'document', sends: 'send', requests: 'request', inbox: 'inbox' };
    Object.keys(kinds).forEach(function (key) {
      var list = lists && Array.isArray(lists[key]) ? lists[key] : [];
      list.forEach(function (item) {
        var st = stateOf(kinds[key], item, nowMs);
        if (openState(st)) out.open += 1;
        else {
          out.klaar += 1;
          if (st === 'completed') out.completed += 1; else out.stopped += 1;
        }
      });
    });
    return out;
  }

  window.paramantDocState = {
    signUntil: signUntil,
    expired: expired,
    state: state,
    isOpen: isOpen,
    isStopped: isStopped,
    sendState: sendState,
    requestState: requestState,
    stateOf: stateOf,
    isOpenState: openState,
    tally: tally,
    FILTERS: FILTERS
  };
})();
