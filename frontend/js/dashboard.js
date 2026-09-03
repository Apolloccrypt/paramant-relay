/* Paramant user dashboard. Client-side renderer.
 *
 * Fetches GET /api/user/me (JSON, credentials: include) and hydrates the
 * existing markup. Auth-gate is hard: 401/403 -> hard-redirect to
 * /auth/login?next=/dashboard before any tool-surface markup becomes
 * visible (the #dh-root container starts hidden, only revealed on 200).
 *
 * ASCII-only. Same security model as the prior loader (10s AbortController,
 * credentials: include, no-store cache).
 */
(function () {
  'use strict';

  var KEYSETUP_KEY = 'paramant.keysetup.dismissed.v1';
  var LOGIN_URL = '/auth/login?next=' + encodeURIComponent('/dashboard');

  var loading = document.getElementById('dh-loading');
  var root    = document.getElementById('dh-root');
  var errBox  = document.getElementById('dh-error');
  var errMsg  = document.getElementById('dh-error-detail');
  if (!root || !loading) return;

  function show(el)   { if (el) el.hidden = false; }
  function hide(el)   { if (el) el.hidden = true; }
  function txt(sel, value) {
    var nodes = root.querySelectorAll('[data-dh="' + sel + '"]');
    for (var i = 0; i < nodes.length; i++) nodes[i].textContent = value;
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }

  // "Created Aug 31, 2026" used to sit one card away from "Ends on
  // 8 September". Two notations for the same kind of fact on the same screen,
  // so both now come from /js/format-date.js.
  function fmtDate(iso) {
    return paramantDate.day(iso);
  }

  function fmtMinutesUntil(iso) {
    if (!iso) return '--';
    var ms = new Date(iso).getTime() - Date.now();
    if (isNaN(ms) || ms <= 0) return 'expired';
    var min = Math.round(ms / 60000);
    if (min < 60) return min + ' min';
    var h = Math.floor(min / 60);
    var r = min % 60;
    return h + 'h ' + (r < 10 ? '0' + r : r) + 'm';
  }

  function showError(detail) {
    hide(loading);
    hide(root);
    show(errBox);
    if (errMsg && detail) errMsg.textContent = detail;
  }

  // Plan names, mirroring relay/lib/tiers.js, which is the declared single
  // source of truth. TIER_LIMITS has exactly four rows and normalisePlan folds
  // every other ID onto one of them: 'free' and 'dev' become community,
  // 'licensed' becomes enterprise, anything unknown becomes community. So the
  // badge has four names to say and never a raw machine string, which is what
  // it printed for 'licensed' before. tests/ui-truthfulness.test.mjs reads the
  // rows and the aliases OUT of tiers.js and fails if this drifts from it.
  var PLAN_ALIASES = { free: 'community', dev: 'community', licensed: 'enterprise' };
  var PLAN_NAMES = {
    community: 'Community',
    pro:       'Pro',
    business:  'Business',
    enterprise:'Enterprise',
  };

  function normalisePlan(plan) {
    var id = String(plan == null ? '' : plan).toLowerCase();
    if (PLAN_ALIASES[id]) return PLAN_ALIASES[id];
    return PLAN_NAMES[id] ? id : 'community';
  }

  // Per-product ladders, lowest first, so the badge can show the highest tier a
  // customer actually pays for. Mirrors PARASEND_TIERS / PARASIGN_TIERS in
  // relay/lib/entitlements.js. The two products do NOT share a floor there:
  // PARASEND_TIERS starts at 'community' and PARASIGN_TIERS at 'free', so both
  // words have to count as unpaid.
  // Only the rungs you can pay for. The two products do NOT share a floor in
  // relay/lib/entitlements.js: PARASEND_TIERS starts at 'community' and
  // PARASIGN_TIERS at 'free'. Rather than list both floor words and hope the
  // list stays complete, this reads the other way round and fails closed: a
  // tier counts as paid only when it is one of these three. A floor word, a
  // renamed tier or a typo all come out unpaid, which is the safe direction.
  var PRODUCT_LADDER = ['pro', 'business', 'enterprise'];
  var PRODUCT_NAMES = { pro: 'Pro', business: 'Business', enterprise: 'Enterprise' };

  // A product tier counts as paid only while its period still runs, which is
  // the rule effectiveProductTier() applies server-side: the floor tier never
  // expires, and a missing paid_until means no period was ever recorded.
  function paidProductTier(tier, paidUntil) {
    var t = String(tier || 'free').toLowerCase();
    if (PRODUCT_LADDER.indexOf(t) < 0) return null;
    if (!paidUntil) return t;
    var ends = Date.parse(paidUntil);
    if (!isNaN(ends) && Date.now() >= ends) return null;
    return t;
  }

  // ── The end of the term that was bought ────────────────────────────────────
  // Same rule and same words as /account: a checkout here buys one month or one
  // year outright, so paid_until_<product> is the day access stops and there is
  // no collection to announce. Two products can hold two dates; the one that
  // matters is the nearest one still ahead, and once they have all passed it is
  // the last one, because that is the day the account fell back to Community.
  var TERM_WARN_DAYS = 7;
  function termState(data, nowMs) {
    var now = typeof nowMs === 'number' ? nowMs : Date.now();
    var ends = [data.paid_until_parasign, data.paid_until_parasend]
      .map(function (v) { return v ? Date.parse(v) : NaN; })
      .filter(function (t) { return !isNaN(t); });
    if (!ends.length) return null;
    var ahead = ends.filter(function (t) { return t > now; });
    var at = ahead.length ? Math.min.apply(null, ahead) : Math.max.apply(null, ends);
    var days = (at - now) / 86400000;
    return { at: at, ended: at <= now, warn: days > 0 && days <= TERM_WARN_DAYS };
  }

  // One notation, from /js/format-date.js, and not the visitor's locale: the
  // site is in English and the same date has to read the same here, on /account
  // and in the reminder mail.
  function renderTerm(root, data) {
    var line = root.querySelector('#dh-term-line');
    var warn = root.querySelector('#dh-term-warn');
    if (line) line.hidden = true;
    if (warn) warn.hidden = true;
    var term = termState(data);
    if (!term) return;
    var when = paramantDate.day(term.at);
    if (line) {
      line.textContent = term.ended
        ? 'Ended on ' + when + ', now on Community.'
        : 'Ends on ' + when + ', nothing renews automatically.';
      line.hidden = false;
    }
    if (warn && term.warn) {
      var text = warn.querySelector('[data-dh="term-warn"]');
      if (text) text.textContent = 'Your plan ends on ' + when + '. Renew for another month or year, or let it fall back to Community. Nothing is charged automatically.';
      warn.hidden = false;
    }
  }

  // What a paying customer already has, per product, quoted from /pricing. It
  // is per product because a self-serve purchase moves one ladder only: someone
  // who bought ParaSend Pro has no signature allowance to read about. Nothing
  // here is an upsell. A customer who has paid should read what he bought.
  var PRODUCT_INCLUDES = {
    parasign: {
      pro: 'ParaSign Pro: 100 signatures a month, then \u20ac0.40 each up to 1,000, and a connection you can plug into your own systems.',
      business: 'ParaSign Business: 1,000 signatures a month, support with a name on it that answers within one business day, help answering your customers\u2019 security questionnaires, and an audit trail you can export as a file.',
      enterprise: 'ParaSign Enterprise: your own dedicated relay, a sector relay for health, legal or finance, a service level agreement with credits, a self-hosting licence and audit support.'
    },
    parasend: {
      pro: 'ParaSend Pro: links that stay open 24 hours, up to 10 reads each, up to 50 registered devices, a record of what you sent, and no rate limit.',
      enterprise: 'ParaSend Enterprise: links that stay open 7 days, up to 100 reads each, unlimited devices, your own dedicated relay, a signed Data Processing Agreement and 99.95% uptime.'
    }
  };

  // ── Return from the payment provider ────────────────────────────────────────
  // Mollie redirects the buyer to /dashboard?billing=return the moment he is
  // done paying, and calls the webhook separately. The webhook is what grants
  // the plan, so the redirect can easily win the race and land on a dashboard
  // that still says Community. Saying nothing at all was the worst of the
  // options: the buyer had just been charged and got no acknowledgement of it
  // anywhere on the site. So the band says which state we are in, and re-asks a
  // few times while the grant is still on its way.
  var lastAccountIsPaid = false;
  var RETURN_TRIES = 5;
  var RETURN_DELAY_MS = 2000;

  function isBillingReturn() {
    try { return new URLSearchParams(window.location.search).get('billing') === 'return'; }
    catch (e) { return false; }
  }

  // Take the parameter out of the address bar once it has been acted on, so a
  // reload or a shared link does not re-announce a payment.
  function clearBillingParam() {
    try {
      if (!window.history || !window.history.replaceState) return;
      var url = new URL(window.location.href);
      url.searchParams.delete('billing');
      window.history.replaceState({}, '', url.pathname + (url.search || '') + (url.hash || ''));
    } catch (e) { /* address bar is cosmetic; never break the page over it */ }
  }

  function showBillingReturn(tries) {
    var band = document.querySelector('#dh-billing-return');
    if (!band) return;
    var kicker = band.querySelector('[data-dh="return-kicker"]');
    var lede = band.querySelector('[data-dh="return-lede"]');
    band.hidden = false;
    if (lastAccountIsPaid) {
      if (kicker) kicker.textContent = 'Payment received';
      if (lede) lede.textContent = 'Thank you. Your plan is active and what it includes is below. The term you bought and the day it ends are under Plan and billing.';
      clearBillingParam();
      return;
    }
    if (tries > 0) {
      if (kicker) kicker.textContent = 'Confirming your payment';
      if (lede) lede.textContent = 'Your bank has sent you back. We are waiting for the payment to be confirmed, which usually takes a few seconds. This page updates by itself.';
      window.setTimeout(function () { refreshAccount(tries - 1); }, RETURN_DELAY_MS);
      return;
    }
    if (kicker) kicker.textContent = 'Payment not confirmed yet';
    if (lede) lede.textContent = 'Your payment has not reached us yet. Nothing is lost: as soon as it is confirmed the plan is granted by itself. Reload this page in a minute, and mail privacy@paramant.app if it still has not appeared.';
    clearBillingParam();
  }

  function render(data) {
    var email = data.email || '';
    var planId = normalisePlan(data.plan);
    var planName = PLAN_NAMES[planId];

    // The unified plan is not the whole answer. A self-serve ParaSign or
    // ParaSend purchase moves only that product's tier, so read those too and
    // let the highest paid one speak for the account.
    var paidTiers = [
      paidProductTier(data.plan_parasign, data.paid_until_parasign),
      paidProductTier(data.plan_parasend, data.paid_until_parasend),
    ].filter(Boolean);
    var topPaid = null;
    for (var pi = 0; pi < paidTiers.length; pi++) {
      if (!topPaid || PRODUCT_LADDER.indexOf(paidTiers[pi]) > PRODUCT_LADDER.indexOf(topPaid)) topPaid = paidTiers[pi];
    }
    var isFree = planId === 'community' && !topPaid;
    if (topPaid && planId === 'community') planName = PRODUCT_NAMES[topPaid] || planName;

    txt('email-full',   email || '--');
    txt('plan',         planName);
    txt('plan-strong',  planName);

    // A free plan gets one visible way up, and it is told what it is on: the
    // Community plan is a gift, not a trial, and the business plans are what
    // pays for it. A paying customer never sees the band.
    var community = root.querySelector('#dh-community');
    if (community) community.hidden = !isFree;

    // Remembered for the return-from-Mollie band below, which has to know
    // whether the webhook has landed yet.
    lastAccountIsPaid = !isFree;

    // The other half of the same rule: a paying account reads what it bought.
    // Per product, so a ParaSend customer is not told about signatures he has
    // no allowance for, and with a plain sentence for an account whose unified
    // plan was granted by hand rather than bought through a product ladder.
    var paid = root.querySelector('#dh-plan-paid');
    if (paid) {
      var lines = [];
      var bought = [
        ['parasign', paidProductTier(data.plan_parasign, data.paid_until_parasign)],
        ['parasend', paidProductTier(data.plan_parasend, data.paid_until_parasend)]
      ];
      for (var bi = 0; bi < bought.length; bi++) {
        var copy = bought[bi][1] && PRODUCT_INCLUDES[bought[bi][0]][bought[bi][1]];
        if (copy) lines.push(copy);
      }
      if (!lines.length && planId !== 'community') {
        lines.push('Your account is on the ' + planName + ' plan, with the ' + planName +
                   ' limits on both ParaSign and ParaSend.');
      }
      paid.hidden = isFree || !lines.length;
      if (!paid.hidden) {
        txt('paid-name', planName);
        txt('paid-includes', lines.join(' '));
      }
    }

    // Outside the paid band on purpose. An expired term floors every product,
    // which empties that band, and the one moment a customer most needs the
    // date is the moment the band that would have carried it disappears.
    renderTerm(root, data);
    txt('created',      fmtDate(data.created_at));
    txt('backup',       String(data.backup_codes_remaining != null ? data.backup_codes_remaining : '--'));
    txt('session',      fmtMinutesUntil(data.session_expires_at));

    initPurposeCard(data);

    hide(loading);
    hide(errBox);
    show(root);
    root.classList.add('dh-loaded');

    checkKeySetup();
    loadOperations();
    loadDocuments();
  }

  function wireActions() {
    root.addEventListener('click', function (ev) {
      var t = ev.target.closest && ev.target.closest('[data-pa-action]');
      if (!t) return;
      var act = t.getAttribute('data-pa-action');
      if (act === 'refresh') {
        ev.preventDefault();
        location.reload();
        return;
      }
      if (act === 'signout') {
        ev.preventDefault();
        t.disabled = true;
        fetch('/api/user/logout', { method: 'POST', credentials: 'include' })
          .catch(function () {})
          .then(function () { location.href = '/auth/login'; });
        return;
      }
      if (act === 'documents-refresh') {
        ev.preventDefault();
        loadDocuments();
        return;
      }
      if (act === 'document-close') {
        ev.preventDefault();
        closeDocumentDialog();
        return;
      }
      if (act === 'document-cancel') {
        ev.preventDefault();
        cancelDocument(t.getAttribute('data-document-id'), t);
      }
    });
  }

  // Account-scoped signing worklist. This is relay-measured lifecycle metadata,
  // not browser-inferred success. Document bytes, hashes, invite capabilities
  // and recipient email hashes are intentionally absent from the response.
  var documents = [];
  var documentFilter = 'open';
  var documentDialogReturnFocus = null;

  function documentState(doc) {
    if (doc.status === 'complete') return 'completed';
    if (doc.status === 'void') return 'cancelled';
    return Number(doc.signed_count || 0) > 0 ? 'in_progress' : 'waiting';
  }

  function documentMatches(doc, filter) {
    var state = documentState(doc);
    if (filter === 'all') return true;
    if (filter === 'open') return state === 'waiting' || state === 'in_progress';
    return state === filter;
  }

  function documentLabel(state) {
    return ({
      waiting: 'Waiting for signatures',
      in_progress: 'In progress',
      completed: 'Completed',
      cancelled: 'Cancelled'
    })[state] || 'Open';
  }

  function renderDocumentCounts() {
    var counts = { open: 0, completed: 0, cancelled: 0, all: documents.length };
    documents.forEach(function (doc) {
      var state = documentState(doc);
      if (state === 'waiting' || state === 'in_progress') counts.open += 1;
      if (state === 'completed') counts.completed += 1;
      if (state === 'cancelled') counts.cancelled += 1;
    });
    Object.keys(counts).forEach(function (key) {
      var node = document.querySelector('[data-doc-count="' + key + '"]');
      if (node) node.textContent = String(counts[key]);
    });
  }

  function renderDocuments() {
    var list = document.getElementById('dh-documents');
    if (!list) return;
    // The skeleton is gone the moment real rows exist, so aria-busy has to go
    // with it or a screen reader keeps announcing a list that already landed.
    list.setAttribute('aria-busy', 'false');
    renderDocumentCounts();
    var visible = documents.filter(function (doc) { return documentMatches(doc, documentFilter); });
    if (!visible.length) {
      var empty = documentFilter === 'open'
        ? ['No open requests', 'Start a signing request when you need someone to sign a document.']
        : ['Nothing here yet', 'Documents in this state will appear here automatically.'];
      // An empty state that only describes the way out is a dead end. The one
      // action that fills this list is a signing request, so it gets a button
      // to the page that starts one. Send is deliberately not offered here:
      // this list counts signing requests, not deliveries.
      list.innerHTML = '<div class="dh-empty"><strong>' + empty[0] + '</strong><span>' + empty[1] + '</span>' +
        '<a class="dh-btn dh-empty-cta" href="/sign?mode=invite">Start a signing request</a></div>';
      return;
    }
    list.innerHTML = visible.map(function (doc) {
      var state = documentState(doc);
      var total = Math.max(0, Number(doc.party_count || 0));
      var signed = Math.max(0, Math.min(total, Number(doc.signed_count || 0)));
      var pct = total ? Math.round((signed / total) * 100) : 0;
      var name = doc.original_filename || 'Signing request';
      // The reference used to be cut to ten characters in code, which sliced
      // env_waiting_... into "env_waitin": a fragment that looks like a whole
      // value and is useless for support. The full value goes in, CSS shortens
      // it with an ellipsis when it does not fit, and the title carries it.
      var reference = String(doc.id || '');
      return '<button type="button" class="dh-document" data-document-id="' + esc(doc.id || '') + '" aria-label="Open details for ' + esc(name) + '">' +
        '<div class="dh-document-name"><strong title="' + esc(name) + '">' + esc(name) + '</strong>' +
        '<span>Created ' + esc(fmtDate(doc.created_at)) +
        (reference ? ' <span class="dh-doc-ref" title="' + esc(reference) + '">· Ref ' + esc(reference) + '</span>' : '') +
        '</span></div>' +
        '<div class="dh-document-progress"><span>' + signed + ' of ' + total + ' signed</span><div class="dh-progress" aria-label="' + signed + ' of ' + total + ' signed"><i style="width:' + pct + '%"></i></div></div>' +
        '<div class="dh-status ' + state + '">' + documentLabel(state) + '</div>' +
        '</button>';
    }).join('');
  }

  function documentById(id) {
    for (var i = 0; i < documents.length; i++) if (documents[i].id === id) return documents[i];
    return null;
  }

  function closeDocumentDialog() {
    var dialog = document.getElementById('dh-document-dialog');
    if (dialog) dialog.hidden = true;
    if (documentDialogReturnFocus && typeof documentDialogReturnFocus.focus === 'function') documentDialogReturnFocus.focus();
    documentDialogReturnFocus = null;
  }

  function openDocumentDialog(id) {
    var doc = documentById(id);
    var dialog = document.getElementById('dh-document-dialog');
    var title = document.getElementById('dh-document-dialog-title');
    var body = document.getElementById('dh-document-dialog-body');
    if (!doc || !dialog || !body || !title) return;
    documentDialogReturnFocus = document.activeElement;
    var state = documentState(doc);
    var total = Math.max(0, Number(doc.party_count || 0));
    var signed = Math.max(0, Math.min(total, Number(doc.signed_count || 0)));
    title.textContent = doc.original_filename || 'Signing request';
    var parties = Array.isArray(doc.parties) ? doc.parties : [];
    var partyText = parties.length ? parties.map(function (p) {
      return esc(p.label || ('Signer ' + (Number(p.index || 0) + 1))) + ': ' + esc(p.status === 'signed' ? 'signed' : p.status === 'viewed' ? 'opened' : 'waiting');
    }).join('<br>') : signed + ' of ' + total + ' signed';
    var help = state === 'completed'
      ? 'The relay keeps the cryptographic proof, not a plaintext copy of your document. Download the .psign proof here. Keep it next to your locally saved signed document. You can verify both later in Paramant.'
      : state === 'cancelled'
        ? 'This request is closed. Existing signatures remain in the audit record, but nobody can add another signature.'
        : 'This request is still open. Paramant stores the delivered document encrypted. The plaintext document and its key are not recoverable from the relay dashboard.';
    var actions = '';
    if (state === 'completed') actions += '<a class="dh-btn" href="/api/user/documents/' + encodeURIComponent(doc.id) + '/receipt" download>Download .psign proof</a>';
    if (state === 'waiting' || state === 'in_progress') actions += '<button class="dh-btn danger" type="button" data-pa-action="document-cancel" data-document-id="' + esc(doc.id) + '">Cancel request</button>';
    actions += '<a class="dh-btn" href="/verify">Verify a document</a>';
    body.innerHTML = '<dl class="dh-doc-kv">' +
      '<dt>Status</dt><dd>' + esc(documentLabel(state)) + '</dd>' +
      '<dt>Reference</dt><dd>' + esc(doc.id || '') + '</dd>' +
      '<dt>Created</dt><dd>' + esc(fmtDate(doc.created_at)) + '</dd>' +
      '<dt>Expires</dt><dd>' + esc(fmtDate(doc.expires_at)) + '</dd>' +
      '<dt>Signers</dt><dd>' + partyText + '</dd></dl>' +
      '<div class="dh-doc-help">' + esc(help) + '</div>' +
      '<div class="dh-doc-actions">' + actions + '</div><div class="dh-doc-message" id="dh-doc-message" aria-live="polite"></div>';
    dialog.hidden = false;
    var close = dialog.querySelector('[data-pa-action="document-close"]');
    if (close) close.focus();
  }

  function cancelDocument(id, button) {
    var doc = documentById(id);
    if (!doc || !confirm('Cancel this signing request? Nobody will be able to add another signature.')) return;
    if (button) button.disabled = true;
    var message = document.getElementById('dh-doc-message');
    if (message) message.textContent = 'Cancelling request...';
    fetch('/api/user/documents/' + encodeURIComponent(id) + '/cancel', {
      method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: '{}'
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        if (!r.ok) throw new Error(body.error || ('http_' + r.status));
        return body;
      });
    }).then(function () {
      doc.status = 'void';
      renderDocuments();
      openDocumentDialog(id);
    }).catch(function (err) {
      if (button) button.disabled = false;
      if (message) message.textContent = err.message === 'already_complete'
        ? 'This request completed before cancellation. Refresh to see the final status.'
        : 'Could not cancel this request. Try again.';
    });
  }

  function loadDocuments() {
    var list = document.getElementById('dh-documents');
    var refresh = document.getElementById('dh-documents-refresh');
    if (!list) return;
    if (refresh) { refresh.disabled = true; refresh.textContent = 'Refreshing'; }
    fetch('/api/user/documents', {
      credentials: 'include',
      headers: { 'Accept': 'application/json' },
      cache: 'no-store'
    }).then(function (r) {
      if (!r.ok) throw new Error('http_' + r.status);
      return r.json();
    }).then(function (body) {
      documents = Array.isArray(body.documents) ? body.documents : [];
      renderDocuments();
    }).catch(function () {
      list.innerHTML = '<div class="dh-empty"><strong>Document status is unavailable</strong><span>Your documents are unchanged. <button class="dh-refresh" type="button" data-pa-action="documents-refresh">Try again</button></span></div>';
    }).finally(function () {
      if (refresh) { refresh.disabled = false; refresh.textContent = 'Refresh'; }
    });
  }

  function wireDocumentFilters() {
    var filters = document.querySelectorAll('[data-doc-filter]');
    for (var i = 0; i < filters.length; i++) {
      filters[i].addEventListener('click', function () {
        documentFilter = this.getAttribute('data-doc-filter') || 'open';
        for (var j = 0; j < filters.length; j++) {
          filters[j].setAttribute('aria-pressed', filters[j] === this ? 'true' : 'false');
        }
        renderDocuments();
      });
    }
  }

  function wireDocumentList() {
    var list = document.getElementById('dh-documents');
    var dialog = document.getElementById('dh-document-dialog');
    if (!list) return;
    list.addEventListener('click', function (ev) {
      var row = ev.target.closest && ev.target.closest('[data-document-id]');
      if (row && row.classList.contains('dh-document')) openDocumentDialog(row.getAttribute('data-document-id'));
    });
    if (dialog) dialog.addEventListener('click', function (ev) {
      if (ev.target === dialog) closeDocumentDialog();
    });
    document.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape' && dialog && !dialog.hidden) closeDocumentDialog();
    });
  }

  // One-time usage-purpose question. Server-driven: /api/user/me returns
  // usage_purpose (null while unanswered). Answering or skipping posts to
  // /api/user/usage-purpose; the server stores it on the account, so the card
  // never returns on any device. On a failed save the card stays and the
  // buttons re-enable (never lose the answer silently).
  function initPurposeCard(data) {
    var card = document.getElementById('dh-purpose');
    if (!card) return;
    if (data.usage_purpose) { card.hidden = true; return; }
    card.hidden = false;
    if (card._wired) return;
    card._wired = 1;
    card.addEventListener('click', function (ev) {
      var t = ev.target.closest && ev.target.closest('[data-pa-purpose]');
      if (!t) return;
      var purpose = t.getAttribute('data-pa-purpose');
      var btns = card.querySelectorAll('[data-pa-purpose]');
      var i;
      for (i = 0; i < btns.length; i++) btns[i].disabled = true;
      fetch('/api/user/usage-purpose', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ purpose: purpose })
      }).then(function (r) {
        if (!r.ok) throw new Error('http_' + r.status);
        card.hidden = true;
      }).catch(function () {
        for (i = 0; i < btns.length; i++) btns[i].disabled = false;
        var note = document.getElementById('dh-purpose-note');
        if (note) { note.hidden = false; note.textContent = 'Could not save right now. Try again, or skip.'; }
      });
    });
  }

  // One-time nudge: if the account is missing a signing key and/or a sign-in
  // passkey, surface a dismissible popup that links into /account. Best-effort
  // and tolerant -- we only flag something as missing when the endpoint answers
  // cleanly with an empty list, never on a fetch error (so we never false-nag).
  function checkKeySetup() {
    try { if (localStorage.getItem(KEYSETUP_KEY) === '1') return; } catch (_) {}

    var modal = document.getElementById('dh-passkey-modal');
    var itemsBox = document.getElementById('dh-pm-items');
    var dismissBtn = document.getElementById('dh-pm-dismiss');
    if (!modal || !itemsBox) return;

    function getJSON(url) {
      return fetch(url, { credentials: 'include', headers: { 'Accept': 'application/json' }, cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .catch(function () { return null; });
    }

    Promise.all([
      getJSON('/api/user/account/signing-key'),
      getJSON('/api/user/account/webauthn/credentials')
    ]).then(function (res) {
      var signing = res[0], passkeys = res[1];
      var items = [];
      if (signing && Array.isArray(signing.keys) && signing.keys.length === 0) {
        items.push({
          href: '/account#signing-identity-section',
          title: 'Set up document signing',
          body: 'Create your ML-DSA-65 signing key so you can sign and co-sign documents.'
        });
      }
      if (passkeys && Array.isArray(passkeys.passkeys) && passkeys.passkeys.length === 0) {
        items.push({
          href: '/account#passkey-section',
          title: 'Add a sign-in passkey',
          body: 'Use Face ID, Touch ID, or a security key to sign in without a code.'
        });
      }
      if (!items.length) return;

      // Titles/bodies are static literals (no user input) -> safe innerHTML.
      itemsBox.innerHTML = items.map(function (it) {
        return '<a class="dh-pm-item" href="' + it.href + '">'
          + '<strong>' + it.title + '</strong>'
          + '<span>' + it.body + '</span></a>';
      }).join('');
      modal.hidden = false;

      function dismiss() {
        modal.hidden = true;
        try { localStorage.setItem(KEYSETUP_KEY, '1'); } catch (_) {}
      }
      if (dismissBtn) dismissBtn.addEventListener('click', dismiss);
      modal.addEventListener('click', function (ev) { if (ev.target === modal) dismiss(); });
      document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape' && !modal.hidden) dismiss(); });
    });
  }

  // ---- Operations: read-only live keys / usage / activity cards ----
  // Fed by GET /api/user/dashboard/overview (authUser). Polled every 5s so the
  // usage bars stay current; the audit feed and key are refreshed on the same tick.
  var opsAudit = [], opsFilter = '', opsPollTimer = 0;
  function fmtTime(ts) {
    if (!ts) return '--:--:--';
    var d = new Date(ts);
    function p(n) { return (n < 10 ? '0' : '') + n; }
    var hm = p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    var now = new Date();
    if (d.toDateString() === now.toDateString()) return hm;
    var mon = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.getMonth()];
    var day = d.getDate() + ' ' + mon + (d.getFullYear() !== now.getFullYear() ? ' ' + d.getFullYear() : '');
    return day + ' ' + hm;
  }
  function opsBar(used, cap) {
    var unlimited = (cap == null);
    var pct = unlimited ? 4 : Math.min(100, Math.round(((used || 0) / Math.max(1, cap)) * 100));
    return { pct: pct, warn: !unlimited && pct >= 80, capTxt: unlimited ? '&#8734;' : String(cap) };
  }
  function renderOpsTimeline() {
    var el = document.getElementById('dh-ops-timeline');
    if (!el) return;
    var f = (opsFilter || '').toLowerCase();
    var rows = opsAudit.filter(function (ev) {
      if (!f) return true;
      return (ev.event_type || '').toLowerCase().indexOf(f) >= 0 ||
             JSON.stringify(ev.metadata || {}).toLowerCase().indexOf(f) >= 0;
    });
    el.innerHTML = rows.length
      ? rows.slice(0, 50).map(function (ev) {
          return '<div class="dh-tl-row"><span class="t">' + fmtTime(ev.ts) + '</span><span class="e">' + esc(ev.event_type || 'event') + '</span></div>';
        }).join('')
      : '<div class="dh-ops-dim">No activity' + (f ? ' matches "' + esc(opsFilter) + '"' : ' yet') + '.</div>';
  }
  function renderOps(d) {
    // No key on this page, not even a masked one. /account is the one page that
    // shows the account key, behind its "Advanced account key" fold and only
    // when that fold is opened; /dashboard authenticates to the relay with a
    // short-lived scoped pst_ token instead (js/app-session-token.js), so it has
    // no reason to hold or print a key shape at all. The overview endpoint stopped
    // sending key_masked with it.
    var keysEl = document.getElementById('dh-ops-keys');
    if (keysEl) {
      keysEl.innerHTML =
        '<div class="dh-ops-row"><span class="dim">account key</span><span class="dim"><a href="/account">on your account page</a></span></div>' +
        '<div class="dh-ops-row"><span class="dim">last used</span><span class="dim">tracked via activity</span></div>';
    }
    var q = d.quota || { transfers: 0, signs: 0, caps: {} };
    var caps = q.caps || {};
    function usageRow(label, used, cap) {
      var b = opsBar(used, cap);
      return '<div class="dh-usage-row"><div class="dh-usage-lab"><span>' + label + '</span><span><b>' + (used || 0) + '</b> / ' + b.capTxt + '</span></div>' +
        '<div class="dh-bar' + (b.warn ? ' warn' : '') + '"><i style="width:' + b.pct + '%"></i></div>' +
        (b.warn ? '<a class="dh-usage-upsell" href="/pricing">Upgrade to Pro</a>' : '') + '</div>';
    }
    var usageEl = document.getElementById('dh-ops-usage');
    if (usageEl) {
      usageEl.innerHTML = usageRow('Transfers', q.transfers, caps.transfers) + usageRow('Signings', q.signs, caps.signs) +
        '<div class="dh-ops-dim" style="font-size:10px">Live, refreshes every 5s.</div>';
    }
    opsAudit = d.audit || [];
    renderOpsTimeline();
  }
  function loadOperations() {
    if (!document.getElementById('dh-ops')) return;
    var fi = document.getElementById('dh-ops-filter');
    if (fi && !fi._wired) { fi._wired = 1; fi.addEventListener('input', function () { opsFilter = fi.value; renderOpsTimeline(); }); }
    function pull() {
      return fetch('/api/user/dashboard/overview', { credentials: 'include', headers: { 'Accept': 'application/json' }, cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) { if (d) renderOps(d); })
        .catch(function () {});
    }
    pull();
    if (!opsPollTimer) opsPollTimer = setInterval(pull, 5000);
  }

  function start(tries) {
    wireActions();
    wireDocumentFilters();
    wireDocumentList();

    var ctrl = ('AbortController' in window) ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, 10000) : 0;
    var opts = {
      credentials: 'include',
      headers: { 'Accept': 'application/json' },
      cache: 'no-store',
    };
    if (ctrl) opts.signal = ctrl.signal;

    fetch('/api/user/me', opts)
      .then(function (r) {
        if (timer) clearTimeout(timer);
        if (r.status === 401 || r.status === 403) {
          location.replace(LOGIN_URL);
          return null;
        }
        if (!r.ok) {
          showError('HTTP ' + r.status);
          return null;
        }
        return r.json();
      })
      .then(function (data) {
        if (data) render(data);
        // Only after render, so lastAccountIsPaid reflects this answer.
        if (isBillingReturn()) showBillingReturn(typeof tries === 'number' ? tries : RETURN_TRIES);
      })
      .catch(function () {
        if (timer) clearTimeout(timer);
        showError('Network error');
      });
  }

  // Re-ask /api/user/me while a just-made payment is still being confirmed.
  function refreshAccount(tries) { start(tries); }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
