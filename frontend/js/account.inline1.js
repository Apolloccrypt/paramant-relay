
(function() {
  // Plan resolution, the same shape js/dashboard.js uses, because a customer
  // who wants to know what he pays comes here rather than to the dashboard and
  // must not read a different answer. relay/lib/tiers.js is the declared single
  // source of truth: TIER_LIMITS holds the canonical rows and normalisePlan
  // folds every other ID onto one of them ('free' and 'dev' to community,
  // 'licensed' to enterprise, anything unknown to community). That last rule is
  // why 'standard', which the API returns for a record with no plan at all,
  // resolves to Community instead of printing a machine string on the page.
  // tests/ui-truthfulness.test.mjs reads the rows and aliases out of tiers.js
  // and fails if this drifts from it.
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

  // Per-product ladders, lowest first. Mirrors PARASEND_TIERS / PARASIGN_TIERS
  // in relay/lib/entitlements.js, where the two products do NOT share a floor:
  // PARASEND_TIERS starts at 'community' and PARASIGN_TIERS at 'free'. Both
  // words therefore have to count as unpaid.
  // Only the rungs you can pay for. The two products do NOT share a floor in
  // relay/lib/entitlements.js: PARASEND_TIERS starts at 'community' and
  // PARASIGN_TIERS at 'free'. Rather than list both floor words and hope the
  // list stays complete, this reads the other way round and fails closed: a
  // tier counts as paid only when it is one of these three. A floor word, a
  // renamed tier or a typo all come out unpaid, which is the safe direction.
  var PRODUCT_LADDER = ['pro', 'business', 'enterprise'];
  var PRODUCT_NAMES = { pro: 'Pro', business: 'Business', enterprise: 'Enterprise' };

  // A product tier counts as paid only while its period still runs, the rule
  // effectiveProductTier() applies server-side: the floor tier never expires,
  // and a missing paid_until means no period was ever recorded.
  function paidProductTier(tier, paidUntil) {
    var t = String(tier || 'free').toLowerCase();
    if (PRODUCT_LADDER.indexOf(t) < 0) return null;
    if (!paidUntil) return t;
    var ends = Date.parse(paidUntil);
    if (!isNaN(ends) && Date.now() >= ends) return null;
    return t;
  }

  // The highest tier this account actually pays for, across both products, or
  // null when it pays for neither. A self-serve purchase moves one product
  // ladder and leaves the unified plan on community, so testing the unified
  // plan alone showed a paying customer the free band and the upgrade link.
  function topPaidTier(data) {
    var top = null;
    var tiers = [
      paidProductTier(data.plan_parasign, data.paid_until_parasign),
      paidProductTier(data.plan_parasend, data.paid_until_parasend)
    ];
    for (var i = 0; i < tiers.length; i++) {
      if (tiers[i] && (!top || PRODUCT_LADDER.indexOf(tiers[i]) > PRODUCT_LADDER.indexOf(top))) top = tiers[i];
    }
    return top;
  }

  // The name to put on screen: the unified plan, unless a product purchase
  // outranks it while the unified plan is still the free row.
  function planName(data, plan) {
    var id = normalisePlan(plan);
    var top = topPaidTier(data);
    if (top && id === 'community') return PRODUCT_NAMES[top] || PLAN_NAMES[id];
    return PLAN_NAMES[id];
  }

  function isFreeAccount(data, plan) {
    return normalisePlan(plan) === 'community' && !topPaidTier(data);
  }

  function show(id) {
    document.querySelectorAll('[id^="state-"]').forEach(function(el) {
      el.classList.add('hidden');
    });
    document.getElementById(id).classList.remove('hidden');
  }

  async function loadAccount() {
    try {
      const res = await fetch('/api/user/account', { credentials: 'include' });
      if (!res.ok) {
        show('state-unauth');
        return;
      }
      const data = await res.json();
      document.getElementById('account-email').textContent = data.email;
      // The api-key is NOT rendered here, masked or otherwise. See the
      // "Advanced account key" block further down: on this page the key is a
      // legacy escape hatch behind a fold, and a page that prints it on load
      // fetches a credential for every visitor who only came to check what they
      // pay. data.api_key_masked is left unread on purpose.
      document.getElementById('plan').textContent = planName(data, data.plan);
      var planChip = document.getElementById('plan-chip');
      if (planChip) planChip.textContent = planName(data, data.plan);
      document.getElementById('label').textContent = data.label || '—';
      document.getElementById('created').textContent = paramantDate.day(data.created_at, 'Unknown');
      document.getElementById('backup-count').textContent = data.backup_codes_remaining;

      const sessionsList = document.getElementById('sessions-list');
      sessionsList.innerHTML = '';
      (data.sessions || []).forEach(function(s) {
        const el = document.createElement('div');
        el.className = 'info-row';
        // user_agent_short (and ip_masked) are attacker-controllable at login,
        // so build the nodes with textContent rather than innerHTML to avoid
        // self/stored DOM XSS.
        const labelEl = document.createElement('div');
        labelEl.className = 'info-label';
        labelEl.textContent = (s.ip_masked || '') + (s.current ? ' (this session)' : '');
        const valueEl = document.createElement('div');
        valueEl.className = 'info-value';
        valueEl.textContent = (s.user_agent_short || '') + ' · last seen ' + paramantDate.moment(s.last_seen);
        el.appendChild(labelEl);
        el.appendChild(valueEl);
        sessionsList.appendChild(el);
      });

      const expiresAt = new Date(data.session_expires_at);
      function updateTimer() {
        const ms = expiresAt - new Date();
        const min = Math.max(0, Math.ceil(ms / 60000));
        document.getElementById('session-timer').textContent =
          min > 60 ? Math.round(min / 60) + 'h' : min + 'm';
      }
      updateTimer();
      setInterval(updateTimer, 30000);

      show('state-account');
    } catch (err) {
      show('state-unauth');
    }
  }

  function _copyText(text) {
    // Try modern Clipboard API first; fall back to execCommand for Safari+VPN combos
    // that throw NotAllowedError even on user-initiated clicks.
    try {
      return navigator.clipboard.writeText(text).then(function(){ return true; }, function(){ return _copyTextFallback(text); });
    } catch (e) { return Promise.resolve(_copyTextFallback(text)); }
  }
  function _copyTextFallback(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none';
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
    return ok;
  }
  // ── The account key, behind the fold and only behind the fold ──────────────
  //
  // /account is the ONE page that may still put the pgp_ key in a browser: it
  // is the page whose job is to show it to you, for the SDK, a script or an IoT
  // device. Everything else on the site now authenticates to the relay with a
  // short-lived scoped pst_ token (relay/lib/session-token.js), and /pricing and
  // /dashboard stopped fetching this key entirely.
  //
  // So the fetch is tied to the "Advanced account key" fold, not to page load.
  // A visitor who opens /account to read their plan, their sessions or their
  // backup codes never causes a request to /api/user/account/key at all, and no
  // key, masked or whole, is in the DOM for them. Opening the fold is the
  // deliberate act that asks for it; from then on it is in this closure for the
  // life of the tab, which is what Copy and Show need and no longer than they
  // need it. tests/app-pages-no-api-key.test.mjs pins the load half of that.
  //
  // The masked form is computed HERE from the fetched key rather than read from
  // data.api_key_masked, because reading that field would mean the account
  // payload still had to carry a key shape to the page that promises not to
  // hold one until asked. Same shape as the server's mask (admin/server.js):
  // first eight, ellipsis, last four.
  var _keyPromise = null;
  function accountKey() {
    if (_keyPromise) return _keyPromise;
    _keyPromise = fetch('/api/user/account/key', {
      credentials: 'include', headers: { Accept: 'application/json' }, cache: 'no-store'
    }).then(function(res) {
      if (!res.ok) throw new Error('key_http_' + res.status);
      return res.json();
    }).then(function(data) {
      if (!data || !data.api_key) throw new Error('key_unavailable');
      return data.api_key;
    }).catch(function(err) {
      // A failed reveal must not poison the fold: the next Copy or Show tries
      // again rather than replaying the error forever.
      _keyPromise = null;
      throw err;
    });
    return _keyPromise;
  }

  function maskKey(key) {
    var k = String(key || '');
    return k.length > 12 ? k.slice(0, 8) + '...' + k.slice(-4) : k;
  }

  var advanced = document.getElementById('acct-advanced');
  var keyRowFilled = false;
  if (advanced) {
    advanced.addEventListener('toggle', function() {
      // Only on open, and only once it has really succeeded: a failed reveal
      // must leave the fold able to try again on the next open, and a
      // successful one must not overwrite a key the reader pressed Show on.
      if (!advanced.open || keyRowFilled) return;
      var el = document.getElementById('api-key');
      accountKey().then(function(key) {
        keyRowFilled = true;
        el.textContent = maskKey(key);
      }).catch(function() {
        el.textContent = 'Unavailable';
      });
    });
  }

  document.getElementById('copy-key').addEventListener('click', async function() {
    var btn = this;
    const original = btn.textContent;
    let key;
    try { key = await accountKey(); }
    catch (e) { btn.textContent = 'Failed'; setTimeout(function(){ btn.textContent = original; }, 2000); return; }
    const ok = await Promise.resolve(_copyText(key));
    if (ok) {
      btn.textContent = 'Copied!';
    } else {
      // Last-resort path for Safari/WebKit with VPN extensions that block writes entirely.
      // Show the key so the user can select + ⌘-C manually.
      document.getElementById('api-key').textContent = key;
      btn.textContent = 'Shown — ⌘-C';
    }
    setTimeout(function(){ btn.textContent = original; }, 2500);
  });

  document.getElementById('show-key').addEventListener('click', async function() {
    try {
      document.getElementById('api-key').textContent = await accountKey();
    } catch (e) {
      document.getElementById('api-key').textContent = 'Unavailable';
    }
  });

  document.getElementById('regen-backup').addEventListener('click', async function() {
    if (!confirm('Regenerate backup codes? Current codes will be invalid.')) return;
    const res = await fetch('/api/user/account/backup-codes/regenerate', {
      method: 'POST',
      credentials: 'include',
    });
    if (res.ok) {
      const data = await res.json();
      alert('New codes:\n\n' + data.backup_codes.join('\n') + '\n\nSave these now. They will not be shown again.');
    }
  });

  document.getElementById('reset-totp').addEventListener('click', async function() {
    if (!confirm('This will send a new setup email. Your current authenticator will be invalidated.')) return;
    const res = await fetch('/api/user/account/totp/reset', {
      method: 'POST',
      credentials: 'include',
    });
    if (res.ok) {
      alert('Setup email sent. Check your inbox.');
      window.location = '/auth/login';
    }
  });

  document.getElementById('sign-out').addEventListener('click', async function() {
    await fetch('/api/user/logout', { method: 'POST', credentials: 'include' });
    window.location = '/';
  });

  document.getElementById('sign-out-all').addEventListener('click', async function() {
    await fetch('/api/user/account/sessions/revoke-others', {
      method: 'POST',
      credentials: 'include',
    });
    alert('Other sessions signed out.');
    loadAccount();
  });

  document.getElementById('delete-account').addEventListener('click', async function() {
    const answer = prompt('Type DEACTIVATE to confirm account deactivation:');
    if (answer !== 'DEACTIVATE') return;
    const res = await fetch('/api/user/account', {
      method: 'DELETE',
      credentials: 'include',
    });
    if (res.ok) {
      alert('Account deactivated. Its key can no longer be used.');
      window.location = '/';
    }
  });


  // ── The end of the term that was bought ────────────────────────────────────
  // Every checkout here is a ONE-OFF payment for one month or one year, so the
  // date in paid_until_<product> is the day access stops and there is no
  // collection to announce or to cancel. Before this the account page said
  // "active" and nothing else, and the first sign a customer had that his term
  // was over was a refused signature.
  //
  // Two products can carry two different dates. The one that matters is the
  // nearest one still ahead, because that is the one that needs acting on; once
  // they have all passed it is the last one, because that is the day the
  // account fell back.
  var TERM_WARN_DAYS = 7;
  function termState(d, nowMs) {
    var now = typeof nowMs === 'number' ? nowMs : Date.now();
    var ends = [d.paid_until_parasign, d.paid_until_parasend]
      .map(function (v) { return v ? Date.parse(v) : NaN; })
      .filter(function (t) { return !isNaN(t); });
    if (!ends.length) return null;
    var ahead = ends.filter(function (t) { return t > now; });
    var at = ahead.length ? Math.min.apply(null, ahead) : Math.max.apply(null, ends);
    var days = (at - now) / 86400000;
    return { at: at, ended: at <= now, warn: days > 0 && days <= TERM_WARN_DAYS };
  }

  // One notation, from /js/format-date.js, and not the visitor's locale: the
  // site is in English and the same date has to read the same here, in the
  // invoice row below, and in the reminder mail.
  function termDate(at) {
    return paramantDate.day(at);
  }

  function renderTerm(d) {
    var term = termState(d);
    var line = document.getElementById('billing-term-line');
    var warn = document.getElementById('billing-term-warn');
    if (line) line.hidden = true;
    if (warn) warn.hidden = true;
    if (!term) return;
    var when = termDate(term.at);
    if (line) {
      line.textContent = term.ended
        ? 'Ended on ' + when + ', now on Community.'
        : 'Ends on ' + when + ', nothing renews automatically.';
      line.hidden = false;
    }
    if (warn && term.warn) {
      var text = warn.querySelector('[data-term="text"]');
      if (text) text.textContent = 'Your plan ends on ' + when + '. Renew for another month or year, or let it fall back to Community. Nothing is charged automatically.';
      warn.hidden = false;
    }
  }

  async function loadBilling() {
    try {
      const res = await fetch('/api/user/billing/status', { credentials: 'include' });
      if (!res.ok) { document.getElementById('billing-loading').textContent = 'Billing unavailable.'; return; }
      const d = await res.json();
      document.getElementById('billing-loading').style.display = 'none';
      document.getElementById('billing-content').classList.remove('hidden');

      const planEl = document.getElementById('billing-plan');
      planEl.textContent = planName(d, d.current_plan);
      // Paying is not one string. ParaSend's floor tier is 'community' and
      // ParaSign's is 'free' (relay/lib/entitlements.js), the API answers
      // 'standard' for a record with no plan at all, and a self-serve purchase
      // moves only its own product ladder while the unified plan stays on
      // community. Comparing against 'community' therefore both offered a free
      // account a Cancel button for a subscription it does not have, and hid
      // the badge from a customer who really was paying.
      const free = isFreeAccount(d, d.current_plan);
      if (!free) {
        document.getElementById('billing-active-badge').classList.remove('hidden');
        // A customer who pays gets a way to stop paying. What was wrong here was
        // never the button but the date behind it: cancel used to schedule the
        // downgrade at now plus 30 days, so someone who had bought a YEAR was
        // told his plan ended next month. It now schedules on the term he
        // actually paid for, the same date shown below.
        document.getElementById('billing-cancel-btn').classList.remove('hidden');
      }
      // One calm line about what this plan is. On Community it says whose gift
      // it is and what the paid plans add, with a single way up. On a paid plan
      // it says what was bought and stops there.
      const band = document.getElementById('billing-community');
      if (band) band.hidden = !free;
      const bought = document.getElementById('billing-paid');
      if (bought) bought.hidden = free;
      // access_until is the end of the term that was paid for and is the honest
      // date on a one-off; next_billing_date only means something once
      // something actually collects again.
      const until = d.access_until || d.next_billing_date;
      if (until) {
        document.getElementById('billing-next-row').style.display = 'flex';
        document.getElementById('billing-next').textContent = paramantDate.day(until);
        const note = document.getElementById('billing-renew-note');
        if (note) note.hidden = !!d.auto_renews;
      }
      renderTerm(d);
      if (d.cancellation_scheduled_at) {
        document.getElementById('billing-cancel-row').style.display = 'flex';
        document.getElementById('billing-cancel-date').textContent = 'Downgrade scheduled ' + paramantDate.day(d.cancellation_scheduled_at);
        document.getElementById('billing-cancel-btn').classList.add('hidden');
      }
    } catch(err) {
      document.getElementById('billing-loading').textContent = 'Could not load billing.';
    }
  }

  // ── Billing history ────────────────────────────────────────────────────────
  // One chronological list: every payment, every credit note, every term that
  // ended, and the admin plan changes that used to be the only thing here. The
  // API derives it from the invoice and credit-note records and from the paid
  // periods on them, so this renders what it is given and invents nothing.
  //
  // Built with DOM nodes rather than a string of markup: these rows carry a
  // document number, a description and an amount that all come from the server,
  // and this page has no business putting any of them through innerHTML.
  function historyLabel(e) {
    if (e.label) return e.label;
    // A row from an older API, or an event this page does not know by name. The
    // event name is not pretty, and it is at least true.
    if (e.event_type === 'plan_changed') {
      var m = e.metadata || {};
      return 'Plan changed from ' + (m.from || 'unknown') + ' to ' + (m.to || 'unknown');
    }
    if (e.event_type === 'plan_cancellation_scheduled') return 'Cancellation scheduled';
    return e.event_type || 'Billing event';
  }

  function historyRow(e) {
    const row = document.createElement('div');
    row.className = 'info-row';

    const left = document.createElement('div');
    left.className = 'info-label';
    left.appendChild(document.createTextNode(paramantDate.day(e.ts)));
    left.appendChild(document.createTextNode(' · ' + historyLabel(e)));
    if (e.document) {
      const num = document.createElement('span');
      num.style.fontFamily = 'var(--mono)';
      num.textContent = ' ' + e.document;
      left.appendChild(num);
    }

    const right = document.createElement('div');
    right.className = 'info-value';
    if (e.amount) {
      const amount = document.createElement('span');
      amount.style.fontFamily = 'var(--mono)';
      amount.textContent = (e.currency || 'EUR') + ' ' + e.amount;
      right.appendChild(amount);
    } else if (e.detail) {
      right.appendChild(document.createTextNode(e.detail));
    }
    if (e.document) {
      right.appendChild(document.createTextNode(' '));
      const link = document.createElement('a');
      link.href = '/api/user/billing/invoices/' + encodeURIComponent(e.document) + '.pdf';
      link.textContent = 'Download PDF';
      right.appendChild(link);
    }
    row.appendChild(left);
    row.appendChild(right);
    return row;
  }

  async function loadBillingHistory() {
    const histEl = document.getElementById('billing-history');
    if (!histEl) return;
    try {
      const res = await fetch('/api/user/billing/history', { credentials: 'include' });
      if (!res.ok) { histEl.textContent = 'Billing history unavailable right now.'; return; }
      const d = await res.json();
      const rows = (d && d.history) || [];
      if (rows.length === 0) { histEl.textContent = 'No billing events yet.'; return; }
      histEl.textContent = '';
      rows.forEach(function(e) { histEl.appendChild(historyRow(e)); });
    } catch(err) {
      histEl.textContent = 'Could not load billing history.';
    }
  }

  document.getElementById('billing-cancel-btn').addEventListener('click', async function() {
    if (!confirm('Cancel your plan? You keep access until the end of your billing period.')) return;
    const res = await fetch('/api/user/billing/cancel', { method: 'POST', credentials: 'include' });
    if (res.ok) {
      const d = await res.json();
      alert('Cancellation scheduled. Your plan downgrades on ' + paramantDate.day(d.scheduled_downgrade_at));
      loadBilling();
    }
  });

  // ── Invoices ───────────────────────────────────────────────────────────────
  // One row per document the relay issued: number, date, total, download. The
  // list is the record, so it is never edited here and nothing is ever removed
  // from it; a reversed document keeps its row and says it was reversed.
  async function loadInvoices() {
    const el = document.getElementById('billing-invoices');
    if (!el) return;
    try {
      const res = await fetch('/api/user/billing/invoices', { credentials: 'include' });
      if (!res.ok) { el.textContent = 'Invoices unavailable right now.'; return; }
      const d = await res.json();
      const rows = (d && d.invoices) || [];
      if (rows.length === 0) { el.textContent = 'No invoices yet. One is issued for every payment.'; return; }
      el.textContent = '';
      rows.forEach(function(inv) {
        const row = document.createElement('div');
        row.className = 'info-row';
        const left = document.createElement('div');
        left.className = 'info-label';
        const num = document.createElement('span');
        num.style.fontFamily = 'var(--mono)';
        num.textContent = inv.number;
        left.appendChild(num);
        left.appendChild(document.createTextNode(' · ' + paramantDate.day(inv.date)));
        // Three shapes in one list. A credit note is not a receipt and must not
        // be labelled as one: it is the document that gives money back, and it
        // says which invoice it belongs to.
        if (inv.kind === 'credit_note') {
          left.appendChild(document.createTextNode(
            ' · ' + (inv.partial ? 'partial credit for ' : 'credit for ') + inv.credit_for));
        } else if (inv.kind !== 'invoice') {
          left.appendChild(document.createTextNode(' · receipt'));
        }
        if (inv.reversed_at) left.appendChild(document.createTextNode(' · reversed'));
        const right = document.createElement('div');
        right.className = 'info-value';
        const amount = document.createElement('span');
        amount.style.fontFamily = 'var(--mono)';
        amount.textContent = inv.currency + ' ' + inv.amount_gross;
        right.appendChild(amount);
        right.appendChild(document.createTextNode(' '));
        const link = document.createElement('a');
        link.href = '/api/user/billing/invoices/' + encodeURIComponent(inv.number) + '.pdf';
        link.textContent = 'Download PDF';
        right.appendChild(link);
        row.appendChild(left);
        row.appendChild(right);
        el.appendChild(row);
      });
    } catch (err) {
      el.textContent = 'Could not load invoices.';
    }
  }

  // ── Company details ────────────────────────────────────────────────────────
  // Optional, and stated as optional: an account with none of these still gets
  // a document, addressed to its email. Only documents issued AFTER a save
  // carry the new details, which is why the page says so rather than implying
  // that saving fixes an invoice already in the customer's bookkeeping.
  async function loadBillingProfile() {
    const form = document.getElementById('billing-profile-form');
    if (!form) return;
    try {
      const res = await fetch('/api/user/billing/profile', { credentials: 'include' });
      if (!res.ok) return;
      const d = await res.json();
      document.getElementById('billing-company').value = d.company || '';
      document.getElementById('billing-address').value = d.address || '';
      document.getElementById('billing-vat').value = d.vat || '';
    } catch (err) {}
  }

  const profileForm = document.getElementById('billing-profile-form');
  if (profileForm) {
    profileForm.addEventListener('submit', async function(ev) {
      ev.preventDefault();
      const msg = document.getElementById('billing-profile-msg');
      const btn = document.getElementById('billing-profile-save');
      btn.disabled = true;
      msg.textContent = 'Saving...';
      try {
        const res = await fetch('/api/user/billing/profile', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            company: document.getElementById('billing-company').value,
            address: document.getElementById('billing-address').value,
            vat: document.getElementById('billing-vat').value,
          }),
        });
        msg.textContent = res.ok
          ? 'Saved. New invoices will carry these details.'
          : 'Could not save. Try again.';
      } catch (err) {
        msg.textContent = 'Could not save. Try again.';
      }
      btn.disabled = false;
    });
  }

  // A redeemed code changes the plan and the term on this very page, so the two
  // blocks that show them are read again rather than left saying what was true
  // before the click. js/redeem-code.js fires this once the relay has
  // confirmed the grant; a browser that cannot make a CustomEvent simply keeps
  // the old block and the success sentence, which already names the plans and
  // the dates.
  document.addEventListener('paramant:plan-changed', function() {
    loadBilling();
    loadBillingHistory();
  });

  loadAccount();
  loadBilling();
  loadBillingHistory();
  loadInvoices();
  loadBillingProfile();
})();
