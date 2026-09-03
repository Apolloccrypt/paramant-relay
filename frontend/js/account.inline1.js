
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
      document.getElementById('api-key').textContent = data.api_key_masked;
      document.getElementById('plan').textContent = planName(data, data.plan);
      var planChip = document.getElementById('plan-chip');
      if (planChip) planChip.textContent = planName(data, data.plan);
      document.getElementById('label').textContent = data.label || '—';
      document.getElementById('created').textContent = data.created_at ? new Date(data.created_at).toLocaleDateString() : 'Unknown';
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
        valueEl.textContent = (s.user_agent_short || '') + ' · last seen ' + new Date(s.last_seen).toLocaleString();
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
  document.getElementById('copy-key').addEventListener('click', async function() {
    var btn = this;
    const res = await fetch('/api/user/account/key', { credentials: 'include' });
    if (!res.ok) { btn.textContent = 'Failed'; setTimeout(function(){ btn.textContent = 'Copy'; }, 2000); return; }
    const data = await res.json();
    const original = btn.textContent;
    const ok = await Promise.resolve(_copyText(data.api_key));
    if (ok) {
      btn.textContent = 'Copied!';
    } else {
      // Last-resort path for Safari/WebKit with VPN extensions that block writes entirely.
      // Show the key so the user can select + ⌘-C manually.
      document.getElementById('api-key').textContent = data.api_key;
      btn.textContent = 'Shown — ⌘-C';
    }
    setTimeout(function(){ btn.textContent = original; }, 2500);
  });

  document.getElementById('show-key').addEventListener('click', async function() {
    const res = await fetch('/api/user/account/key', { credentials: 'include' });
    if (res.ok) {
      const data = await res.json();
      document.getElementById('api-key').textContent = data.api_key;
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
        // Cancel stops a NEXT collection. With auto_renews false there is no
        // next collection to stop, and offering the button anyway scheduled a
        // downgrade on a date nobody had bought, so the term end below is the
        // whole answer. The button returns the day recurring billing is on.
        if (d.auto_renews) document.getElementById('billing-cancel-btn').classList.remove('hidden');
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
        document.getElementById('billing-next').textContent = new Date(until).toLocaleDateString();
        const note = document.getElementById('billing-renew-note');
        if (note) note.hidden = !!d.auto_renews;
      }
      if (d.cancellation_scheduled_at) {
        document.getElementById('billing-cancel-row').style.display = 'flex';
        document.getElementById('billing-cancel-date').textContent = 'Downgrade scheduled ' + new Date(d.cancellation_scheduled_at).toLocaleDateString();
        document.getElementById('billing-cancel-btn').classList.add('hidden');
      }
    } catch(err) {
      document.getElementById('billing-loading').textContent = 'Could not load billing.';
    }
  }

  async function loadBillingHistory() {
    try {
      const res = await fetch('/api/user/billing/history', { credentials: 'include' });
      if (!res.ok) return;
      const d = await res.json();
      const histEl = document.getElementById('billing-history');
      if (!d.history || d.history.length === 0) { histEl.textContent = 'No billing events yet.'; return; }
      histEl.innerHTML = d.history.map(function(e) {
        const date = new Date(e.ts).toLocaleString();
        const label = e.event_type === 'plan_changed'
          ? 'Plan changed: ' + (e.metadata.from || '?') + ' → ' + (e.metadata.to || '?')
          : e.event_type === 'plan_cancellation_scheduled'
          ? 'Cancellation scheduled'
          : e.event_type;
        return '<div class="info-row"><div class="info-label">' + date + '</div><div class="info-value">' + label + '</div></div>';
      }).join('');
    } catch(err) {}
  }

  document.getElementById('billing-cancel-btn').addEventListener('click', async function() {
    if (!confirm('Cancel your plan? You keep access until the end of your billing period.')) return;
    const res = await fetch('/api/user/billing/cancel', { method: 'POST', credentials: 'include' });
    if (res.ok) {
      const d = await res.json();
      alert('Cancellation scheduled. Your plan downgrades on ' + new Date(d.scheduled_downgrade_at).toLocaleDateString());
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
        left.appendChild(document.createTextNode(' · ' + new Date(inv.date).toLocaleDateString()));
        if (inv.kind !== 'invoice') left.appendChild(document.createTextNode(' · receipt'));
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

  loadAccount();
  loadBilling();
  loadBillingHistory();
  loadInvoices();
  loadBillingProfile();
})();
