
(function() {
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
      document.getElementById('plan').textContent = data.plan;
      var planChip = document.getElementById('plan-chip');
      if (planChip) planChip.textContent = data.plan;
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
      planEl.textContent = d.current_plan.charAt(0).toUpperCase() + d.current_plan.slice(1);
      if (d.current_plan !== 'community') {
        document.getElementById('billing-active-badge').classList.remove('hidden');
        document.getElementById('billing-cancel-btn').classList.remove('hidden');
      }
      if (d.next_billing_date) {
        document.getElementById('billing-next-row').style.display = 'flex';
        document.getElementById('billing-next').textContent = new Date(d.next_billing_date).toLocaleDateString();
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

  loadAccount();
  loadBilling();
  loadBillingHistory();
})();
