(function() {
  const token = location.pathname.split('/billing/checkout/')[1];
  if (!token) { document.getElementById('state-loading').style.display = 'none'; document.getElementById('state-error').style.display = 'block'; return; }

  async function load() {
    try {
      const res = await fetch('/api/user/billing/checkout/' + token, { credentials: 'include' });
      if (!res.ok) { showError(); return; }
      const d = await res.json();
      document.getElementById('plan-badge').textContent = d.plan_name;
      document.getElementById('plan-name').textContent = d.plan_name;
      document.getElementById('plan-period').textContent = d.period === 'yearly' ? 'Yearly' : 'Monthly';
      document.getElementById('plan-email').textContent = d.email;
      document.getElementById('plan-amount').textContent = d.amount_eur === 0 ? 'Free' : ('€' + d.amount_eur + (d.period === 'yearly' ? '/yr' : '/mo'));
      document.getElementById('state-loading').style.display = 'none';
      document.getElementById('state-checkout').style.display = 'block';
    } catch(e) { showError(); }
  }

  function showError() {
    document.getElementById('state-loading').style.display = 'none';
    document.getElementById('state-error').style.display = 'block';
  }

  document.getElementById('confirm-btn').addEventListener('click', async function() {
    const btn = this;
    btn.disabled = true;
    btn.textContent = 'Processing…';
    document.getElementById('confirm-error').style.display = 'none';
    try {
      const res = await fetch('/api/user/billing/checkout/' + token + '/confirm', {
        method: 'POST',
        credentials: 'include',
      });
      if (res.ok) {
        window.location = '/account';
      } else {
        const d = await res.json();
        document.getElementById('confirm-error').textContent = d.error || 'Confirm failed. Try again.';
        document.getElementById('confirm-error').style.display = 'block';
        btn.disabled = false;
        btn.textContent = 'Confirm upgrade';
      }
    } catch(e) {
      document.getElementById('confirm-error').textContent = 'Network error. Try again.';
      document.getElementById('confirm-error').style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Confirm upgrade';
    }
  });

  load();
})();
