
(function() {
  async function initUpgrade() {
    let session = null;
    try {
      const r = await fetch('/api/user/session/verify', { credentials: 'include' });
      if (r.ok) session = await r.json();
    } catch(e) {}

    function showPricingError(msg) {
      const el = document.getElementById('pricing-error');
      if (el) { el.textContent = msg; el.style.display = 'block'; }
    }

    function doUpgrade(period) {
      return async function(e) {
        e.preventDefault();
        if (!session || !session.authenticated) {
          window.location = '/auth/login?return=/pricing';
          return;
        }
        try {
          const r = await fetch('/api/user/billing/checkout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ plan_id: 'pro', period }),
          });
          if (r.ok) {
            const d = await r.json();
            window.location = d.checkout_url;
          } else {
            showPricingError('Could not start checkout. Please try again.');
          }
        } catch(e) {
          showPricingError('Network error. Please try again.');
        }
      };
    }

    const btnM = document.getElementById('upgrade-pro-monthly');
    const btnY = document.getElementById('upgrade-pro-yearly');
    const note = document.getElementById('pro-login-note');
    if (session && session.authenticated) {
      if (btnM) btnM.addEventListener('click', doUpgrade('monthly'));
      if (btnY) btnY.addEventListener('click', doUpgrade('yearly'));
    } else {
      if (note) note.style.display = 'block';
      if (btnM) { btnM.href = '/auth/login?return=/pricing'; btnM.removeAttribute('id'); }
      if (btnY) { btnY.href = '/auth/login?return=/pricing'; btnY.removeAttribute('id'); }
    }
  }
  initUpgrade();
})();
