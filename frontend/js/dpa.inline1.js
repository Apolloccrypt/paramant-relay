
(function () {
  var consent = document.getElementById('sig-consent');
  var btn = document.getElementById('signBtn');

  consent.addEventListener('change', function () { btn.disabled = !this.checked; });

  btn.addEventListener('click', async function () {
    var name  = document.getElementById('sig-name').value.trim();
    var title = document.getElementById('sig-title').value.trim();
    var org   = document.getElementById('sig-org').value.trim();
    var kvk   = document.getElementById('sig-kvk').value.trim();
    var email = document.getElementById('sig-email').value.trim();
    var errBox = document.getElementById('errorBox');

    errBox.style.display = 'none';
    if (!name || !org || !email) { showError('Name, organisation, and email are required.'); return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { showError('Please enter a valid email address.'); return; }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Signing&hellip;';

    try {
      var r = await fetch('/api/sign-dpa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, title, org, kvk, email,
          signed_at: new Date().toISOString(), version: '2025-01-01' })
      });
      var d = await r.json();
      if (r.ok && d.ok) {
        document.getElementById('refNumber').textContent = 'Reference: ' + d.ref;
        document.getElementById('sigEmailDisplay').textContent = email;
        document.getElementById('successBox').style.display = 'block';
        btn.style.display = 'none';
        consent.disabled = true;
      } else {
        showError(d.error || 'Something went wrong. Please try again or email privacy@paramant.app.');
        btn.disabled = false;
        btn.textContent = 'Sign agreement';
      }
    } catch (e) {
      showError('Network error. Please check your connection and try again.');
      btn.disabled = false;
      btn.textContent = 'Sign agreement';
    }
  });

  function showError(msg) {
    var b = document.getElementById('errorBox');
    b.textContent = msg;
    b.style.display = 'block';
  }
}());
