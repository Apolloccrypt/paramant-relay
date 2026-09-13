(function() {
  const form = document.getElementById('backup-form');
  const errorDiv = document.getElementById('error');
  const emailInput = document.getElementById('email');
  const codeInput = document.getElementById('code');
  const submitBtn = form.querySelector('button[type="submit"]');

  function fail(message) {
    errorDiv.textContent = message;
    errorDiv.classList.add('visible');
  }

  // This page is reached from the sign-in page, where the visitor has usually
  // already typed their address. Carry it over so they do not type it twice on
  // the one page they only open when their phone is gone. Missing value is not
  // an error: the field simply stays empty and keeps the focus.
  try {
    const remembered = sessionStorage.getItem('paramant:recovery-email');
    if (remembered && !emailInput.value) emailInput.value = remembered;
  } catch (_) { /* private mode, or storage blocked: no prefill, no problem */ }

  if (emailInput.value) codeInput.focus();
  else emailInput.focus();

  form.addEventListener('submit', async function(e) {
    e.preventDefault();
    errorDiv.classList.remove('visible');

    const email = emailInput.value.trim();
    const code = codeInput.value.trim().toUpperCase();

    // Say what is missing in the page itself. The browser's own bubble for a
    // `required` field disappears on the next tap and is easy to miss on a
    // phone, which left the button looking dead: pressing it did nothing and
    // nothing explained why.
    if (!email) { fail('Fill in the email address of your account first.'); emailInput.focus(); return; }
    if (!code) { fail('Fill in one of the backup codes you saved.'); codeInput.focus(); return; }

    submitBtn.disabled = true;
    const originalLabel = submitBtn.textContent;
    submitBtn.textContent = 'Signing in...';

    let res;
    try {
      res = await fetch('/api/user/login-with-backup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, backup_code: code }),
        credentials: 'include',
      });
    } catch (_) {
      submitBtn.disabled = false;
      submitBtn.textContent = originalLabel;
      fail('We could not reach Paramant. Check your connection and try again.');
      return;
    }

    if (res.ok) {
      try { sessionStorage.removeItem('paramant:recovery-email'); } catch (_) {}
      window.location = '/dashboard';
      return;
    }

    submitBtn.disabled = false;
    submitBtn.textContent = originalLabel;
    if (res.status === 429) {
      fail('Too many attempts. Wait a few minutes and try again.');
    } else {
      fail('That email and backup code do not match. Each code works once, so check you are not reusing one you already used.');
    }
  });
})();
