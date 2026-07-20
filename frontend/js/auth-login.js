(function() {
  const form = document.getElementById('login-form');
  const errorDiv = document.getElementById('error');
  const submitBtn = document.getElementById('submit-btn');

  const params = new URLSearchParams(window.location.search);
  // Honour both the nginx gate's ?next= and legacy ?return= links. Local paths
  // only (leading single slash, no // or /\) so it can't become an open redirect.
  const _rv = params.get('next') || params.get('return') || '/dashboard';
  const returnUrl = /^\/(?![\/\\])/.test(_rv) ? _rv : '/dashboard';

  // Non-blocking, dismissible note shown after a successful login when the account's
  // authenticator app produced a SHA-1 code (accepted via dual-verify). Login already
  // succeeded (the session cookie is set); this only nudges toward a SHA-256 app
  // before continuing. It never blocks the sign-in.
  function showSha1Notice(dest) {
    const notice = document.getElementById('sha1-notice');
    if (!notice) { window.location = dest; return; }
    if (form) form.hidden = true;
    if (errorDiv) errorDiv.classList.remove('visible');
    notice.hidden = false;
    const cont = document.getElementById('sha1-continue');
    if (cont) {
      cont.setAttribute('href', dest);
      cont.addEventListener('click', function(ev) { ev.preventDefault(); window.location = dest; });
    }
  }

  form.addEventListener('submit', async function(e) {
    e.preventDefault();
    errorDiv.classList.remove('visible');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Signing in...';

    const email = document.getElementById('email').value.trim();
    const totp = document.getElementById('totp').value.trim();

    try {
      const res = await fetch('/api/user/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, totp }),
        credentials: 'include',
      });

      if (res.ok) {
        // Login succeeded. If the authenticator app used a SHA-1 code, show a
        // soft, dismissible note before continuing; otherwise redirect as before.
        let body = null;
        try { body = await res.json(); } catch (_) { /* non-JSON, ignore */ }
        if (body && body.totp_algorithm === 'sha1') { showSha1Notice(returnUrl); return; }
        window.location = returnUrl;
      } else if (res.status === 401) {
        errorDiv.textContent = 'Invalid email or code.';
        errorDiv.classList.add('visible');
        document.getElementById('totp').value = '';
        document.getElementById('totp').focus();
      } else if (res.status === 403) {
        errorDiv.innerHTML = 'No authenticator linked to this account. <a href="/auth/request-reset">Request a setup link</a> or <a href="/signup">create an account</a>.';
        errorDiv.classList.add('visible');
      } else if (res.status === 429) {
        errorDiv.textContent = 'Too many attempts. Try again in 15 minutes.';
        errorDiv.classList.add('visible');
      } else {
        errorDiv.textContent = 'Sign-in failed. Please try again.';
        errorDiv.classList.add('visible');
      }
    } catch (err) {
      errorDiv.textContent = 'Network error.';
      errorDiv.classList.add('visible');
    }

    submitBtn.disabled = false;
    submitBtn.textContent = 'Sign in';
  });

  // Progressive disclosure: the 6-digit code field stays hidden until the user
  // chooses the code path, so the default view is just "email + pick a method".
  const showCodeBtn = document.getElementById('show-code-btn');
  const codeFields = document.getElementById('code-fields');
  if (showCodeBtn && codeFields) {
    showCodeBtn.addEventListener('click', function() {
      codeFields.hidden = false;
      showCodeBtn.hidden = true;
      showCodeBtn.setAttribute('aria-expanded', 'true');
      const t = document.getElementById('totp');
      if (t) t.focus();
    });
  }
})();
