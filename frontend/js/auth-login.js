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

  // One sign-in POST. `proof`, when present, is a solved proof-of-work; the
  // server asks for one only after this address has failed often enough.
  function postLogin(email, totp, proof) {
    const body = { email: email, totp: totp };
    if (proof) { body.challenge_id = proof.challenge_id; body.nonce = proof.nonce; }
    return fetch('/api/user/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'include',
    });
  }

  form.addEventListener('submit', async function(e) {
    e.preventDefault();
    errorDiv.classList.remove('visible');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Signing in...';

    const email = document.getElementById('email').value.trim();
    const totp = document.getElementById('totp').value.trim();

    try {
      let res = await postLogin(email, totp, null);

      // 428: this address has collected enough failed sign-ins that the next
      // attempt has to carry a proof-of-work. It is a price, not a refusal, so
      // pay it here and post again. Nobody is locked out by it; the only cost
      // is the second or two the challenge takes.
      if (res.status === 428) {
        submitBtn.textContent = 'Verifying...';
        let proof = null;
        try { proof = await ParamantCaptcha.getCaptchaProof(); } catch (_) { proof = null; }
        if (proof) res = await postLogin(email, totp, proof);
      }

      if (res.ok) {
        // Login succeeded. If the authenticator app used a SHA-1 code, show a
        // soft, dismissible note before continuing; otherwise redirect as before.
        let body = null;
        try { body = await res.json(); } catch (_) { /* non-JSON, ignore */ }
        if (body && body.totp_algorithm === 'sha1') { showSha1Notice(returnUrl); return; }
        window.location = returnUrl;
      } else if (res.status === 401) {
        errorDiv.textContent = 'That email and code do not match. Codes change every 30 seconds, so use the one your app is showing right now.';
        errorDiv.classList.add('visible');
        document.getElementById('totp').value = '';
        document.getElementById('totp').focus();
      } else if (res.status === 403) {
        errorDiv.innerHTML = 'This account has no authenticator app linked to it yet. <a href="/auth/request-reset">Email me a setup link</a>, or <a href="/signup">create an account</a>.';
        errorDiv.classList.add('visible');
      } else if (res.status === 428) {
        errorDiv.textContent = 'We could not run the extra verification this sign-in needs. Refresh the page and try again.';
        errorDiv.classList.add('visible');
      } else if (res.status === 429) {
        errorDiv.textContent = 'Too many sign-in attempts from this internet connection. Sign-in from here is paused for up to 15 minutes. The limit counts the connection, not your account, so someone else on your network can set it off, and nobody can trigger it by guessing at your email address.';
        errorDiv.classList.add('visible');
      } else if (res.status === 503) {
        errorDiv.textContent = 'Sign-in is temporarily unavailable. Nothing is wrong with your account or your code. Try again in a few minutes.';
        errorDiv.classList.add('visible');
      } else {
        errorDiv.textContent = 'Sign-in did not go through. Nothing changed on your account. Try again in a moment.';
        errorDiv.classList.add('visible');
      }
    } catch (err) {
      errorDiv.textContent = 'We could not reach Paramant. Check your connection and try again.';
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
