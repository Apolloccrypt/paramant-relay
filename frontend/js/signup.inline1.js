
(function() {
  const form = document.getElementById('signup-form');
  const errorDiv = document.getElementById('error');
  const submitBtn = document.getElementById('submit-btn');
  const step2 = document.getElementById('step2');

  // Shared signup call: invisible PoW, then POST. Throws {kind,...} on failure;
  // callers own their own button/status so both the email form and the Step-2
  // "resend" reuse it. dpa_accepted is true because continuing IS the agreement
  // (the DPA is a line-with-link now, not a blocking checkbox).
  async function doSignup(email, label, onProgress) {
    let proof;
    try { proof = await ParamantCaptcha.getCaptchaProof(onProgress || function(){}); }
    catch (_) { throw { kind: 'captcha' }; }
    const res = await fetch('/api/user/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, label, dpa_accepted: true, challenge_id: proof.challenge_id, nonce: proof.nonce }),
    });
    if (!res.ok) { const err = await res.json().catch(() => ({})); throw { kind: 'http', status: res.status, err }; }
  }

  function showError(e) {
    if (e && e.kind === 'captcha') { errorDiv.textContent = 'Verification failed. Please try again.'; }
    else if (e && e.kind === 'http') {
      if (e.status === 403) errorDiv.textContent = 'Verification failed. Please refresh and try again.';
      else if (e.status === 409) errorDiv.innerHTML = 'An account with this email already exists. <a href="/auth/login">Sign in</a>.';
      else if (e.status === 422) errorDiv.textContent = 'This email domain is not accepted. Please use a real email address.';
      else if (e.status === 429) errorDiv.textContent = 'Too many attempts. Please try again later.';
      else errorDiv.textContent = (e.err && e.err.message) || 'Something went wrong. Please try again.';
    } else { errorDiv.textContent = 'Network error. Please check your connection.'; }
    errorDiv.classList.add('visible');
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorDiv.classList.remove('visible');
    const email = document.getElementById('email').value.trim();
    const label = document.getElementById('label').value.trim();
    if (!email) { errorDiv.textContent = 'Please enter your email address.'; errorDiv.classList.add('visible'); return; }
    submitBtn.disabled = true;
    submitBtn.textContent = 'Verifying…';
    try {
      await doSignup(email, label, n => { submitBtn.textContent = 'Verifying… (' + (n / 1000).toFixed(0) + 'k)'; });
      document.getElementById('step2-email').textContent = email;
      form.style.display = 'none';
      step2.hidden = false;
      step2.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e2) {
      showError(e2);
      submitBtn.disabled = false;
      submitBtn.textContent = 'Continue';
    }
  });

  const resendBtn = document.getElementById('resend-btn');
  if (resendBtn) resendBtn.addEventListener('click', async () => {
    const status = document.getElementById('resend-status');
    const email = document.getElementById('email').value.trim();
    if (!email) return;
    resendBtn.disabled = true;
    status.style.color = ''; status.textContent = 'Sending…';
    try { await doSignup(email, document.getElementById('label').value.trim()); status.textContent = 'Sent. Check your inbox again.'; }
    catch (_) { status.style.color = 'var(--danger, #b91c1c)'; status.textContent = 'Could not resend. Try again in a moment.'; }
    finally { resendBtn.disabled = false; }
  });
})();
