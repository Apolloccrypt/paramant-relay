(function() {
  const form = document.getElementById('reset-form');
  const errorDiv = document.getElementById('error');
  const successDiv = document.getElementById('success');
  const submitBtn = document.getElementById('submit-btn');

  form.addEventListener('submit', async function(e) {
    e.preventDefault();
    errorDiv.classList.remove('visible');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Sending...';

    const email = document.getElementById('email').value.trim();

    try {
      // Solve PoW challenge
      let proof;
      try {
        submitBtn.textContent = 'Verifying…';
        proof = await ParamantCaptcha.getCaptchaProof();
      } catch (_) {
        errorDiv.textContent = 'The browser check did not finish. It runs on this device and takes a few seconds. Try again.';
        errorDiv.classList.add('visible');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Send reset link';
        return;
      }

      const res = await fetch('/api/user/auth/request-totp-reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, challenge_id: proof.challenge_id, nonce: proof.nonce }),
        credentials: 'include',
      });

      if (res.ok) {
        form.style.display = 'none';
        successDiv.style.display = 'block';
        successDiv.innerHTML = '<p>If an account exists for <strong>' + email + '</strong>, a setup link is on its way. Look in your inbox, and in the spam folder. The sender is noreply@paramant.app.</p><p style="margin-top:8px">The link works for 14 days. We do not say whether the address is registered, so this message looks the same either way.</p>';
      } else {
        errorDiv.textContent = 'We could not send the link. Nothing changed on your account. Try again, or mail privacy@paramant.app.';
        errorDiv.classList.add('visible');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Send reset link';
      }
    } catch (err) {
      errorDiv.textContent = 'We could not reach Paramant. Check your connection and try again.';
      errorDiv.classList.add('visible');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Send reset link';
    }
  });
})();
