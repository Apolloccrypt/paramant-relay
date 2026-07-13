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
        errorDiv.textContent = 'Verification failed. Please try again.';
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
        successDiv.innerHTML = '<p>If an account exists for <strong>' + email + '</strong>, a setup link has been sent. Check your inbox (and spam folder).</p><p style="margin-top:8px">The link is valid for 14 days.</p>';
      } else {
        errorDiv.textContent = 'Request failed. Try again or contact privacy@paramant.app.';
        errorDiv.classList.add('visible');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Send reset link';
      }
    } catch (err) {
      errorDiv.textContent = 'Network error.';
      errorDiv.classList.add('visible');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Send reset link';
    }
  });
})();
