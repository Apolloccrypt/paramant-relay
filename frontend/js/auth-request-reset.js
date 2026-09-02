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
        successDiv.innerHTML = '<p>If an account exists for <strong>' + email + '</strong>, a confirmation email is on its way. Look in your inbox, and in the spam folder. The sender is noreply@paramant.app.</p><p style="margin-top:8px">That first mail only confirms the request, and its link is valid for 60 minutes. Once you open it, we send the second mail with the link that links a new authenticator app; that one works for 14 days.</p><p style="margin-top:8px">We do not say whether the address is registered, so this message looks the same either way.</p>';
      } else if (res.status === 429) {
        // server.js returns retry_after 86400 here: 5 requests per address per
        // 24 hours, 10 per connection per hour. Telling the reader to try again
        // hides a wait that can run to a full day, so the button stays disabled
        // and the message says how long the wait can be.
        errorDiv.textContent = 'Too many reset requests. An address can ask five times a day and a connection ten times an hour, so this can take up to 24 hours to clear. If you are locked out and cannot wait, mail privacy@paramant.app.';
        errorDiv.classList.add('visible');
        submitBtn.textContent = 'Send reset link';
      } else {
        errorDiv.textContent = 'We could not send the mail. Nothing changed on your account. Try again, or mail privacy@paramant.app.';
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
