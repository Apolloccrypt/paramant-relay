(function() {
  const token = window.location.pathname.split('/').pop();
  const confirmBtn = document.getElementById('confirm-btn');
  const errorDiv = document.getElementById('error');

  if (!token || token === 'reset-confirm') {
    document.getElementById('initial-view').innerHTML =
      '<p class="form-subtitle" style="color:#dc2626">Invalid link. Please request a new reset.</p>' +
      '<p class="footer-text mt-4"><a href="/auth/request-reset">Request a reset link</a></p>';
    return;
  }

  confirmBtn.addEventListener('click', async function() {
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Processing...';
    errorDiv.classList.remove('visible');

    try {
      const res = await fetch('/api/user/auth/reset-confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
        credentials: 'include',
      });

      const data = await res.json().catch(() => ({}));

      if (res.ok) {
        document.getElementById('initial-view').style.display = 'none';
        document.getElementById('success-view').style.display = '';
      } else if (res.status === 401) {
        document.getElementById('initial-view').style.display = 'none';
        document.getElementById('expired-view').style.display = '';
      } else {
        errorDiv.textContent = 'Error: ' + (data.error || 'unknown error. Try again.');
        errorDiv.classList.add('visible');
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Yes, reset my authenticator';
      }
    } catch (err) {
      errorDiv.textContent = 'Network error. Please try again.';
      errorDiv.classList.add('visible');
      confirmBtn.disabled = false;
      confirmBtn.textContent = 'Yes, reset my authenticator';
    }
  });
})();
