(function() {
  const form = document.getElementById('backup-form');
  const errorDiv = document.getElementById('error');

  form.addEventListener('submit', async function(e) {
    e.preventDefault();
    errorDiv.classList.remove('visible');

    const email = document.getElementById('email').value.trim();
    const code = document.getElementById('code').value.trim().toUpperCase();

    const res = await fetch('/api/user/login-with-backup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, backup_code: code }),
      credentials: 'include',
    });

    if (res.ok) {
      window.location = '/dashboard';
    } else {
      errorDiv.textContent = 'Invalid email or backup code.';
      errorDiv.classList.add('visible');
    }
  });
})();
