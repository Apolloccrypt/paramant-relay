// One file, two languages: the Dutch page and its English copy under /en/ load
// this same script, and <html lang> says which of the two strings to show.
function nlEn(nl, en) { return /^en\b/i.test(document.documentElement.lang || '') ? en : nl; }
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
      window.location = nlEn('/dashboard', '/en/dashboard');
    } else {
      errorDiv.textContent = nlEn('Dit e-mailadres en deze back-upcode horen niet bij elkaar. Elke code werkt maar één keer. Kijk of u deze code al eerder hebt gebruikt.', 'That email and backup code do not match. Each code works only once. Check whether you used this one before.');
      errorDiv.classList.add('visible');
    }
  });
})();
