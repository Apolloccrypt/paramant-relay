// One file, two languages: the Dutch page and its English copy under /en/ load
// this same script, and <html lang> says which of the two strings to show.
function nlEn(nl, en) { return /^en\b/i.test(document.documentElement.lang || '') ? en : nl; }
(function() {
  const token = window.location.pathname.split('/').pop();
  // The language switch names the page, not the link in the mail: carry the
  // token across so the other language opens the same setup.
  const langSwitch = document.querySelector('.lang-switch a');
  if (langSwitch && token && token !== 'reset-confirm') {
    langSwitch.setAttribute('href', langSwitch.getAttribute('href') + '/' + encodeURIComponent(token));
  }
  const confirmBtn = document.getElementById('confirm-btn');
  const errorDiv = document.getElementById('error');

  if (!token || token === 'reset-confirm') {
    document.getElementById('initial-view').innerHTML =
      nlEn('<p class="form-subtitle is-bad">Deze link is onvolledig, dus wij kunnen niet zien bij welk account hij hoort. Mailprogramma\'s verdelen een lange link soms over twee regels.</p>', '<p class="form-subtitle is-bad">This link is incomplete, so we cannot tell which account it belongs to. Mail clients sometimes break a long link across two lines.</p>') +
      nlEn('<p class="footer-text mt-4"><a href="/auth/request-reset">Resetlink aanvragen</a></p>', '<p class="footer-text mt-4"><a href="/auth/request-reset">Request a reset link</a></p>');
    return;
  }

  confirmBtn.addEventListener('click', async function() {
    confirmBtn.disabled = true;
    confirmBtn.textContent = nlEn('Bezig...', 'Processing...');
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
        errorDiv.textContent = nlEn('De reset lukte niet, dus uw huidige authenticator-app werkt nog. ', 'The reset did not go through, so your current authenticator still works. ') + (data.error ? nlEn('De server meldde: ', 'The relay reported: ') + data.error + '.' : nlEn('Probeer het zo opnieuw.', 'Try again in a moment.'));
        errorDiv.classList.add('visible');
        confirmBtn.disabled = false;
        confirmBtn.textContent = nlEn('Ja, stel mijn authenticator-app opnieuw in', 'Yes, reset my authenticator');
      }
    } catch (err) {
      errorDiv.textContent = nlEn('Paramant is niet bereikbaar. Controleer uw verbinding en probeer het opnieuw.', 'We could not reach Paramant. Check your connection and try again.');
      errorDiv.classList.add('visible');
      confirmBtn.disabled = false;
      confirmBtn.textContent = nlEn('Ja, stel mijn authenticator-app opnieuw in', 'Yes, reset my authenticator');
    }
  });
})();
