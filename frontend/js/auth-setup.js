// One file, two languages: the Dutch page and its English copy under /en/ load
// this same script, and <html lang> says which of the two strings to show.
function nlEn(nl, en) { return /^en\b/i.test(document.documentElement.lang || '') ? en : nl; }
(function() {
  const token = window.location.pathname.split('/').pop();
  // The language switch names the page, not the link in the mail: carry the
  // token across so the other language opens the same setup.
  const langSwitch = document.querySelector('.lang-switch a');
  if (langSwitch && token && token !== 'setup') {
    langSwitch.setAttribute('href', langSwitch.getAttribute('href') + '/' + encodeURIComponent(token));
  }
  let setupData = null;
  let backupCodes = [];

  function show(stateId) {
    document.querySelectorAll('section[id^="state-"]').forEach(function(s) {
      s.classList.add('hidden');
    });
    document.getElementById(stateId).classList.remove('hidden');
  }

  async function init() {
    try {
      const res = await fetch('/api/user/setup/' + encodeURIComponent(token), {
        method: 'POST',
      });

      if (!res.ok) {
        show('state-invalid');
        return;
      }

      setupData = await res.json();
      backupCodes = setupData.backup_codes;

      new QRCode(document.getElementById('qr-code'), {
        text: setupData.otpauth,
        width: 240,
        height: 240,
        colorDark: '#0B3A6A',
        colorLight: '#F8FAFC',
        correctLevel: QRCode.CorrectLevel.M,
      });

      document.getElementById('setup-email').textContent = setupData.email;
      document.getElementById('secret-display').textContent = setupData.secret;

      show('state-active');

      setTimeout(function() {
        document.getElementById('state-verify').classList.remove('hidden');
        document.getElementById('verify-code').focus();
      }, 1500);
    } catch (err) {
      show('state-invalid');
    }
  }

  document.getElementById('copy-secret').addEventListener('click', function() {
    if (setupData) navigator.clipboard.writeText(setupData.secret);
  });

  document.getElementById('verify-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    const code = document.getElementById('verify-code').value.trim();
    const errorDiv = document.getElementById('verify-error');
    errorDiv.classList.remove('visible');

    const res = await fetch('/api/user/setup/' + encodeURIComponent(token) + '/confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ totp: code }),
      credentials: 'include',
    });

    if (!res.ok) {
      errorDiv.textContent = nlEn('Deze code werd niet geaccepteerd. De code verandert elke 30 seconden, dus gebruik de code die uw app nu toont.', 'That code was not accepted. Codes change every 30 seconds, so use the one your app is showing right now.');
      errorDiv.classList.add('visible');
      return;
    }

    const data = await res.json();
    // Backup codes are minted by the server at activation and returned here, in the
    // confirm response — exactly once. This is the authoritative source, so a
    // reloaded setup page or a re-issued link can no longer strand the user on an
    // empty set. (The setup/QR step intentionally returns no codes.)
    if (Array.isArray(data.backup_codes) && data.backup_codes.length > 0) {
      backupCodes = data.backup_codes;
    }

    // Defensive last-resort: codes should always arrive with a successful confirm,
    // so an empty set here means a genuine relay/activation failure, not the old
    // reload race. Surface a real error instead of a silent empty success screen.
    if (!Array.isArray(backupCodes) || backupCodes.length === 0) {
      errorDiv.innerHTML = nlEn('Uw authenticator-app is gekoppeld, dus u kunt inloggen. Uw back-upcodes kwamen niet door, meestal is dat tijdelijk. Mail <a href="mailto:hello@paramant.app?subject=Instellen%20onvolledig%20-%20back-upcodes" style="color:#92400E;text-decoration:underline">hello@paramant.app</a> met als onderwerp <code>Instellen onvolledig</code>, dan maken wij een nieuwe set.', 'Your authenticator app is linked, so you can sign in. Your backup codes did not come through, which is usually temporary. Mail <a href="mailto:hello@paramant.app?subject=Setup%20incomplete%20-%20backup%20codes" style="color:#92400E;text-decoration:underline">hello@paramant.app</a> with the subject <code>Setup incomplete</code> and we issue a new set.');
      errorDiv.classList.add('visible');
      return;
    }

    const grid = document.getElementById('backup-codes');
    grid.innerHTML = '';
    backupCodes.forEach(function(c) {
      const div = document.createElement('div');
      div.className = 'backup-code';
      div.textContent = c;
      grid.appendChild(div);
    });

    show('state-success');
  });

  document.getElementById('saved-confirm').addEventListener('change', function(e) {
    document.getElementById('finish-btn').disabled = !e.target.checked;
  });

  document.getElementById('copy-codes').addEventListener('click', function() {
    navigator.clipboard.writeText(backupCodes.join('\n'));
  });

  document.getElementById('download-codes').addEventListener('click', function() {
    const blob = new Blob([
      nlEn('Paramant back-upcodes\n', 'Paramant backup codes\n') +
      nlEn('Bewaar deze op een veilige plek. Elke code werkt één keer.\n\n', 'Save these in a safe place. Each can be used once.\n\n') +
      backupCodes.join('\n') +
      nlEn('\n\nAangemaakt: ', '\n\nGenerated: ') + new Date().toISOString()
    ], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'paramant-backup-codes.txt';
    a.click();
  });

  document.getElementById('print-codes').addEventListener('click', function() {
    window.print();
  });

  document.getElementById('finish-btn').addEventListener('click', function() {
    show('state-welcome');
    window.scrollTo(0, 0);
  });

  document.getElementById('start-btn').addEventListener('click', function() {
    show('state-connecting');
    init();
  });
})();
