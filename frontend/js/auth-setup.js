(function() {
  const token = window.location.pathname.split('/').pop();
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
      errorDiv.textContent = 'Invalid code. Try the current number shown in your app.';
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
      errorDiv.innerHTML = 'Your TOTP is set up, but your backup codes could not be generated. This is usually temporary. Please contact <a href="mailto:hello@paramant.app?subject=Setup%20incomplete%20-%20backup%20codes" style="color:#92400E;text-decoration:underline">hello@paramant.app</a> with subject <code>Setup incomplete</code> and we will regenerate them.';
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
      'Paramant backup codes\n' +
      'Save these in a safe place. Each can be used once.\n\n' +
      backupCodes.join('\n') +
      '\n\nGenerated: ' + new Date().toISOString()
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
