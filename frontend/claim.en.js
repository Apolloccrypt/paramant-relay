'use strict';
// Claim page: reads the one-time token from the URL fragment (never sent to the
// server on load, never logged), and only on an explicit click POSTs it to burn
// on reveal. Requiring a click prevents mail-scanner prefetch from spending the
// token. The key is shown once and never stored anywhere client-side.
(function () {
  var token = (location.hash || '').replace(/^#/, '').trim();
  var startEl = document.getElementById('start');
  var revealBtn = document.getElementById('revealBtn');
  var resultEl = document.getElementById('result');
  var keyOut = document.getElementById('keyOut');
  var copyBtn = document.getElementById('copyBtn');
  var errorEl = document.getElementById('error');

  function showError(msg) {
    errorEl.textContent = msg;
    errorEl.hidden = false;
  }

  if (!/^[a-f0-9]{64}$/.test(token)) {
    revealBtn.disabled = true;
    showError('This claim link is missing or malformed. Use the exact link from your email.');
    return;
  }

  revealBtn.addEventListener('click', function () {
    revealBtn.disabled = true;
    revealBtn.textContent = 'Revealing…';
    errorEl.hidden = true;
    fetch('/v2/claim/reveal', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: token })
    }).then(function (r) {
      return r.json().then(function (body) { return { ok: r.ok, body: body }; });
    }).then(function (res) {
      if (!res.ok || !res.body || !res.body.key) {
        var code = res.body && res.body.error;
        showError(code === 'claim_not_found_or_used'
          ? 'This key has already been claimed or the link has expired.'
          : 'Could not reveal the key. Please try again or contact support via paramant.app.');
        revealBtn.textContent = 'Reveal my API key';
        revealBtn.disabled = false;
        return;
      }
      // Clear the token from the address bar so it isn't left in history.
      if (history.replaceState) history.replaceState(null, '', location.pathname);
      keyOut.textContent = res.body.key;
      startEl.hidden = true;
      resultEl.hidden = false;
    }).catch(function () {
      showError('Network error. Please try again.');
      revealBtn.textContent = 'Reveal my API key';
      revealBtn.disabled = false;
    });
  });

  copyBtn.addEventListener('click', function () {
    var txt = keyOut.textContent || '';
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(txt).then(function () {
        copyBtn.textContent = 'Copied';
        setTimeout(function () { copyBtn.textContent = 'Copy key'; }, 1500);
      });
    }
  });
})();
