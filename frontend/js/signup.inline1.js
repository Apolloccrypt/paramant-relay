// One file, two languages: the Dutch page and its English copy under /en/ load
// this same script, and <html lang> says which of the two strings to show.
function nlEn(nl, en) { return /^en\b/i.test(document.documentElement.lang || '') ? en : nl; }

(function() {
  const form = document.getElementById('signup-form');
  const errorDiv = document.getElementById('error');
  const submitBtn = document.getElementById('submit-btn');
  const step2 = document.getElementById('step2');

  // Shared signup call: invisible PoW, then POST. Throws {kind,...} on failure;
  // callers own their own button/status so both the email form and the Step-2
  // "resend" reuse it. dpa_accepted is true because continuing IS the agreement
  // (the DPA is a line-with-link now, not a blocking checkbox).
  async function doSignup(email, label, onProgress) {
    let proof;
    try { proof = await ParamantCaptcha.getCaptchaProof(onProgress || function(){}); }
    catch (_) { throw { kind: 'captcha' }; }
    const res = await fetch('/api/user/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, label, dpa_accepted: true, challenge_id: proof.challenge_id, nonce: proof.nonce }),
    });
    if (!res.ok) { const err = await res.json().catch(() => ({})); throw { kind: 'http', status: res.status, err }; }
  }

  function showError(e) {
    if (e && e.kind === 'captcha') { errorDiv.textContent = nlEn('De controle lukte niet. Probeer het opnieuw.', 'Verification failed. Please try again.'); }
    else if (e && e.kind === 'http') {
      if (e.status === 400 && e.err && e.err.error === 'invalid_email') errorDiv.textContent = nlEn('Dit e-mailadres lijkt niet te kloppen. Controleer het en probeer het opnieuw.', 'This email address does not look right. Check it and try again.');
      else if (e.status === 403) errorDiv.textContent = nlEn('De controle lukte niet. Vernieuw de pagina en probeer het opnieuw.', 'Verification failed. Please refresh and try again.');
      else if (e.status === 409) {
        // The sign-in keeps the way back this page was given (?next=), and the
        // English page signs in on the English login.
        const nx = new URLSearchParams(location.search).get('next') || '';
        const a = document.createElement('a');
        a.href = nlEn('/auth/login', '/en/auth/login') + (/^\/(?![\/\\])[^\s\\]*$/.test(nx) ? '?next=' + encodeURIComponent(nx) : '');
        a.textContent = nlEn('Inloggen', 'Sign in');
        errorDiv.textContent = nlEn('Er is al een account met dit e-mailadres. ', 'An account with this email already exists. ');
        errorDiv.append(a, '.');
      }
      else if (e.status === 422) errorDiv.textContent = nlEn('Dit e-mailadres kunnen we niet gebruiken voor een account. Gebruik een adres dat je blijvend leest.', 'We cannot use this email address for an account. Please use an address you will keep reading.');
      else if (e.status === 429) errorDiv.textContent = nlEn('Te veel pogingen. Probeer het later opnieuw.', 'Too many attempts. Please try again later.');
      else errorDiv.textContent = (e.err && e.err.message) || nlEn('Er ging iets mis. Probeer het opnieuw.', 'Something went wrong. Please try again.');
    } else { errorDiv.textContent = nlEn('Geen verbinding. Controleer je internetverbinding.', 'No connection. Check your internet connection.'); }
    errorDiv.classList.add('visible');
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorDiv.classList.remove('visible');
    const email = document.getElementById('email').value.trim();
    const label = document.getElementById('label').value.trim();
    if (!email) { errorDiv.textContent = nlEn('Vul je e-mailadres in.', 'Please enter your email address.'); errorDiv.classList.add('visible'); return; }
    submitBtn.disabled = true;
    submitBtn.textContent = nlEn('Bezig met controleren…', 'Verifying…');
    try {
      await doSignup(email, label, n => { submitBtn.textContent = nlEn('Bezig met controleren… (', 'Verifying… (') + (n / 1000).toFixed(0) + 'k)'; });
      document.getElementById('step2-email').textContent = email;
      form.style.display = 'none';
      // One step on screen at a time. The heading of step 1 ("stap 1 van 5")
      // stayed above "stap 2 van 5" after sending (test with a stranger,
      // 13-10-2026), so the page showed two steps as current.
      const step1 = document.getElementById('step1');
      if (step1) step1.hidden = true;
      step2.hidden = false;
      step2.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e2) {
      showError(e2);
      submitBtn.disabled = false;
      submitBtn.textContent = nlEn('Doorgaan', 'Continue');
    }
  });

  const resendBtn = document.getElementById('resend-btn');
  if (resendBtn) resendBtn.addEventListener('click', async () => {
    const status = document.getElementById('resend-status');
    const email = document.getElementById('email').value.trim();
    if (!email) return;
    resendBtn.disabled = true;
    status.style.color = ''; status.textContent = nlEn('Bezig met versturen…', 'Sending…');
    try { await doSignup(email, document.getElementById('label').value.trim()); status.textContent = nlEn('Verstuurd. Kijk opnieuw in je inbox.', 'Sent. Check your inbox again.'); }
    catch (_) { status.style.color = 'var(--danger, #b91c1c)'; status.textContent = nlEn('Opnieuw versturen lukte niet. Probeer het zo nog eens.', 'Could not resend. Try again in a moment.'); }
    finally { resendBtn.disabled = false; }
  });
})();
