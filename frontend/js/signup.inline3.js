// One file, two languages: the Dutch page and its English copy under /en/ load
// this same script, and <html lang> says which of the two strings to show.
function nlEn(nl, en) { return /^en\b/i.test(document.documentElement.lang || '') ? en : nl; }

(function(){
  var p = new URLSearchParams(location.search);
  var err = p.get('error');
  if (!err) return;
  var banner = document.getElementById('signup-error-banner');
  var title  = document.getElementById('signup-error-title');
  var msg    = document.getElementById('signup-error-msg');
  if (!banner || !title || !msg) return;
  var map = {
    expired_token: {
      t: nlEn('Deze bevestigingslink is verlopen', 'This verification link has expired'),
      m: nlEn('Een bevestigingslink werkt 24 uur. Vul hieronder uw e-mailadres in voor een nieuwe. Al klaar met instellen? <a href="/auth/login">Log dan in</a>.', 'Verification links are valid for 24 hours. Enter your email below to get a fresh one. If you already finished setup, <a href="/auth/login">sign in</a> instead.')
    },
    invalid_token: {
      t: nlEn('Bevestigingslink niet herkend', 'Verification link not recognised'),
      m: nlEn('De link die u opende is niet compleet. Kwam hij uit een mail, kopieer dan het hele adres naar de browser. Of meld u hieronder opnieuw aan met hetzelfde e-mailadres.', 'The link you opened is incomplete. If it came from an email, copy the full address into your browser. Or sign up again below with the same email address.')
    },
    account_exists: {
      t: nlEn('Er is al een account met dit e-mailadres', 'An account already exists for this email'),
      m: nlEn('Ga naar <a href="/auth/login">Inloggen</a>. Kunt u niet meer bij uw authenticator-app? <a href="/auth/request-reset">Koppel dan een nieuwe met een back-upcode</a>. Geen back-upcode? Mail <a href="mailto:privacy@paramant.app">privacy@paramant.app</a> vanaf uw accountadres.', 'Go to <a href="/en/auth/login">Sign in</a>. If you no longer have your authenticator app, <a href="/en/auth/request-reset">link a new one with a backup code</a>. No backup code? Email <a href="mailto:privacy@paramant.app">privacy@paramant.app</a> from your account address.')
    },
    server_error: {
      t: nlEn('Er ging bij ons iets mis', 'Something went wrong on our side'),
      m: nlEn('Probeer het over een paar minuten opnieuw, of mail <a href="mailto:hello@paramant.app">hello@paramant.app</a> als het blijft mislukken.', 'Please try again in a few minutes, or email <a href="mailto:hello@paramant.app">hello@paramant.app</a> if it keeps failing.')
    },
    busy: {
      t: nlEn('Uw account wordt nog aangemaakt', 'Your account is still being created'),
      m: nlEn('Wij kregen uw bevestiging net binnen en zijn er nog mee bezig. Wacht een paar seconden en klik dan nog een keer op de link in uw mail.', 'We received your verification a moment ago and are finishing it up. Wait a few seconds, then click the link in your email once more.')
    }
  };
  var e = map[err] || { t: nlEn('Onbekende fout', 'Unknown error'), m: nlEn('Meld u hieronder opnieuw aan.', 'Sign up again below.') };
  title.textContent = e.t;
  msg.innerHTML = e.m;
  banner.hidden = false;
  banner.scrollIntoView({behavior:'smooth', block:'start'});
})();
