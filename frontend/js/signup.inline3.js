
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
      t: 'This verification link has expired',
      m: 'Verification links are valid for 24 hours. Enter your email below to get a fresh one. If you already finished setup, <a href="/auth/login">sign in</a> instead.'
    },
    invalid_token: {
      t: 'Verification link not recognised',
      m: 'The link you clicked is malformed. If you followed it from an email, try copy-pasting the full URL into the browser. Otherwise, sign up again below with the same email.'
    },
    account_exists: {
      t: 'An account already exists for this email',
      m: 'Go to <a href="/auth/login">Sign in</a> to log in, or <a href="/auth/request-reset">request a new setup link</a> if you no longer have access to your authenticator app.'
    },
    server_error: {
      t: 'Something went wrong on our side',
      m: 'Please try again in a few minutes, or email <a href="mailto:hello@paramant.app">hello@paramant.app</a> if it keeps failing.'
    },
    busy: {
      t: 'Your account is still being created',
      m: 'We received your verification a moment ago and are finishing it up. Wait a few seconds, then click the link in your email once more.'
    }
  };
  var e = map[err] || { t: 'Unknown error', m: 'Please try signing up again below.' };
  title.textContent = e.t;
  msg.innerHTML = e.m;
  banner.hidden = false;
  banner.scrollIntoView({behavior:'smooth', block:'start'});
})();
