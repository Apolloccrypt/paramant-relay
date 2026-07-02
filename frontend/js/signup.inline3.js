
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
      t: 'Your account is already active',
      m: 'You\'ve already verified this email. <a href="/auth/login" style="background:#1D4ED8;color:#fff;padding:6px 14px;border-radius:4px;text-decoration:none;font-weight:600;display:inline-block;margin:6px 0">Sign in</a> <br><span style="color:#78350F;font-size:13px">Still finishing setup? Look for the email <code>Complete your Paramant account setup</code> in your inbox and open the link to continue.</span>'
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
