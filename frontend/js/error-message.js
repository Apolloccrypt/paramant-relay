'use strict';
// What a customer is told when something we did not plan for goes wrong.
//
// The signer had one sentence for a wrong authenticator code, one for an
// account without an authenticator, and for everything else it rethrew the
// error it caught. That error's message is whatever the wire said: "http_500",
// "internal_error", "Failed to fetch", or the string a browser puts on a
// TypeError. Someone stuck halfway through signing a contract read that and
// had no idea whether to wait, to retry, or to call someone. Two of those
// three strings do not even name a problem.
//
// So there is one sentence for the unplanned case, it says what to do next,
// and it names an address that reaches a human. The technical detail is not
// thrown away: it goes to the console, which is where it was useful anyway.
//
// Loadable three ways on purpose, following js/parasign-pdf-ops.js: node
// requires it (the suite that tests this file), a page loads it as a plain
// script and reads self.paramantErrors (js/parashare.page.js is a classic
// script and cannot import), and an ES module side-effect-imports it and reads
// the same namespace. One copy of the sentence, so the two products cannot
// drift into two different apologies.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.paramantErrors = factory();
})(typeof self !== 'undefined' ? self : this, function () {

  var SUPPORT_FAILURE_MESSAGE =
    'Something went wrong on our side. Try again in a minute; if it keeps happening, ' +
    'mail privacy@paramant.app with the time and what you did.';

  // The cases we DID plan for. Each tells the customer something he can act on
  // that the generic sentence cannot, so they keep their own words. Every other
  // code, and every error with no code at all, is unplanned by definition.
  var KNOWN = {
    totp_required:    'Enter the 6-digit code from your authenticator app.',
    totp_invalid:     'That authenticator code didn’t match. Try the current 6-digit code.',
    totp_unavailable: 'Set up an authenticator app on your account first, then sign with its code.',
  };

  function isKnownFailure(error) {
    var code = error && error.code;
    return typeof code === 'string' && Object.prototype.hasOwnProperty.call(KNOWN, code);
  }

  // The translator. Errors in, one readable sentence out, never a raw message.
  // A thrown TypeError, a 500 from the relay and an error object from a browser
  // extension all land on the same sentence, because to the person reading it
  // they are the same event: this did not work and it was not his fault.
  function userFacingMessage(error) {
    return isKnownFailure(error) ? KNOWN[error.code] : SUPPORT_FAILURE_MESSAGE;
  }

  // Log the technical detail, return the error to throw in its place. `where`
  // is a short label naming the step, so a console holding three failures still
  // says which one broke. The replacement carries code 'service_error' unless
  // the original had a code of its own, and callers that render a message
  // switch on that code rather than on the sentence.
  function reportFailure(where, error) {
    try { console.error('[paramant] ' + where, error); } catch (ignored) { /* a missing console is never why a flow dies */ }
    var replacement = new Error(userFacingMessage(error));
    replacement.code = isKnownFailure(error) ? error.code : 'service_error';
    replacement.cause = error;
    return replacement;
  }

  return { SUPPORT_FAILURE_MESSAGE: SUPPORT_FAILURE_MESSAGE, KNOWN: KNOWN, isKnownFailure: isKnownFailure, userFacingMessage: userFacingMessage, reportFailure: reportFailure };
});
