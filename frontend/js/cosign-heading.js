// The heading of /co-sign, said for the state the request is in.
//
// The page used to carry one fixed heading, "Lees het document en zet uw
// handtekening", also above "Door iedereen getekend" and on the sender's own
// result page, where there is nothing left to sign and the reader may not be a
// signer at all (acceptance 3.1.1, 10). The heading follows the status now.
//
// state: 'open' | 'complete' | 'declined' | 'cancelled' | 'expired'
// signedByMe: this party has signed already
// owner: the sender reads his own result page
// L(nl, en): the page's language picker
export function cosignHeading({ state, signedByMe = false, owner = false }, L) {
  if (state === 'declined') return { title: L('Dit verzoek is geweigerd', 'This request was declined'), sub: L('Tekenen kan niet meer.', 'It can no longer be signed.') };
  if (state === 'cancelled') return { title: L('Dit verzoek is ingetrokken', 'This request was withdrawn'), sub: L('Tekenen kan niet meer.', 'It can no longer be signed.') };
  if (state === 'expired' && !signedByMe) return { title: L('Dit verzoek is verlopen', 'This request has expired'), sub: L('Tekenen kan niet meer.', 'It can no longer be signed.') };
  if (state === 'complete') return { title: L('Door iedereen getekend', 'Signed by everyone'), sub: L('Hieronder vindt u het getekende document.', 'The signed document is below.') };
  if (owner) return { title: L('Uw verzoek', 'Your request'), sub: L('Hier ziet u wie al getekend heeft.', 'Here you see who has signed.') };
  if (signedByMe) return { title: L('U heeft getekend', 'You have signed'), sub: L('We wachten nog op de anderen.', 'We are waiting for the others.') };
  return { title: L('Document ondertekenen', 'Sign this document'), sub: L('Lees het document en zet uw handtekening.', 'Read the document and add your signature.') };
}
