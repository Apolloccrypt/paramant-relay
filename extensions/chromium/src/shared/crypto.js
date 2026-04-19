// crypto.js — ML-KEM-768 wrapper stub for Week 5+
// When Track A PR 5 is live, wire this to noble-mlkem-bundle.js
// (same bundle already used on paramant.app/send).
//
// For now the background worker sends plaintext to paramant.app
// which handles encryption server-side. Client-side ML-KEM in the
// extension is optional hardening, not required for v1.

export async function clientSideEncrypt(_fileBuffer, _recipientPublicKey) {
  throw new Error('Client-side ML-KEM encryption not yet implemented in extension. Using server-side path.');
}
