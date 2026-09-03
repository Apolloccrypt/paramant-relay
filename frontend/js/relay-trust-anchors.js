// The relay identity keys this site ships with, so a transfer receipt can be
// checked without asking anything of the network.
//
// These are ML-DSA-65 public keys, exactly as GET /v2/pubkey publishes them.
// Public keys are not secrets; pinning them here is what makes /verify work
// with the network switched off. Each entry carries the SHA3-256 fingerprint of
// its own key, and the verifier recomputes that fingerprint rather than
// trusting the string below.
//
// If a relay ever rotates its identity key, receipts signed by the new key show
// up as "signed by a key this page does not recognise" and stay checkable by
// pasting the current key. That is the intended failure mode: never a false
// "genuine", never a false "forged". Refresh a pin from the endpoint in
// PUBKEY_URL and update the fingerprint in the same commit.
//
// relay.paramant.app, pinned 2026-09-03 from https://relay.paramant.app/v2/pubkey
export const PUBKEY_URL = 'https://relay.paramant.app/v2/pubkey';

export const RELAY_TRUST_ANCHORS = [
  {
    name: 'the Paramant relay',
    host: 'relay.paramant.app',
    alg: 'ML-DSA-65',
    fingerprint: '3d9b960c107a5145dc7412b5953d52c0f5d5b89a654f2da296b1133164befd61',
    key: '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',
  },
];

export function defaultAnchor() {
  return RELAY_TRUST_ANCHORS[0] || null;
}

export function anchorByFingerprint(fingerprint) {
  return RELAY_TRUST_ANCHORS.find((a) => a.fingerprint === fingerprint) || null;
}
