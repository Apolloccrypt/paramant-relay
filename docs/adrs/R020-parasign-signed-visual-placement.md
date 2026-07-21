# R020. ParaSign signed visual placement

Status: implemented for new web envelopes

Date: 2026-07-21

## Problem

An invited signer could review the delivered document and add an ML-DSA-65
signature to the envelope, but could not choose where a visible signature or
date appeared. Adding an unsigned browser overlay would be misleading. The
envelope signature covered the source document hash, not that overlay.

## Decision

New authenticated web envelopes use signing recipe 5. Each party signature
commits to:

```text
sha3_256(
  "paramant/parasign/doc/v1" || 0x00 ||
  envelope_id || document_hash || party_index || party_email_hash ||
  signer_public_key || appearance_hash
)
```

`appearance_hash` is SHA3-256 over a canonical JSON manifest. The manifest is
versioned and contains at most eight fields. Each field contains only:

- type: `seal` or `date`;
- zero-based page index;
- normalized `x`, `y`, `w` and `h` coordinates rounded to six decimals.

The relay normalizes the manifest before verification. Unknown field types,
out-of-range pages, non-finite coordinates and fields outside the page are
rejected. The normalized manifest and its hash are written atomically with the
party signature. They are returned in status and `.psign` receipt read-back.

## Privacy boundary

The placement manifest contains no document text, drawn signature image,
recipient email address or free-form signer input. The visible seal is rendered
from envelope data the relay already holds: party label, signed timestamp and
signing-key fingerprint. The source document and document key remain outside
the relay.

## Browser behavior

For a PDF, an invited signer can place one Paramant seal and one signing date.
Prior signed placements are shown as locked fields. The current signer can
remove or move their own fields before signing. A placement draft in
`sessionStorage` contains only field types and coordinates, survives refresh in
the same tab and is removed after a successful signature.

After signing, the browser can render and download a visual PDF copy containing
the signed placements available in that envelope view. Its rewritten PDF bytes
do not equal the signed source hash. It is therefore labelled as a visual copy,
not as the cryptographic proof. Verification uses the original delivered PDF
plus the final `.psign`. The original, visual copy and `.psign` must be kept
together.

## Compatibility

Recipes 1 through 4 remain verifiable. Open envelopes continue to use effective
recipe 4. Existing email envelopes keep their stored recipe. Only newly created
authenticated web envelopes use recipe 5.

Self-signing already bakes its visual stamp into the source bytes before the
document hash is created. It submits an empty recipe 5 appearance manifest, so
the same backend route remains usable without duplicating the visual stamp.

## Deliberate limits

This decision does not add arbitrary text, handwriting images, form fields or
document editing to the recipient flow. Those require a separate privacy model
because the relay must not receive document content disguised as field data.

The account owner cannot reconstruct the source PDF from the dashboard because
the document key remains in the personal invitation link. A cross-device owner
workspace requires recipient key wrapping and encrypted local workspace backup
from R019.
