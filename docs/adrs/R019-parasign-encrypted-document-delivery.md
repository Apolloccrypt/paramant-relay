# R019. ParaSign encrypted document delivery

Status: implemented compatibility layer, target architecture recorded

Date: 2026-07-21

## Problem

An invited signer received an envelope hash and was expected to obtain the
document through another channel. The co-sign page could not open the document
from the signing invitation. This made the signing request incomplete and easy
to use incorrectly.

The relay must support a recoverable document workflow without receiving
document plaintext or a private signing key. An intercepted email link must not
be sufficient to retrieve the encrypted document.

## Current decision

The sender browser encrypts the source document with AES-256-GCM. The capsule
is bound to the envelope id and document hash through authenticated additional
data. The relay stores the capsule until envelope expiry.

The random document key is placed in the invite URL fragment. Browsers do not
send fragments in HTTP requests. Ciphertext retrieval requires all of:

1. the envelope id and party index;
2. the party invite token;
3. an authenticated Paramant session for the exact invited email address;
4. an internal assertion from the admin proxy to the relay.

The browser decrypts locally and recomputes SHA3-256. Signing remains disabled
until that hash equals the envelope hash. A link alone and a session alone are
both insufficient.

Email delivery is optional. It sends the complete personal link through the
transactional email provider. The provider sees that link but cannot retrieve
the ciphertext without the invited Paramant identity. Manual link sharing uses
the same recipient identity gate.

## Target architecture

Recipient public-key wrapping removes the document key from email delivery.
Each account publishes transparent, rotating encryption prekeys. When a sender
adds an existing recipient, the sender browser wraps the document key for that
recipient. The email then carries only an envelope capability.

The default product flow remains one action. Paramant selects the strongest
available delivery automatically:

- a recipient with a valid prekey gets end-to-end key wrapping;
- a new external recipient gets the identity-gated compatibility path;
- first use creates a prekey through the recipient's passkey setup;
- an organisation may require prekey-only delivery and disallow fallback.

Recipient prekeys must be covered by the transparency log so a relay cannot
silently substitute its own key. Rotation, recovery and multi-device access
must be designed before this target is enabled. The signing key and encryption
key remain separate.

## User interface

The primary flow says what the user can accomplish, not how key transport works.
It shows an email invitation, subject, message and recipient status. Technical
choices live under Security settings. Per-recipient status uses plain language:

- End-to-end protected
- Identity check required
- Waiting for recipient security setup

Partial email delivery is never reported as success. Failed recipients remain
visible and can be retried without resending successful invitations.

## Consequences

The compatibility layer persists ciphertext, unlike burn-on-read ParaSend.
Privacy, DPA and sovereignty documentation must distinguish those lifecycles.
Envelope expiry also expires the encrypted document capsule.

The email provider still processes the fragment key in the compatibility path.
This is an explicit limitation until recipient prekey wrapping is implemented.
