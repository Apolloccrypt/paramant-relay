# Qualified electronic signature: a prototype, behind a flag

This is a working prototype of a QES layer for ParaSign. It is off by default and
it changes nothing about signing until `PARASIGN_QES_PROVIDER` names a provider.
It exists to answer one question without a contract: does a qualified signature
fit next to what ParaSign already does, or does it need the product rebuilt?

The answer is that it fits. This document records what was proved, against what,
and what is still missing.

## The shape

Three layers that do not touch each other:

1. **The PAdES signature inside the PDF.** A qualified trust service provider
   signs a SHA-256 digest and returns a signature value. The container is built
   here. The document never leaves.
2. **The `.psign` receipt.** Unchanged, with one extra top-level field pointing
   at the qualified signature. It is a separate file next to the PDF, so it
   cannot break a PAdES signature and a PAdES signature cannot break it.
3. **The public log.** Untouched.

"Verifiable without us" holds for both halves separately: the receipt through
the existing verify page, the PAdES signature through Adobe Acrobat or the EU
DSS validator, neither of which has to ask Paramant anything.

## The modules

| File | What it is |
|---|---|
| `relay/lib/qes/asn1.js` | Minimal DER encoder and decoder. No new dependency. |
| `relay/lib/qes/cms.js` | CMS SignedData for a detached CAdES-BES signature, plus the signed attributes and the one digest that goes out. |
| `relay/lib/qes/pades.js` | The PDF incremental-update writer: signature dictionary, ByteRange, signature field, cross-reference section. |
| `relay/lib/qes/tsa.js` | RFC 3161 timestamping, for PAdES-B-T. |
| `relay/lib/qes/cleverbase.js` | Cleverbase Signing API client (CSC API v1.0.4). |
| `relay/lib/qes/index.js` | The flag, and the two phases either side of the provider call. |
| `scripts/qes-verify.mjs` | Independent verification of the result. |

`pdf-lib` is used only as the object model. It cannot write an incremental
update: `PDFDocument.save()` rewrites the whole file, which would break any
signature already present and makes "the original bytes are untouched"
impossible to assert. So pdf-lib parses the catalogue, the page tree and the
AcroForm, and `pades.js` writes the bytes.

## What the sandbox allowed, and what it did not

Checked on 3 September 2026 against `https://connect.acc.cleverbase.com`.

**Reachable without any credentials.** `POST /csc/v1/info` answers 200 with the
CSC discovery document: `specs 1.0.4.0`, `region NL`, `authType ["oauth2code"]`,
and the method list `auth/revoke, credentials/info, credentials/list, info,
oauth2/authorize, oauth2/revoke, oauth2/token, signatures/signHash`. Production
answers identically on `https://connect.cleverbase.com`.

**Hash-only signing is confirmed by absence.** There is no `signatures/signDoc`
in the method list. The only way to get a signature out of this API is to hand
it a digest. That is the finding the whole architecture rests on, and it holds.

**No qualified timestamp.** There is no `signatures/timestamp` method either.
Cleverbase has no TSA/QTST service, so the timestamp has to be bought elsewhere.

**No signature is reachable from a test.** `authType` is `oauth2code` and
nothing else. Every signature needs a natural person to authorise it in the
Cleverbase app, having identified himself there with an NFC chip read plus
biometrics. There is no `client_credentials` grant: asking for one returns
`invalid_request: Invalid parameter grant_type`. This is not a sandbox
limitation to be worked around; it is what makes the signature qualified.

**The published test credentials do not work here.** The client id
`6dd5f48d-bcd9-4a98-8a4c-5c82182f5be4` and secret published on
`https://cleverbase.com/en/dev-docs/client-registration/` are for the *trust
driver stub* services, of which only the identification stub
(`trust-driver-stub-idf.cleverbase.com`) is publicly reachable. Against the
signing host they are rejected: `/csc/v1/oauth2/authorize` redirects to
`error=invalid_client`. There is no self-service OAuth client for the Signing
API. Client registration is a manual step with an account manager, in
pre-production as well as in production.

So the honest state of the integration is: the client speaks the protocol, the
request and response shapes are pinned by unit tests against recorded payloads,
the discovery call runs live in CI when asked, and the one call that produces a
signature has never been made because it cannot be made without a registered
client and an identified person.

## The timestamp

`QES_TSA_URL` defaults to `http://timestamp.digicert.com`. It is free, needs no
account, answers over plain HTTP as RFC 3161 specifies, and it works: a request
made on 3 September 2026 came back `Status: Granted` with a SHA-256 token whose
imprint matched.

It is **not** an EU-qualified TSA. It is a code-signing timestamp service and it
appears on no member state's eIDAS trusted list. With it the signature is
PAdES-B-T in shape only. For a signature that counts, the URL has to point at a
qualified TSA, which means a provider with a granted TSA/QTST service: DigiCert
Europe Netherlands has nine on the Dutch list, Zetes ten on the Belgian one.
Setting `QES_TSA_URL=` (empty) skips timestamping and stays honestly at
PAdES-B-B.

## Verification

```
node scripts/qes-verify.mjs signed.pdf [--json]
```

It recomputes the ByteRange digest, checks it against the message-digest
attribute, checks that `signing-certificate-v2` names the certificate that is
actually in the CMS, verifies the RSA signature over the signed attributes,
walks the certificate chain link by link, and checks that any timestamp covers
this signature value.

It does not check trust. No trusted list is consulted, so nothing it prints
proves the issuer is a qualified trust service provider. It does not check
revocation: no CRL, no OCSP. It does not do full RFC 5280 path validation. Use
Adobe Acrobat or the EU DSS demo validator for the real verdict.

## What is still needed for production

1. **A contract with Cleverbase.** Client registration is manual. The API tariff
   per `signHash` at low volume is not published anywhere.
2. **A qualified timestamp authority.** Cleverbase has none. Without one there
   is no B-T, and therefore no B-LT and no B-LTA.
3. **Long term validation.** B-LTA needs a DSS dictionary with the certificates,
   OCSP responses and CRLs, plus a document timestamp. None of that is built
   here. Without it the signature stops being verifiable once the signer
   certificate expires.
4. **The Belgian gap.** A Belgian can identify at Cleverbase only with a
   passport. The Belgian eID card is not accepted.
5. **The public wording.** `about.html`, `security.html` and `parasign.html`
   currently state that a ParaSign signature is not qualified, and the tests pin
   that sentence. Those pages describe the ParaSign signature and stay correct
   while the QES sits next to it as a separate, optional artefact. They will
   need a deliberate rewrite before any of this is offered to customers.

## Running the tests

```
# no network
node --test relay/test/qes-pades.test.js relay/test/qes-cms.test.js
node --test tests/qes-pdf-readable.test.mjs

# real calls to the Cleverbase pre-production host and a public TSA
CLEVERBASE_SANDBOX=1 node --test tests/qes-cleverbase-live.test.mjs
```
