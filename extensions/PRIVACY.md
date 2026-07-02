# Privacy policy — Paramant mail integrations

Applies to the Paramant browser extension (Chrome and Edge) and the Paramant Outlook add-in.
Host this text at the privacy policy URL referenced in the store listing.

## What the integrations do

They encrypt a file you choose in your browser, upload the encrypted result to a Paramant
relay, and put a one-time download link into your email. The recipient decrypts the file in
their browser.

## What stays on your device

- Your Paramant API key (or session), stored by the browser for the extension and in the
  add-in's local storage.
- Your preferences: default link expiry and link format.
- A local transfer history: the name, size, and time of files you have sent. This list never
  leaves your device and never contains decryption keys or links.

## What is sent to the Paramant relay

- The encrypted file, as fixed-size 5 MB ciphertext blocks. The relay cannot read it.
- A random per-file identifier used only to count a multi-part transfer as one transfer.
- Your API key, in the request header, to authorise the upload.

The relay does not receive the file's plaintext, the filename, or the decryption key. The
decryption key is placed in the link's URL fragment, which browsers do not transmit to
servers.

## What the relay keeps, and for how long

The encrypted blocks are held until the link is opened once (burn-on-read) or until the
expiry you chose (1 hour to 7 days), whichever comes first, then deleted.

## Third parties

No analytics, advertising, or tracking services are used. No data is sold. The browser
extension loads no remote code. The Outlook add-in loads Microsoft's required Office.js
runtime (`appsforoffice.microsoft.com`), a mandatory Office platform dependency; this exposes
your IP and load time to Microsoft on add-in load. No other remote code is loaded.

## Contact

Questions: via https://paramant.app
