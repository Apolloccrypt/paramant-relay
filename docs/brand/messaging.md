# Messaging guide

Who we sell to, what we promise, how we prove it.

This file governs the words on paramant.app. Anyone editing a public page,
writing a new one, or reviewing a frontend PR follows it. It settles ordering
and phrasing, not styling: the house palette (bone, navy, cobalt, lime) and the
mono labels stay exactly as they are.

**Status:** adopted 2026-09-02. It replaces no earlier document; there was none.

## The one rule that outranks everything here

A sentence may only go on the site if it is already true on the site or in the
code, and there is a test that fails when it stops being true. That rule comes
from the standing brief in the vault (`Plan/Paramant directie.md`): no new
promise without a test that breaks when the promise does. Every claim in this
guide is quoted from a page that ships today or from `frontend/pricing.html`.
Nothing here was invented for marketing purposes, and nothing here may be
softened into something larger than the code delivers.

---

## 1. Who we sell to, and what hurts

**Primary: the person who signs.** A lawyer, accountant, adviser, notary clerk,
broker or practice manager in the Netherlands or the wider EU. An office of one
to twenty people. A duty of confidentiality and a GDPR responsibility. They sign
engagement letters, powers of attorney, annual accounts and settlement
agreements every week. They decide alone, buy without a procurement department,
and want three answers in five seconds: can I use this today, where does my
document sit, what does it cost.

**Secondary: the person who checks.** A compliance officer, IT lead or security
questionnaire. They arrive on /security and /docs after the primary buyer has
already decided to look. They are the confirmation, never the opening.

**Not an audience on commercial pages: developers.** They are served, well, at
/docs and /help. They do not get hero space. A homepage that opens on Docker Hub
and PyPI is what made /docs busier than /pricing.

The three things that hurt, in the order the buyer feels them:

1. The client document goes through a supplier with a US parent, and "where is
   this and who can reach it" cannot be answered without taking the supplier's
   word for it.
2. The price scales per user, so every new employee or intern costs another
   licence while the actual signing volume stays small.
3. The fallback is email, so the attachment sits in two mailboxes forever and
   afterwards nobody can prove who signed what, when.

We name these plainly, once, in short sentences. We do not dramatise them. No
breach statistics, no hooded attackers, no countdown to quantum. State the leak
the way a plumber states a leak: this happens, this is the consequence, this is
the repair.

## 2. The promise, in one sentence

> Anyone in the EU can sign and send securely for free, forever. Organisations
> pay for volume, never for security.

That is the whole positioning. Everything else on the site is either an
instruction for using it or evidence that it is true.

## 3. The only selling point: free for everyone, paid for organisations

Mick Beer's words, 2026-09-02: the Community tier is his giveback to society,
and there are paid business solutions for organisations that need more. That
split is the structure of the site, not a section in it. On the homepage and on
/pricing it appears **above the fold or immediately under it**, before any
table, any product tour and any cryptography. No other message may stand in
front of it.

It ships on /pricing in these words, and this is the sourced version:

> The Community plan is free, forever. It is not a trial and not a funnel. It is
> what Paramant gives back: signing and sending that does not route through an
> American cloud, available to whoever needs it. Paramant is built by Mick Beer,
> privacy and security researcher and founder of Paramantis Solutions B.V., and
> the Community plan is his contribution back to the society the tools came
> from. Businesses pay for the higher limits (longer links, more reads, more
> devices, a dedicated relay), not to unlock features, and that is what keeps
> the Community plan free.

**A monthly allowance is written "a month", never "per month".** One limit, one
spelling, on every page that repeats it. `relay/test/pricing-page.test.js` fails
a page that drifts back, and the number checks around it accept both spellings
on purpose so a real limit change fails on the number instead.

**The free plan is called Community.** Not Free, not Starter, not Basic. It is
Community on both products and `tests/ui-truthfulness.test.mjs` fails when a
page calls it anything else.

**Free for everyone** (name the tiers as /pricing names them):

- ParaSign Community. EUR 0, forever. 2 signatures a month, no limit on
  receiving, full post-quantum crypto, public verification log, no card
  required.
- ParaSend Community. EUR 0, forever, no card required. AES-256-GCM with a
  browser-generated key, 1 hour link expiry, burn on first read.

**For organisations** (same names, same prices, always excl. btw with the incl.
figure beside it, exactly as /pricing does it):

- Firm. EUR 29/month excl. btw (EUR 35.09 incl.). Annual EUR 290/year excl. btw
  (EUR 350.90 incl.), 16.7% off. One plan and one payment for both products: it
  grants the ParaSign Pro and ParaSend Pro limits together. On ParaSign, 100
  signatures a month and no metered extras: when the 100 are used, signing waits
  for the new month or for a bigger plan. Plus API access. On
  ParaSend, 500 transfers a month, 24 hour expiry, up to 10 reads, up to 50
  registered devices, send history, webhooks, no IP rate limit. The two Pro
  plans it replaced are off sale.
- ParaSign Business. EUR 299/month excl. btw (EUR 361.79 incl.). 1,000
  signatures a month, named support with a response within one business day,
  exportable audit log with CT tree head (CSV or JSON). Annual EUR 2,990 excl.
- ParaSign Enterprise. "Let's talk", per organisation. Dedicated relay instance,
  sector relay, SLA with service credits, self-hosting licence, audit support.
- ParaSend Enterprise. Custom. Dedicated relay, SLA 99.9%, IEC 62443 / NIS2 /
  NEN 7510 documentation, signed DPA.

The line that holds the two halves together is already on /pricing and moves to
the top of the site unchanged:

> Every plan gets the same encryption, the same post-quantum signatures and the
> same public proof log. Pay for volume, never for security. And pay per
> organisation, not per user.

And the line that says the free half is permanent, also already on /pricing:

> Businesses pay for the higher limits (longer links, more reads, more devices,
> a dedicated relay), not to unlock features, and that is what keeps the
> Community plan free.

Why this works and fear-first does not: an office that is shown a problem and
handed an invoice has been sold anxiety. An office that is shown the same
problem and told the answer is free for ordinary use has been shown a position.
The Community plan also removes the risk of trying: two signatures a month,
forever, no card.

## 4. The three proofs, in fixed wording

Three claims carry the promise. They are quoted, not paraphrased, and each one
needs a test that fails when the site stops being able to make it. Where the pin
does not exist yet it is named as work, and until it exists the claim does not
move into a hero.

### Proof 1: EU jurisdiction, no US party in the data path

The claim is about the data path, not about the whole chain. Files and keys stay
in the EU. Transactional email is the one exception and it goes through Resend,
a US provider. Saying "no US company in the chain" is broader than the code
delivers, so it is never written that way again.

Fixed wording, from the rules grid on /, word for word:

> Hetzner Germany, Bunny DNS (Slovenia). No US provider in the data path. Email
> goes out via Resend, as /privacy sets out.

The long form, from rule 5 on /rules, word for word, and it is the
version to use wherever there is room for three sentences:

> Hosted in Germany, owned top to bottom in the EU. No US CLOUD Act reach over
> your files or your keys: they never leave the EU, and they are ciphertext
> everywhere but your own browser. Transactional email is the one exception in
> the chain and goes via Resend, a US provider, which receives the address, the
> message and the invite link but never the document. See the subprocessor list.

Both name the exception in the same breath as the claim. A page may shorten the
long form to the short one, never the other way round, and neither may drop the
Resend sentence.

Pinned by: nothing today. **To add** to `tests/ui-truthfulness.test.mjs`: assert
that `frontend/index.html` still carries "No US provider in the data path" and,
in the same rule, the Resend sentence with its link to /privacy; assert the same
pairing in rule 5 on `frontend/rules.html`; and assert that no public
page carries "no US company in the chain", "no US provider in the chain" or
"no US company" without the Resend exception beside it. See the open
contradiction in section 9: /security still carries the unqualified row and has
to be brought in line first.

### Proof 2: the key stays with the signer, and the proof outlives us

Fixed wording, from /about:

> ML-DSA-65 (FIPS 204), generated in your browser. The private key never reaches
> the relay.

> Every signature is entered into a public, append-only log.

> A signed document verifies without contacting us.

Pinned by: `tests/ui-truthfulness.test.mjs` already forbids the overclaim on
top of this. `frontend/sign.html` must keep "Signer not verified" and must say
the proof "does not show who holds that key", and must not say "identity
verified", "verified signer", "signer verified" or "legally binding". **To add**:
the three /about sentences above, asserted on `frontend/about.html`.

### Proof 3: same cryptography on every plan

Fixed wording, from /pricing:

> Every plan gets the same encryption, the same post-quantum signatures and the
> same public proof log. Pay for volume, never for security. And pay per
> organisation, not per user.

Pinned by: nothing today. **To add** to `tests/ui-truthfulness.test.mjs`: assert
that sentence in `frontend/pricing.html`, since it is the sentence the whole
free-versus-paid split rests on. If the pricing model ever changes to gate
cryptography behind a tier, that test must be the thing that fails first.

### The limits, stated in the same voice

Two limits belong beside the proofs, not in small print. Both already ship.

From /about, word for word, and it does not change:

> A ParaSign signature is a Simple Electronic Signature (SES): an ML-DSA-65
> cryptographic attestation produced in your browser. It is not a notarised
> legal signature under eIDAS or any qualified-trust regime (QES).

From the /pricing FAQ:

> This is documentation you can use as input for your own compliance process.
> Paramant does not hold third-party certification for these frameworks.

For a lawyer these two are a reason to keep reading. They are evidence that the
rest of the page is measured. They are never apologised for and never moved into
a footnote.

## 5. Mick as the face

Name: **Mick Beer**.
Title: **privacy and security researcher, founder of Paramantis Solutions B.V.**

That is the exact title. No other qualification, award, year count, prior
employer, certification or price is ever attached to his name, because none of
that is on the site or in the code. `tests/ui-truthfulness.test.mjs` reads the
title off /about and fails any page that names him with a different one, and it
also rejects any word beside his name that /about does not use.

The founder paragraph, four sentences, and this is the version to use:

> Paramant is a product of Paramantis Solutions B.V. in Harderwijk, the
> Netherlands, founded by Mick Beer, privacy and security researcher. That
> background shapes the choices: post-quantum signatures (ML-DSA-65), a public
> transparency log, offline-verifiable documents, and source code you can
> inspect yourself. The Community plan is his way of giving something back to
> society; the business plans pay for it. Paramantis Solutions B.V. is the
> contracting and responsible party; the founder is the origin of the work, not
> the service itself.

Sentences one, two and four are the current /about text, word for word.
Sentence three is the split from section 3. It is not on /about yet, only on
/pricing and on the signed-in pages; see section 9. Nothing else is added, and
in particular nothing about a US subscription: the jurisdiction claim belongs in
proof 1, with its Resend exception, not beside his name.

Where he appears: a short block on the homepage (name, title, that one reason,
link to /about), and at the top half of /about rather than in section 03. On
/pricing his reason for the free tier may be quoted in one sentence above the
tables. He does not appear on /docs, /help or the auth pages.

## 6. Tone

English. Short sentences, verb first, active voice. Fifteen words is a long
sentence here. Dutch plainness in English words.

- No exclamation marks. No em-dashes.
- Banned: revolutionary, seamless, cutting-edge, enterprise-grade, military-grade,
  trusted by, world-class, effortless, next-generation, unlock, empower, journey.
- No testimonials, no customer logos, no user counts, no "trusted by N teams".
  We do not have them, so we do not imply them.
- Numbers only where they already appear on the site: prices, 2 signatures a
  month, 7 day IP log retention, 99.9% SLA, 48 hour disclosure acknowledgement.
- Claim plus checkpoint, the shape the rules on /rules already use: say what it
  is and say where it is checked.
- Where something is unfinished, say so in the same voice, without a date. The
  Chromium and Outlook extensions currently take a server-side encryption path
  and are not zero-knowledge; "In development" means not live and no date.
- There are two product names, and only two: **ParaSend** and **ParaSign**.
  Nothing else is presented as a product, on a commercial page or anywhere else.
  ParaShare is not a product name. The URL /parashare stays, because extension
  links that were minted years ago point at it and the sdk-js 3.x contract names
  it in a `Link: rel="successor-version"` header, but in copy the page is "the
  ParaSend web app" or "the sending tool". It never appears as an H1, a kicker
  or a product card, and `tests/ui-truthfulness.test.mjs` fails when it does.
  The rules page is "Our rules" on /rules. "ParaRules" is retired as a name and
  the individual rules are "rule 5", not "ParaRule 5"; /pararules keeps a 301.
- Cryptography names, standard numbers and RAM-only appear below the fold, as
  the reason the top half is true. Never in an H1.

Mobile is the design target. At 390px the first screen carries three things and
no more: H1, a sub of at most two sentences and roughly 160 characters, and two
buttons.

## 7. Page order, sitewide

Every commercial page runs the same four movements, top to bottom:

1. What you can do here, in one action.
2. The split: free for everyone, paid for organisations.
3. Who is behind it.
4. The proof, including the honest limits.

Developer material and self-hosting are the last block on any commercial page,
one line and two links. The site never runs in the other direction.

## 8. Per page

Where the H1 below matches what ships today, it stays; changing an H1 changes a
search result, so it is only changed when the current one does not name what the
page is for.

### / (home)

- **Goal:** in five seconds on a 390px screen, say what happens here, that it is
  free to start, and where organisations pay.
- **H1:** Get documents signed and send files safely, from your browser.
  (unchanged; it ships since #328) An H1 must not carry the jurisdiction claim,
  because an H1 has no room for the Resend exception that proof 1 requires
  beside it.
- **First paragraph:** unchanged. "Paramant is for small professional firms that
  would rather not put client files on an American cloud: legal, finance and
  healthcare practices in the EU. Send a contract out for signature, or send a
  file that is gone the moment it has been read. Everything runs on servers in
  Germany."
- **Primary CTA:** Sign a document, to /sign. Secondary: See pricing, to
  /pricing.
- **Order below:** (1) the split, both halves named as in section 3, with one
  button to /pricing; (2) what an office actually does: sign it yourself,
  co-sign with a routing order, send a file that disappears after one read;
  (3) Mick, name and title and the one reason, link to /about; (4) the proof
  block: EU location, key stays on your device, public transparency log,
  offline verification, no third-party requests, source-available, plus the SES
  limit and the certification limit; (5) developers and self-hosting, one line,
  two links.
- **Note:** `feat/homepage-koper` landed as #328, so index.html now ships this
  shape and the rules grid carries the proof 1 wording. This section describes
  what is live, not a target.

### /parasign

- **Status:** does not exist. It returns 404 today, which is why the flagship
  product cannot be found by name. Building it is backlog item 5.
- **Goal:** be the page that ranks for ParaSign and sells signing on its own.
- **H1:** Sign documents in your browser, prove it years later.
- **First paragraph:** ParaSign signs PDFs on your device with ML-DSA-65 and
  records every signature in a public transparency log. The private key never
  reaches the relay. A signed document verifies without contacting us.
- **Primary CTA:** Sign a document, to /sign.
- **Order:** same four movements as the homepage, signing only. Free tier limits
  first, then Firm, ParaSign Business and Enterprise, then the proof, then the
  SES limit.

### /sign

- **Goal:** turn a visitor into a first signature, and tell them what signing
  needs before they pick a file.
- **H1:** Get an important document signed. (unchanged)
- **First paragraph:** unchanged. "Sign it yourself, work together or send it to
  others. Your document stays private and every completed signature comes with
  independently verifiable proof."
- **Primary CTA:** Create an account, to /signup, for a visitor without a
  session. With a session, the CTA is the flow itself.
- **Locked by `tests/ui-truthfulness.test.mjs`, do not reword:** "Signing a
  document needs an account", "open a signing request someone sent you",
  "Signer not verified", and the sentence that the proof does not show who holds
  that key. Keep "Free accounts sign 2 documents a month" with its link to the
  paid tiers.

### The send pages

ParaSend has no public product page. That is the same defect ParaSign has, and
it is worth a `/parasend` page in a later round, built to the /parasign pattern.
Until then the buyer-facing surface for sending is the homepage product block
and /pricing. Two pages exist today and keep their own jobs.

**/parashare** (the ParaSend web app, behind sign-in, noindex, and it stays that
way; the URL keeps its name, the copy does not)

- **Goal:** let a signed-in user send one encrypted file.
- **H1:** unchanged.
- **Primary CTA:** the send action itself. No pricing copy, no founder block.

**/vault** (public, "Lock a file")

- **Goal:** let anyone encrypt a file for themselves with a passphrase.
- **H1:** Lock a file. (unchanged)
- **First paragraph:** unchanged. It already says the file and the passphrase
  never leave the browser, and that a lost passphrase means a lost file.
- **Primary CTA:** Lock file.

### /pricing

- **Goal:** make the split legible before a single table, then let the buyer
  find their tier.
- **H1:** Pricing. (unchanged)
- **First paragraph:** The Community tier is free forever, for everyone.
  Organisations that need higher limits, an API, named support or a dedicated
  relay pay for the business plans. Every plan gets the same encryption, the
  same post-quantum signatures and the same public proof log.
- **Primary CTA:** Create account, to /signup. The tier buttons keep their
  current checkout links.
- **Order:** (1) the split, in the words above, before any table; (2) ParaSign,
  because it is the flagship, currently second; (3) ParaSend; (4) Limits,
  Encryption, Compliance, Support; (5) FAQ.
- **Never remove:** "Pay for volume, never for security. And pay per
  organisation, not per user." It is proof 3.

### /signup

- **Goal:** complete step 1 of 5 with an email address. Nothing else.
- **H1:** Let's create your account. (unchanged)
- **First paragraph:** unchanged. "We'll send a link to confirm it's you. No
  password to invent."
- **Primary CTA:** Continue.
- **Rule:** no selling on this page beyond one line naming what the free tier
  gives. A signup form that argues has lost the argument.

### /security

- **Goal:** be the destination of "how do I check you", for the person who
  checks after the buyer has decided to look.
- **H1:** Security. (unchanged)
- **First paragraph:** one added line before the current text, saying this page
  is the evidence under the homepage promise and that the free tier gets exactly
  the same protection. Then the existing "We treat security as infrastructure,
  not a feature" paragraph, unchanged.
- **Primary CTA:** none. This page ends in the disclosure address, not a button.
- **Order change:** the Jurisdiction and privacy table moves up. It is the row
  the buyer came for. Everything else keeps its order and its wording.

### /about

- **Goal:** put a named person and a checkable set of artefacts behind the
  product.
- **H1:** About Paramant. (unchanged)
- **First paragraph:** unchanged. "Paramant is privacy-first, post-quantum
  document signing and encrypted transfer, built to stay verifiable and to keep
  working under EU jurisdiction. You should not have to trust us. You should be
  able to check."
- **Primary CTA:** See pricing, to /pricing, at the foot of the founder block.
- **Order change:** section 03, Who is behind Paramant, moves into the top half,
  directly under the mission. The split sentence from section 5 is added there;
  PR #332 is the one that puts it on the page, see section 9.
  Section 02 and the SES paragraph follow unchanged. Responsible disclosure
  stays last.

### /docs

- **Goal:** serve developers, and stop absorbing traffic that belongs on
  /pricing.
- **H1:** Documentation. (unchanged)
- **First paragraph:** unchanged, plus one line stating that the ParaSign API is
  available from Firm, with a link to /pricing.
- **Primary CTA:** Quick start.
- **Rule:** no marketing copy, no founder block, no tier comparison beyond that
  one line.

### /help

- **Goal:** unblock someone who already has an account.
- **H1:** Help. (unchanged)
- **First paragraph:** unchanged.
- **Primary CTA:** the most-read article, currently the API key versus TOTP
  answer.
- **Rule:** support voice, not sales voice. A person on this page has already
  bought or already signed up.

### /auth/login, /auth/setup, /auth/backup, /auth/request-reset, /auth/reset-confirm

- **Goal:** get the right person back into their account with the least text
  possible.
- **H1:** unchanged on all five.
- **First paragraph:** one sentence saying what this screen does and what
  happens next. Nothing about pricing, products or the founder.
- **Primary CTA:** the single action of the screen, and it is the only button.
- **Rule:** these pages are noindex, they keep the legal strip stamped by
  `apply-nav.py`, and they never carry a promise. An auth screen that sells is
  an auth screen that lost someone's password reset.

## 9. Open contradictions, do not paper over

Three places where the site currently disagrees with itself, or where this guide
runs ahead of it. None may be fixed silently inside a copy change; each needs
its own PR and its own test.

1. **SES versus AES.** /about says a ParaSign signature is a Simple Electronic
   Signature (SES). The /pricing FAQ says "Signatures are advanced (AES), not
   qualified (QES)." Both cannot be right. The /about wording is the one this
   guide pins, so the FAQ line is the one that has to move, in a separate round.
2. **/security still says "no US company".** Settled on the homepage and on
   /rules, not yet on /security. Those two pages now say no US provider in
   the *data path* and name Resend in the same breath, per proof 1. The
   Jurisdiction and privacy table on /security still has the unqualified row
   "US CLOUD Act: Not applicable: no US infrastructure, no US company", which
   reads as no US party anywhere and is broader than /privacy allows. That row
   is the one that has to move, in its own PR with its own test, to the data
   path wording. Until it does, proof 1 is quoted from / and /rules only.
   Cloudflare is no longer part of this: DNS moved to Bunny and the site is
   served straight from Hetzner, so the name is gone from the frontend and from
   the out-of-scope list, which now reads "Resend, Hetzner, Bunny, Mollie".
3. **The give-back sentence is not on /about yet.** Section 5 puts it as
   sentence three of the founder paragraph and section 3 makes it the structure
   of the site, but on `main` today /about carries only the other three
   sentences. The sourced version lives on /pricing and, once PR #332 lands, in
   the "Behind Paramant" block on /about as "The Community plan is his way of
   giving something back to society; the business plans pay for it." Until that
   PR is merged, the sentence is quoted from /pricing, and the assertion in
   section 4 that pins the /about sentences waits for it.

Until each is settled, the disputed sentence stays where it is and does not get
promoted into a hero.

## 10. Adding a claim

1. Find the sentence that already ships, on a page or in `frontend/pricing.html`.
   If there is none, stop; you are about to invent something.
2. Quote it. Do not improve it.
3. Add or extend an assertion in `tests/ui-truthfulness.test.mjs` that fails when
   the sentence leaves the page or when the underlying fact changes.
4. Check the structural gates still pass: `tests/seo-contract.test.mjs`
   (one h1, title under 65 characters, description 50 to 165, canonical, Open
   Graph, valid JSON-LD, sitemap in both directions), `tests/links.test.mjs`,
   `tests/navigation-shell.test.mjs`, `tests/frontend-loading-contract.test.mjs`,
   `scripts/check-csp-inline.sh` and `scripts/check-cache-bust.sh`.
5. Nav and footer are stamped by `frontend/apply-nav.py`. Do not hand-edit them,
   and do not touch `frontend/js/nav-auth.js`.
