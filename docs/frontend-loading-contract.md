# The frontend loading contract

Four product breaks in July 2026 came from the same place: **how a script finds
another script, and how it learns that one is ready.** None of them produced a
build error, a failed request, a console message or a red CI run. Each one just
made a page stop working, silently, for weeks.

This document is the rule that replaces guessing. It is enforced by
`tests/frontend-loading-contract.test.mjs` (Node only, ~200 ms) and by the
browser gate in `tests/product-heartbeat.test.mjs`.

## Rule 1 — readiness is sticky, never an event

**Do not do this.** It is the bug, not a simplification of it:

```js
// loader.js, loaded as <script type="module">
window.thing = thing;
window.dispatchEvent(new Event('thing-ready'));      // ✗

// consumer.js, loaded as <script defer>
window.addEventListener('thing-ready', () => init()); // ✗ never fires
```

Module scripts and deferred classic scripts both run *after parsing, in document
order*. The loader sits higher up the page, so it fires its event before the
consumer has registered anything. The event goes nowhere. `init()` is never
called. Every asset is loaded, every global is set, and the console is clean.

That is not a hypothetical. `/ontvang` — receiving a file, half of ParaSend —
sat on "Generating keypair..." from 2026-07-02 to 2026-07-28 for exactly this
reason. Re-dispatching the event by hand in the console made the page finish in
under a second.

**Do this instead.** `frontend/js/ready.js` keeps a sticky registry:

```js
// producer
window.ready.signal('mlkem', ml_kem768);

// consumer — resolves whether it asks before or after the signal
const lib = await window.ready.when('mlkem');

// or, when hanging forever is worse than failing loudly:
const lib = await window.ready.within('mlkem', 20000, 'ML-KEM-768 library');
```

Order stops being load-bearing, which is the entire point.

### Loading ready.js

Any page using `ready.*` must load it as **the first script, plain, in
`<head>`** — no `defer`, no `async`, no `type="module"`:

```html
<script src="/js/ready.js?v=1"></script>
```

A plain script in `<head>` runs during parsing, so it is guaranteed to exist
before every module and deferred file on the page. Give it `defer` and it joins
the same queue as everything else, and you have rebuilt the race it exists to
prevent. The gate fails the build if you do.

### What is not covered

Events that fire on a **user action** are fine: `signing-key-enrolled` is
dispatched on a click, long after every script on the page exists. The rule is
about *load-time readiness*, where the producer can legitimately win the race.

## Rule 2 — entry points use document-root absolute paths

A file loaded straight from a page resolves relative imports against **its own
URL**. Move the file and the import 404s in silence.

```js
import { encryptBlob } from './crypto-bridge.js';   // ✗ breaks when the file moves
import { encryptBlob } from '/crypto-bridge.js';    // ✓
```

This is how sending a file died. Commit `042b4c5` extracted inline scripts into
`js/` for CSP hardening, the relative specifier moved along with the code, and
`./crypto-bridge.js` started resolving to `/js/crypto-bridge.js`, which does not
exist. `window._cryptoBridge` stayed empty and ParaSend refused to encrypt, from
2026-07-02 to 2026-07-26.

The same applies to `src` and `href` in HTML. Pages are reachable both as
`/parashare` and `/parashare/`, and `./vendor/qrcode.min.js` resolves to a
different file under each.

**Exception:** files *inside* a vendor package may import each other relatively.
They move as one unit. The rule binds files a page loads directly.

## Rule 3 — a heartbeat proves work, not loading

`tests/product-heartbeat.test.mjs` used to check that `/ontvang` had
`window._cryptoBridge.decryptBlob`. It did. It had every global it needed while
the page did nothing at all, so the gate was green through the entire outage.

A heartbeat that only asks "did the machinery load" cannot see a page that never
starts. Pages where the user has to *get somewhere* now also carry a `progress`
check that asserts visible advancement — for `/ontvang`, that a real fingerprint
appears on screen, which is only possible if keygen actually ran:

```js
progress: () => /^[0-9A-F]{4}(-[0-9A-F]{4}){4}$/.test(
  document.getElementById('fp-display')?.textContent?.trim() || ''),
```

Verified to fail on the broken code before it was written into a passing state.
A gate that was never seen failing is not a gate.

Only two pages do load-time work the user waits on (`/ontvang`, `/sign`), so
only those two carry a hand-written check. Rather than leave the rest blank,
every page states either a `progress` check or a `progressNote` saying where its
work is covered instead, and a test fails if a page has neither. Silence about
coverage is what let `/ontvang` stay broken for 26 days behind a green suite.

Covering the pages nobody wrote a check for, there is one rule that needs no
per-page knowledge: **a page that finished loading must not still be telling the
user to wait.**

```js
const STUCK_TEXT = /\b(loading|checking|generating|verifying|connecting|...)\b[^.!?]*(\.\.\.|…)\s*$/i;
```

It matches verbs, not punctuation, because a bare `-` or an em dash is a normal
empty-value placeholder. Pointed at the broken build with the per-page check
disabled, it reports:

```
/ontvang.html is still asking the user to wait after it finished loading:
  #keygen-title: "Generating keypair..."
  #keygen-status: "Generating ML-KEM-768 + ECDH P-256 keypair in your browser..."
```

Both July hangs — "Generating keypair..." and "Checking your account..." — would
have been caught by that one line, on a page nobody had thought about yet.

## Rule 4 — one file, one cache-buster

A module's identity is its **full URL, query string included**. Load the same
file under two `?v=` values and the browser gives you two *instances*, each with
its own state. Whoever holds the wrong one is talking to a module nobody else
uses.

```js
// sign.html loads /sign-flow.js?v=49
const mod = await import('/sign-flow.js?v=48');   // ✗ a second, empty instance
```

That is what turned `sign-e2e` red the moment the cache-busters were bumped:
`buildStampedPdf` ran on an instance that had never opened a document, and it
surfaced as `Cannot read properties of null (reading 'pageIndex')` — nowhere
near the cause. Checking for it found two older cases that had been sitting
there for weeks: `sign-full` drove `parasign-signer.js` at `v=11` and `vault.js`
at `v=4` while the application had moved to `v=14` and `v=5`.

In a test, do not repeat the URL at all. Read it off the page:

```js
await import(document.querySelector('script[src*="sign-flow.js"]').getAttribute('src'));
```

The gate requires a single `?v=` per file across `frontend/` and `tests/`. Bump
it in one place and every reference has to follow, which is the point: the
coupling exists either way, so make it loud.

## Where each rule is enforced

| Rule | Gate | Cost | Runs in |
|---|---|---|---|
| Sticky readiness | `frontend-loading-contract.test.mjs` | ~200 ms, no browser | Root integration suites |
| ready.js loaded first and blocking | `frontend-loading-contract.test.mjs` | ~200 ms | Root integration suites |
| Absolute paths in entry points | `frontend-loading-contract.test.mjs` | ~200 ms | Root integration suites |
| One cache-buster per file | `frontend-loading-contract.test.mjs` | ~200 ms | Root integration suites |
| Modules loaded as modules | `frontend-module-scripts.test.mjs` | ~100 ms | Root integration suites |
| The page actually works | `product-heartbeat.test.mjs` | ~20 s, Chromium | product-heartbeat (pull requests), heartbeat (hourly against production) |

The hourly production run is what turns these from "green at merge" into "still
true right now". `PARAMANT_BASE_URL=https://paramant.app node --test
tests/product-heartbeat.test.mjs` runs it by hand.

## The pattern behind all four breaks

Each one was a **silent** failure in the browser: no exception, no bad request,
nothing a Node test or a linter could see. What they had in common is that
something was *implicitly* depending on order or location, and an unrelated,
correct-looking refactor changed it.

So the fix is never only the fix. It is removing the implicit dependency —
sticky signals instead of order, absolute paths instead of location — and then
adding a gate that fails on the old code. If a new gate does not fail when
pointed at the bug it was written for, it does not work yet.
