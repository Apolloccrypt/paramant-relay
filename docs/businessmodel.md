# Paramant Business Model — v1.0

> Prices in this document are out of date. It still names Pro at 12 euro and Team at 49 euro; neither plan is on sale. `frontend/pricing.html` is the leading source for what a plan costs and what it includes. The file sizes and the RAM-only reasoning below were corrected on 2026-09-05; the rest is v1.0 as written.

## Core philosophy

RAM-only is not a limitation. It is the product.
RAM-only does not mean small. The relay never holds a whole file. It holds blocks of a fixed 5 MiB, in working memory, and a file is cut into chunks that each travel as one block. So a 500 MB file moves through a relay that still writes nothing to disk and still holds no file.
500 MB covers every document that matters: contracts, medical records, legal filings, sensor payloads, firmware chunks, financial transfers, and the scans and slide decks that used to be too big.
If you need to send a movie, use WeTransfer. If you need zero trace, use Paramant.

---

## Tiers

### FREE — €0/forever

Both Zivver and OT use cases.

**Zivver kant:**
- 500 MB per file over the live hand-over, the same ceiling as every paid tier
- 5 MB per file over a one-time link, because one link is one sealed block
- Up to 10 transfers/day (IP-limited, no account)
- Burn-on-read
- 1h TTL
- Magic link send (no account, no key)
- Email notification to recipient (via Resend)
- CT audit proof per transfer
- No send history

**OT kant:**
- Up to 10 sensor transfers/day
- **OT eval key: 1000 transfers / 30 days, no daily cap** (request at /request-key)
- 1 device registration
- `--interval` mode (min 60s)
- iot.paramant.app managed relay

---

### PRO — €12/mo (monthly) or €9/mo (annual, billed €108/year)

For professionals who send sensitive documents regularly.

**Zivver kant:**
- 500 MB per file, the same as the free tier: size is not what a plan sells. Every block stays in RAM, nothing is disk-backed
- Unlimited transfers
- Email notification to recipient
- TTL options: 1h / 24h / 7d / 30d
- Send history (last 30 transfers)
- Custom expiry message
- Delivery confirmation email to sender

**OT kant:**
- Unlimited transfers
- 5 device registrations
- `--interval` mode (min 5s)
- WebSocket streaming
- Latency SLA: best effort

---

### TEAM — €49/mo (monthly) or €39/mo (annual, billed €468/year)

For teams that need shared oversight. Up to 10 users included.

**User ceiling:** 10 users included. Additional users: €5/user/mo, up to 25 total.
Over 25 users: contact Enterprise.

Everything in Pro, plus:
- 10 users included, shared billing
- Extra users: €5/user/mo (max 25 total)
- Team dashboard (send history across team)
- Admin controls (revoke keys, audit log export)
- Shared relay with team isolation
- Priority email support, 48h response
- 100 device registrations (OT)

---

### ENTERPRISE — Custom pricing

For regulated industries: healthcare, legal, defense, critical infrastructure.

Everything in Team, plus:
- Dedicated relay (data never shared with other customers)
- On-premise option (your hardware, your jurisdiction)
- SLA 99.9% uptime
- IEC 62443 / NEN 7510 / NIS2 compliance documentation*
- GDPR Art. 28 Data Processing Agreement (customized)
- Custom TTL and blob size limits
- SCADA integration support
- Priority support (phone + email, 4h response)
- Unlimited devices and users
- Custom onboarding + security review

*Compliance documentation supports your own certification process. Paramant does not hold third-party IEC 62443, NEN 7510, or NIS2 certification.

---

## Key decisions

### 500 MB on every tier, including free
- Size is not what a plan sells. The file ceiling is `file_mb` in `relay/lib/tiers.js` and it is 500 MB on every capped row
- Reached by chunking: the file is cut up in the browser and each chunk travels as one fixed 5 MiB block. Nothing is disk-backed and nothing is written to disk
- Enough for: contracts (PDF), medical referrals, legal filings, sensor payloads, firmware chunks, scans, slide decks
- Not enough for: video libraries and large archives
- "We don't store files. If you need storage, use Dropbox. If you need zero trace, use us."

### Three numbers that are not the same number
- The block on the wire is a fixed 5 MiB. That is the padding, a privacy measure, and it does not move
- The live hand-over cuts a file into chunks, so it reaches 500 MB a file. The receiver has to be online while you send, and you compare a short code
- A one-time link is one block under one token, so that way stops at 5 MB a file. The receiver does not have to be online

### OT evaluation mode — 1000 transfers / 30 days
- Free daily cap (10/day) would kill SCADA evaluation (5-min intervals × 24h = 288 transfers/day)
- Trial keys on the IoT relay sector get a total budget instead of a daily cap
- Activated automatically: trial key + RELAY_MODE=iot → 1000 transfer budget, no daily reset
- After 1000 transfers or 30 days: upgrade path to Enterprise

### Team user ceiling
- Base: 10 users included at €49/mo
- Overage: €5/user/mo for users 11–25
- Over 25 users: must contact Enterprise

### Freemium conversion logic
Free users hit two natural upgrade triggers:
1. File > 5 MB in the link mode → "Hand it over live, or upgrade for longer links" (the size itself is the same on every plan)
2. TTL expired before recipient downloaded → "Upgrade to Pro for 7-day links"

### DPA availability
- Standard DPA (/dpa, GDPR Art. 28) is publicly available to all tiers
- Enterprise gets customized DPA with negotiated terms, custom sub-processors, jurisdiction overrides

### Business continuity
Paramant is published under BUSL-1.1. If the managed service shuts down, every self-hosted relay keeps running indefinitely. No vendor lock-in.

### OT pricing rationale
OT customers (regulated industrial) buy Enterprise — dedicated relay, compliance docs, human contact.
Free + Pro OT tiers exist for engineer evaluation before procurement.

---

## Revenue model
- Primary: Pro subscriptions (individuals, SMB)
- Secondary: Enterprise contracts (OT, healthcare, legal)
- No ads. No data selling. No VC pressure.
- BUSL-1.1 for community self-hosted — prevents competitors from reselling

## Business continuity
Source-available under BUSL-1.1. Managed service shutdown does not affect self-hosted operators. Source code permanently available on GitHub.

---

## Competitive positioning

| Competitor | Positioning |
|------------|-------------|
| Zivver | "Zivver stores your files. We don't. One burns, one doesn't." |
| WeTransfer | "WeTransfer is for sharing. Paramant is for zero-trace transport." |
| Tresorit | "Tresorit is secure storage. Paramant is secure transport." |
| Signal | "Signal is for conversations. Paramant is for documents." |

---

## What we do not do
- No email gateway interception (Zivver's core)
- No persistent collaborative storage (Tresorit/Dropbox)
- No mobile apps (browser-first for now)
- No Outlook plugin for Pro (Thunderbird FileLink exists)

---

## Rate limiting — honest copy

Free tier limits are courtesy limits, not hard enforcement guarantees.
Do not promise strict enforcement in marketing copy.
Use: "up to 10 transfers/day" not "maximum 10/day, strictly enforced."
