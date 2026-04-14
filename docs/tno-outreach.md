# TNO ACQuA outreach — draft email

> **Status:** draft — review before sending  
> **Target:** TNO ACQuA (Applied Cryptography & Quantum-safe Algorithms)  
> **Goal:** explore joint whitepaper or reference architecture listing; position Paramant as operational PQC reference implementation for NEN 7510 / NIS2

---

## Email

**To:** acqa@tno.nl  
**CC:** *(optional: info@tno.nl)*  
**Subject:** Paramant — operational post-quantum relay as reference implementation for NEN 7510 / NIS2

---

Dear ACQuA team,

I am writing because Paramant addresses something that is almost entirely absent from current PQC migration discussions: an operational, open-source file relay running today on ML-KEM-768 (NIST FIPS 203) and ML-DSA-65 (FIPS 204), fully within EU jurisdiction.

**What Paramant is**

Paramant is a post-quantum encrypted file relay built on the Ghost Pipe protocol. Files are encrypted fully client-side using ML-KEM-768 + ECDH P-256 (hybrid), transmitted over AES-256-GCM, and destroyed after the first authorised download — burn-on-read. There is no persistent storage. A Merkle-based CT log records every transfer without retaining the content.

Five live relay sectors (healthcare, legal, finance, industrial IoT, general) run on Hetzner Frankfurt. Source code: https://github.com/Apolloccrypt/paramant-relay

**Why this is relevant to ACQuA**

ACQuA focuses on the practical deployability of post-quantum cryptography — exactly where Paramant sits. Most publicly available PQC implementations are libraries or proof-of-concepts. Paramant is a production system that:

- Applies ML-KEM-768 to a realistic use case (file transfer in healthcare and critical infrastructure)
- Falls fully within NIS2 Annex I/II and NEN 7510-2
- Is verifiable via a public CT log and open source code
- Is in use today, not in two years

**What we propose**

We would like to explore whether there is a basis for collaboration on one or more of the following:

1. **Joint whitepaper** — "PQC in practice: reference implementation for NEN 7510 and NIS2" — written for healthcare institutions and government organisations currently deciding which PQC stack to adopt
2. **Listing as a reference implementation** in ACQuA's migration guidelines or the NCSC PQC factsheets, as a concrete example of ML-KEM-768 in production
3. **Technical review** — we make our codebase, protocol specifications, and audit report (April 2026) available for review by ACQuA, so you can form an independent assessment

We are not asking for commercial endorsement — only the technical conversation.

**Our credentials**

- ML-KEM-768 + ECDH P-256 hybrid key exchange (conforming to FIPS 203 + NIST SP 800-227)
- ML-DSA-65 relay identity certificate
- Independent security audit completed April 2026 (report available)
- 5 live relay sectors, operational
- BUSL-1.1 licence — source code fully transparent

**Request**

Would you be open to a 30-minute conversation to explore whether there is overlap with ongoing ACQuA research? We are happy to work around your schedule.

Kind regards,

*(name)*  
Paramant  
privacy@paramant.app  
https://paramant.app

---

## Sending notes

- Alternative contact: via LinkedIn (TNO Cyber Security & Resilience group)
- NCSC equivalent: ncsc@ncsc.nl — similar email, focus on NCSC PQC factsheet listing
- RvIG / DigiD integration: separate track — establish ACQuA contact first
- Timing: send after public release of the security audit report
