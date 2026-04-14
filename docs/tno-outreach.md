# TNO ACQuA outreach — draft email

> **Status:** draft — review before sending  
> **Target:** TNO ACQuA (Applied Cryptography & Quantum-safe Algorithms)  
> **Goal:** explore joint whitepaper or reference architecture listing; position Paramant as operational PQC reference implementation for NEN 7510 / NIS2

---

## Email

**To:** acqa@tno.nl  
**CC:** *(optional: info@tno.nl)*  
**Subject:** Paramant — operationele post-quantum relay als referentie-implementatie voor NEN 7510 / NIS2

---

Beste ACQuA-team,

Ik schrijf jullie omdat Paramant iets is wat in de PQC-migratiediscussie nog vrijwel ontbreekt: een operationele, open-source bestandsrelay die vandaag draait op ML-KEM-768 (NIST FIPS 203) en ML-DSA-65 (FIPS 204), volledig binnen EU-jurisdictie.

**Wat Paramant is**

Paramant is een post-quantum versleutelde bestandsrelay gebouwd op het Ghost Pipe-protocol. Bestanden worden volledig client-side versleuteld met ML-KEM-768 + ECDH P-256 (hybride), via AES-256-GCM versleuteld verstuurd, en vernietigd na de eerste geautoriseerde download — burn-on-read. Er is geen persistente opslag. Een Merkle-gebaseerd CT-log legt elke overdracht vast zonder de inhoud te bewaren.

Vijf live relay-sectoren (zorg, juridisch, financieel, industrieel IoT, algemeen) draaien op Hetzner Frankfurt. Broncode: https://github.com/Apolloccrypt/paramant-relay

**Waarom relevant voor ACQuA**

ACQuA richt zich op de praktische inzetbaarheid van post-quantum cryptografie — precies waar Paramant zit. De meeste PQC-implementaties die publiek beschikbaar zijn, zijn libraries of proof-of-concepts. Paramant is een productiesysteem dat:

- ML-KEM-768 toepast op een realistisch use-case (bestandsoverdracht in zorgsector en kritieke infrastructuur)
- Volledig binnen NIS2 Annex I/II en NEN 7510-2 valt
- Verifieerbaar is via een publieke CT-log en open broncode
- Vandaag in gebruik is, niet over twee jaar

**Wat we voorstellen**

We zouden graag verkennen of er basis is voor samenwerking op één van de volgende punten:

1. **Gezamenlijke whitepaper** — "PQC in de praktijk: referentie-implementatie voor NEN 7510 en NIS2" — geschreven voor zorginstellingen en overheidsorganisaties die nu de afweging maken welke PQC-stack ze adopteren
2. **Vermelding als referentie-implementatie** in ACQuA's migratie-guidelines of de NCSC PQC-factsheets, als concreet voorbeeld van ML-KEM-768 in productie
3. **Technische review** — we stellen onze codebase, protocolspecificaties en auditrapport (2026-04) open voor review door ACQuA, zodat jullie een onafhankelijk oordeel kunnen geven

We vragen geen commerciële endorsement — alleen de technische discussie.

**Onze credentials**

- ML-KEM-768 + ECDH P-256 hybride sleutelwisseling (conform FIPS 203 draft + NIST SP 800-227)
- ML-DSA-65 relay-identiteitscertificaat
- Onafhankelijk security-audit afgerond april 2026 (rapport beschikbaar)
- 5 live relay-sectoren, operationeel
- BUSL-1.1 licentie — broncode volledig inzichtelijk

**Vraag**

Zouden jullie open staan voor een gesprek van 30 minuten om te verkennen of er overlap is met lopend ACQuA-onderzoek? We passen ons aan aan jullie agenda.

Met vriendelijke groet,

*(naam)*  
Paramant  
privacy@paramant.app  
https://paramant.app

---

## Notes voor verzending

- Alternatief contactadres: via LinkedIn (TNO Cyber Security & Resilience groep)
- NCSC equivalent: ncsc@ncsc.nl — vergelijkbare email, focus op NCSC PQC-factsheet vermelding
- RvIG / DigiD-aansluiting: apart traject — eerst ACQuA-contact leggen
- Timing: verstuur na publieke vermelding van het security-audit rapport
