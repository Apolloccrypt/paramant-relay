# PARAMANT Ghost Pipe — Proof of Concept

Verifieert alle productclaims live tegen de relay. Geen mocks, geen stubs — echte calls.

## Vereisten
```bash
pip install cryptography
```

Python 3.8+ — geen andere dependencies.

## Gebruik
```bash
# Volledige test (alle claims)
python3 paramant_poc.py --key pgp_xxx

# Met rapport opslaan
python3 paramant_poc.py --key pgp_xxx --report

# Specifieke relay
python3 paramant_poc.py --key pgp_xxx --relay https://health.paramant.app

# Zonder E2E (alleen API checks)
python3 paramant_poc.py --key pgp_xxx --skip-e2e
```

## Wat wordt getest

| # | Claim | Hoe getest |
|---|-------|-----------|
| 1 | Alle relay nodes online | GET /health op alle 5 nodes |
| 2 | Post-quantum crypto stack | /health response: ML-DSA, burn-on-read, 5MB padding, EU/DE |
| 3 | API key authenticatie | Geldige/ongeldige key, beveiligd endpoint → 401 |
| 4 | E2E send → relay → receive → burn | Volledige encryptie, upload, download, decrypt, 404 verificatie |
| 5 | 5MB fixed padding | Blobs van 10B tot 100KB — allemaal exact 5MB |
| 6 | Publiek CT log | GET /v2/ct/log — Merkle root + entries |
| 7 | CORS beperkt | evil.com geweigerd, paramant.app toegestaan |
| 8 | Monitor stats | GET /v2/monitor met key |
| 9 | SDK beschikbaar | pypi.org + npmjs.com live check |

## CI/CD integratie
```bash
# Geeft exit code 0 bij succes, 1 bij failure
python3 paramant_poc.py --key $PARAMANT_KEY --report
echo "Exit: $?"
```

## Test key (health relay)
```
Key:   pgp_xxx_redacted
Relay: https://health.paramant.app
```
