# Swarm-run: Paramant als echte gebruiker op productie (2026-09-08)

Aanpak: hoofdsessie doet zelf de sessie-gebonden flows (die zijn niet parallelliseerbaar: één account, één quotum, één cookiejar), vijf verkenners parallel op alles wat zonder sessie kan. Twee echte Community-accounts aangemaakt op productie via wegwerpmailboxen (mail.tm-API), zodat de registratie- en mailketen echt doorlopen werd in plaats van gesimuleerd.

Kosten: 5 subagents, ~650k subagent-tokens, ~200 tool-calls, ~50 min wallclock.
Resultaat: 5 stille breuken zelf gemeten, 7 tekst-versus-werkelijkheid-afwijkingen, plus 5 verkennerrapporten (publieke crawl, docs versus API, mobiel/a11y, mail/DNS/TLS-infra, twee zelfbouw-audits).
Convergentie: dominante root-cause = **de foutmelding bereikt de gebruiker niet**. Backup-code-login, 5 MB-overschrijding en de inlogpoging op een gedeactiveerd account falen alle drie zonder één zichtbaar woord. Tweede cluster: `limit_req` op het hele `/api/user/`-prefix (nginx-paramant-live.conf:123) veroorzaakt zowel de 429's op /account als de gebruiker die zichzelf uitgelogd ziet.

## Verdeling van het werk

| spoor | wie | waarom daar |
|---|---|---|
| registratie, TOTP, ondertekenen, verify, ParaSend, vault, passkey, co-sign, deactivatie | hoofdsessie | sessie-gebonden, quotum van 2 handtekeningen per maand, niet te splitsen |
| publieke crawl, 119 URL's, security headers | verkenner | read-only, geen sessie |
| docs versus live API, SDK, OpenAPI | verkenner | read-only |
| mobiel en toegankelijkheid, 13 pagina's x 2 viewports | verkenner | eigen browserprofiel, read-only |
| DNS, TLS, SPF/DKIM/DMARC, CT-logs | verkenner | extern, geen browser nodig |
| zelfbouw-audit auth/crypto en infra/frontend | 2 verkenners | codebase, read-only |

## Lessons learned

1. **Meet de sessie via de API, niet via de URL.** Ik concludeerde eerst dat SHA-1-TOTP bij inloggen geweigerd werd, omdat de pagina op `/auth/login` bleef staan. De screenshot liet zien dat de gebruiker gewoon ingelogd was, met een knop "Continue to your account". `GET /api/user/session/verify` is het enige betrouwbare signaal.
2. **Bekijk de screenshot voor je een bevinding opschrijft.** Twee van mijn eerste drie "bugs" overleefden dat niet: een knop die leeg leek (font nog niet geladen) en een user-agent in de PDF (zat al in mijn eigen testbestand).
3. **Een virtuele WebAuthn-authenticator is verplicht gereedschap.** Via CDP `WebAuthn.addVirtualAuthenticator` is de hele passkey-helft van Paramant geautomatiseerd testbaar. Zonder dat is die helft blind vlek.
4. **Wegwerpmailboxen met API maken de mailketen testbaar.** De volgorde klopt alleen als je eerst verifieert en dan pas op de tweede mail wacht: die wordt pas verstuurd na het openen van de verificatielink.
5. **Right-sizing:** vijf verkenners was precies goed. Een zesde op de betaalde flows had niets opgeleverd, want die zitten achter een betaalmuur die we op een testaccount niet halen.

## Niet gedekt

- ParaSend "Hand over live" (vereist twee gelijktijdige browsers aan weerskanten).
- Alles achter een betaald plan: Firm, Business, Enterprise-limieten en de facturatie.
- De `/v1`-API met een `psk_live_`-sleutel, want `/developer` geeft 404 en er is dus geen route om er een te minten.
