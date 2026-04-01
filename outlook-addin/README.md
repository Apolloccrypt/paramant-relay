# ParaShare — Outlook Add-in

Stuur bijlagen als zelfvernietigende links direct vanuit Outlook.

## Wat het doet

1. Klik **Send via ParaShare** in de compose toolbar
2. Vul je API key in (wordt lokaal onthouden)
3. Selecteer welke bijlagen je wilt vervangen
4. Klik **Replace with ParaShare link →**
5. Bijlagen worden verwijderd, beveiligde download-links worden in de mail ingevoegd
6. Ontvanger klikt de link — downloadt het bestand — het wordt vernietigd

## Installatie (Sideload)

### Outlook Web (OWA)
1. Ga naar outlook.office.com
2. Tandwiel → **View all Outlook settings**
3. Mail → Customize actions → **Manage add-ins**
4. **+ Add a custom add-in** → Add from file
5. Upload `manifest.xml`
6. Open een nieuw bericht → **Send via ParaShare** verschijnt in de toolbar

### Outlook Desktop (Windows)
1. Bestand → Opties → Invoegtoepassingen
2. **COM-invoegtoepassingen beheren** → Ga naar → Toevoegen
3. Selecteer `manifest.xml`

### Outlook Desktop (Mac)
1. Extra → Invoegtoepassingen → **+**
2. Upload `manifest.xml`

### Organisatie-brede rollout (Microsoft 365 Admin)
1. Microsoft 365 Admin Center → Settings → Integrated apps
2. Upload custom app → `manifest.xml`
3. Wijs toe aan gebruikers of groepen

## Vereisten

- Outlook 365 (web, Windows of Mac)
- Microsoft 365 account
- PARAMANT API key (vanaf €9.99/mnd via [paramant.app](https://paramant.app))

## Beveiliging

| | |
|---|---|
| Encryptie | AES-256-GCM in de browser, vóór upload |
| Relay | Slaat nooit plaintext op — alleen versleutelde 5MB blobs |
| Burn-on-read | Na één download bestaat de file nergens meer |
| Locatie | EU/DE servers (Hetzner Frankfurt) — geen US CLOUD Act |
| TTL | Links verlopen automatisch na 10 minuten |
| Padding | Elke blob is exact 5MB — bestandsgrootte onzichtbaar |

## Contact

privacy@paramant.app
