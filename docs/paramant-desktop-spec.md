# Paramant Desktop — spec v0.1 (kort)

Mooie, oma-proof app (Windows .exe eerst; later mac/linux) om bestanden te
**vergrendelen** (encrypt -> `.prmnt`), **openen** (decrypt), en **ondertekenen**
(sign -> `.psign`, of encrypt+sign in één `.prmnt`). Alles client-side, server-blind,
offline, post-quantum, in Paramant-stijl. De webapp IS de exe (Tauri-shell eromheen).

## Sleutelmodel (de belangrijke keuze)
- **Sleutelbron = passkey-PRF** (Windows Hello / Face ID). Geen wachtwoorden.
  Hergebruikt de bestaande signing-identity.
- **TOTP = optionele extra-gate bij openen, NIET de sleutel** (code, geen sleutel;
  seed is server-side -> mag de sleutel niet bepalen, anders breekt server-blind).
- **Recovery = verplichte backstop** (anders: device kwijt = bestand voorgoed weg):
  minstens één extra key-slot, aanbevolen **geprinte herstel-sleutel** (default-aan,
  vriendelijk ritueel), optioneel **tweede passkey** en/of **passphrase-slot**.

## `.prmnt` container
```
PRMNT  v1   suite: ML-KEM-768 + AES-256-GCM (FIPS)   domain: "paramant/prmnt/v1"
meta (authenticated, cleartext): filename, mime, size, created, optioneel signer-fp
key-slots[]:   - { kem:        wrap CEK naar passkey-pubkey }      (voor mij)
               - { recovery:   wrap CEK naar geprinte sleutel }   (backstop)
               - { passphrase: salt + kdf-params }                (draagbaar)
               - { kem:        naar iemands pubkey }              (voor anderen)
ciphertext: AES-256-GCM(bestand) onder content-key (CEK); nonce + tag
[optioneel] embedded .psign  -> bestand tegelijk versleuteld EN ondertekend
```
Spiegelt het bestaande `.psign`-envelope (recipients[]/magic/versie/domain), dus
hergebruikt `crypto-bridge.js` + `noble-mlkem` + de envelope-code.

## Schermen (oma-proof, DocuSign-stijl wijs-en-klik)
- **Home**: 3 grote kaarten + sleep-zone — "Vergrendel een bestand" · "Open een
  .prmnt" · "Onderteken".
- **Vergrendelen**: bestand -> "Voor mij" (default) / "Met wachtwoord" / "Voor
  iemand" -> Face/PIN -> "Klaar, hier staat 't [Open map]". Eerste keer: print
  herstel-sleutel.
- **Openen**: sleep `.prmnt` -> Face/PIN -> bestand terug.
- **Onderteken**: ParaSign-flow met de pdf.js-vijf (multi-page, zoom, tekstlaag/
  zoeken, annotaties, sleep-stempel), gele-tag "teken hier"-begeleiding, handtekening
  onthouden, voortgang, helder eindscherm.
- Mensentaal, één hoofdactie per scherm, preview vóór commit, geruststelling
  "verlaat deze computer niet".

## Tauri-architectuur
- Webapp (HTML/JS/wasm) in **Tauri** (Rust shell + systeem-WebView2) -> ~5-10MB exe.
- **Windows Hello** = WebAuthn-passkey via WebView2.
- **Shell-integratie**: rechtsklik "Versleutel/Onderteken met Paramant" + `.prmnt`/
  `.psign` dubbelklik-koppeling (de oma-killer-feature).
- Offline-first; relay alleen voor versturen. **Code-signed** exe + auto-update.

## Stijl
Navy/cobalt + lime-accent, Inter + mono, hexagon-mark, hairlines, veel witruimte,
rustige grote afgeronde knoppen.

## Scope
- **v1**: encrypt/decrypt/sign lokaal · `.prmnt` · passkey + geprinte recovery +
  passphrase · web + Tauri-exe + shell-integratie.
- **v2**: Paramant-gehoste vault (durable storage), mac/linux, mobiel.
