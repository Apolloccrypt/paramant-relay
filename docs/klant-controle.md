# Zelf controleren dat uw verzending in de log staat

`scripts/klant-controle.py` laat een klant zelf nagaan dat een ParaSend-verzending in de transparantielog van Paramant staat. Zonder account, zonder Paramant-code, met alleen Python 3 en OpenSSL.

Herkomst: het onafhankelijke CT-onderzoek van 6 oktober 2026 (`paramant-bewijs/ct-onderzoek-2026-10-06`, scripts `klant_controle.py` en `ctverify.py`). Daar is deze controle met eigen code nagerekend op echte bladen van health (4900) en relay (777). De tool is die code, opgeschoond en getest.

## Wat u nodig hebt

- Python 3.8 of nieuwer. Alleen de standaardbibliotheek.
- OpenSSL 3.5 of nieuwer, voor de ML-DSA-65-handtekeningen. Met een oudere OpenSSL lopen alle andere stappen gewoon. De handtekeningstappen staan dan op "niet gecontroleerd" en de uitslag is ONVOLLEDIG, nooit AANGETOOND.
- Het ontvangstbewijs van uw verzending (de `X-Paramant-Receipt`-kop bij het ophalen, als base64url of als JSON).
- De gepinde sleutels in `frontend/js/relay-trust-anchors.js`. De tool leest ze daaruit en controleert per sleutel de SHA3-vingerafdruk. Hij heeft geen eigen kopie.

## Gebruik

```
python3 scripts/klant-controle.py ontvangstbewijs.json
python3 scripts/klant-controle.py - < ontvangstbewijs.txt
python3 scripts/klant-controle.py --index 777 --relay https://relay.paramant.app
python3 scripts/klant-controle.py bewijs.json --relay https://mijn-relay.example --pubkey <base64>
```

`--json` geeft de uitslag machineleesbaar. Exitcodes: `0` aangetoond, `1` een controle faalt, `2` gebruik- of netwerkfout, `3` onvolledig (handtekening niet gecontroleerd).

## Wat de tool doet

Met een ontvangstbewijs:

1. Het blad opnieuw berekenen uit `blob_hash`, `sector` en `ts` van het bewijs: `SHA3-256(0x02 || blob_hash || SHA3-256(sector) || ts)`, dezelfde formule als `relay/lib/ct-hash.js`.
2. Het inclusiebewijs uit het ontvangstbewijs narekenen naar de root van toen (RFC 9162, 2.1.3.2).
3. Controleren dat de boomtop in het bewijs bij die root en grootte hoort, en dat zijn handtekening klopt onder de gepinde sleutel van de relay die het bewijs noemt.
4. In de openbare boom nagaan dat op die positie hetzelfde blad staat (`/v2/ct/proof/<positie>`, uit de volledige boom; `/v2/ct/log` toont alleen de laatste 10.000 en is alleen de terugval voor een relay zonder die route).
5. Het consistentiebewijs van de boom van toen naar de huidige boomtop narekenen (RFC 9162, 2.1.4.2). Dat toont dat er sindsdien alleen is bijgeschreven.
6. De handtekening onder de huidige boomtop controleren tegen dezelfde gepinde sleutel.

Zonder ontvangstbewijs (`--index`) doet hij stap 4 tot en met 6 op een openbaar blad, met het inclusiebewijs dat de relay via `/v2/ct/proof` geeft. De naam van de relay komt dan uit de boomtop zelf. Dat is geen vertrouwen op de relay: de handtekening moet kloppen onder de gepinde sleutel van precies die naam.

## Wat dit wel en niet aantoont

Wel (bevestigd, zie de test hieronder): uw blad staat in de boom die de relay nu ondertekent, en die boom is een ongewijzigde aanvulling op de boom uit uw ontvangstbewijs. Een relay die na uw verzending een blad weghaalt of herschrijft, valt hierop door de mand.

Niet:

- **Dat anderen dezelfde boom zien.** De relay kan elke klant een eigen, intern kloppende boom laten zien. Om dat te ontdekken moet iemand buiten Paramant de boomtoppen bewaren en vergelijken. Dat gebeurt nu niet. Zie `docs/ontwerp-ct-witness.md` voor het voorstel.
- **Wie de verzending deed of wat erin zat.** Het blad bevat alleen de hash van de versleutelde inhoud.
- **Dat het ophalen in de log staat.** Alleen het uploaden komt in de CT-log. Ophalen en `/v2/ack` gaan naar een privé-auditketen van de relay, die u niet kunt inzien.

## ParaSign-handtekeningen: kan nog niet

Voor een ParaSign-envelope werkt deze controle nog niet, en dat schrijven we liever eerlijk op:

- De verificatiepagina voor ParaSign kijkt niet in de log. Hij toont hooguit een indexnummer.
- Een envelope-blad hangt af van gegevens die de klant niet heeft: het tijdstip tot op de milliseconde en de volledige payload staan niet in het bewijs dat u krijgt. U kunt het blad dus niet zelf herberekenen, en zonder dat blad is er niets om in de boom terug te vinden.

Daarvoor moet het bewijs van een ParaSign-envelope eerst de invoer van het blad meekrijgen, of een inclusiebewijs zoals een ParaSend-ontvangstbewijs dat heeft. Tot dat gebouwd is, weigert de tool een bestand zonder `blob_hash` en `inclusion_proof` met die melding.

## Getest

`tests/klant-controle.test.mjs`, in de CI-job met de integratiesuites zonder browser:

- Echt blad 777 van relay.paramant.app, met de echte boomtop van 1523 bladen en de pin uit `relay-trust-anchors.js`: alle stappen kloppen. De fixture (`tests/fixtures/klant-controle/relay-777.json`) is herberekend met `relay/lib/ct-tree.js` over alle 1523 opgehaalde bladen.
- Sabotage: één byte anders in het auditpad, de root, de handtekening of het blad geeft "niet aangetoond".
- Een boomtop die een relay zonder pin noemt, is zonder `--pubkey` nooit "aangetoond". Met `--pubkey` kan het wel, en de uitslag meldt dan dat de sleutel door u is opgegeven en niet gepind.
- Een ontvangstbewijs waarvan het blad buiten het venster van `/v2/ct/log` valt, wordt nog steeds aangetoond.
- Een ontvangstbewijs dat zich relay.paramant.app noemt maar met een andere sleutel is ondertekend, wordt door de pin geweigerd.
- Een ontvangstbewijs van een zelf gehoste relay met een opgegeven sleutel klopt, en wordt gemeld als niet gepind.

In CI heeft de runner OpenSSL 3.0. Daar toetst de suite dat de uitslag dan ONVOLLEDIG is. Lokaal, met OpenSSL 3.5, lopen de handtekeningstappen echt.

## English summary

`scripts/klant-controle.py` lets a customer check, with nothing but Python 3 and OpenSSL 3.5+, that a ParaSend transfer receipt is in Paramant's transparency log: it recomputes the leaf from the receipt, verifies the receipt's inclusion proof and head signature, finds the same leaf at that position in the full tree (`/v2/ct/proof`, so also past the 10,000 entries `/v2/ct/log` lists), verifies an RFC 9162 consistency proof from the receipt's tree to the current signed head, and checks that head against the key pinned in `frontend/js/relay-trust-anchors.js`. It proves the leaf is in the tree the relay signs now and that nothing was removed since. It does not prove that other people see the same tree: without an independent party storing signed heads, a split view cannot be detected. It does not work for ParaSign signatures yet, because the ParaSign verifier does not consult the log and the customer lacks the inputs needed to recompute an envelope leaf.
