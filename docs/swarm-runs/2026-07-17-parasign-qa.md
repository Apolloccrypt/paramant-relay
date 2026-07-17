# Swarm-run: ParaSign QA (2026-07-17)

Aanpak: 7 pad-verkenners (solo-pdf, edit-tools, image, hash-only, cosign-invite, edge-inputs, mobiel-a11y) met echte Playwright/Chromium-runs op de NUC tegen frontend/ over een lokale statische server, daarna adversariele reproductie per bevinding.

Kosten: 43 agents, ~2.25M subagent-tokens, 757 tool-calls, ~49 min wallclock.
Resultaat: 36 ruwe -> 35 bevestigd, 1 afgewezen na verificatie.
Convergentie: dominante root-cause = click-na-drag/resize/edit herplaatst de zegel (onPlaceClick), raakte 3 HOOG-bevindingen tegelijk.

## Bevestigde bevindingen
1. [hoog] (solo-pdf) Stempel-resize wordt bij loslaten ongedaan gemaakt en de stempel springt naar de cursorpositie
   Alone-modus, PDF laden, stempel plaatsen, dan de blauwe hoekgrip (.ds-stamp-resize) slepen (+80px) en loslaten. De browser vuurt na pointerup een click-event dat via de wrap in onPlaceClick belandt; d

2. [hoog] (solo-pdf) Review-preview tekent het zegel op de verkeerde plek en het verkeerde formaat; slepen in review corrumpeert de echte zegelpositie
   Stempel plaatsen op ~30% linksboven, door naar review. De zoombar wordt als eerste kind in het flex-row paneel (.ds-review-pane, display:flex) gezet en drukt het document van 407px naar 200px; de zege

3. [hoog] (solo-pdf) Stempel-state overleeft documentwissel: spookstempel van het vorige document, Continue her-enabled door pagina-operatie
   Alone-modus, 5p-PDF laden, stempel op p3, Back naar documentkeuze, 2p-PDF laden (Continue staat dan terecht uit), daarna een willekeurige pagina-operatie (bijv. p1 roteren). runPageOp zet Continue op 

4. [middel] (solo-pdf) Highlight en note zijn onzichtbaar/verkeerd gepositioneerd in de review-preview (NaN-stijlen), pen-strokes idem
   Op de Place-stap een +Highlight en +Note plaatsen, door naar review. De loop rekent voor elk extra extraBoxH(ex.size) en top uit ex.y; highlight heeft geen size (NaN-height), note heeft yTop i.p.v. y 

5. [middel] (solo-pdf) Naam typen in de identity-stap sloopt de resize-grip van de stempelmarker
   Stempel plaatsen, Continue naar identity, naam typen (elke input-event herschrijft el.innerHTML = stampMockupHtml() van de marker), Back naar Place: de grip is weg en resizen kan niet meer tot je de s

6. [middel] (solo-pdf) Proof-JSON in review wordt niet bijgewerkt na het slepen van het zegel in de review zelf
   In review het zegel slepen; de 'Cryptographic proof'-kaart (coords in ds-proof-json) blijft de oude x/y tonen terwijl state.stamp wel gewijzigd is (en dus bij tekenen de nieuwe positie gebakken wordt)

7. [laag] (solo-pdf) Edit-toolbar niet sticky: highlight/note landen op de verkeerde pagina bij meerpaginadocumenten
   Scroll naar pagina 3 van een 5p-doc en plaats daar tekst (landt goed op p3). Om +Highlight of +Note te bereiken moet je terug omhoog scrollen; de IntersectionObserver zet _placeCurrentPage dan op de b

8. [hoog] (edit-tools) Slepen of resizen van elk edit-object plaatst/verplaatst stilletjes de handtekening-stempel naar die plek
   Upload PDF (sign alone) -> + Text, typ, Enter -> sleep het tekstobject. Na pointerup verschijnt de seal-stempel gecentreerd op de dropplek en wordt Continue enabled, zonder dat de gebruiker ooit op de

9. [hoog] (edit-tools) Dubbelklik-bewerken is dood: editor opent nooit, stempel schiet onder de cursor
   + Date plaatsen -> dubbelklik op het datumobject. Verwacht: contentEditable-editor. Werkelijk: editing-element count blijft 0 en de seal-stempel wordt op de dubbelklik-plek geplaatst (stamp fx 0.029/f

10. [hoog] (edit-tools) Review-preview zet stempel en tekst/datum-objecten op 2x de juiste positie (stempel zelfs volledig onder de pagina)
   Flow t/m review met stempel + tekst + datum. Vergelijk fractionele positie (left/canvasbreedte) in place-stap vs review-preview.

11. [hoog] (edit-tools) Review-preview rendert highlight, note en pen-strokes als kapotte stubs (verkeerde positie, geen opmaak, 'undefined'-velden)
   Plaats highlight + note + pen-stroke, ga naar review. Verwacht: gele balk, notitieblok en stroke op hun plek. Werkelijk: elementen zonder top/height in flow onder de pagina.

12. [middel] (edit-tools) Sticky paginanavigatie valt achter de site-header: knoppen onklikbaar en muisklik raakt menu-links
   Document 6 pagina's, jump naar pagina 5 (scrollY ~5240). De pill 'Page 5 of 6' pint op top:8px, binnen de 56px hoge site-header.

13. [polijst] (edit-tools) Sign-gate zonder account: nette blokkade met foutbanner, knop komt terug
   Sign this document klikken op statische server zonder API/account.

14. [hoog] (image-flow) Back-knop op identity-stap stuurt afbeeldingsmodus naar dood hash-only-scherm
   sign.html op statische server (poort 8403) > modus 'Sign it myself' > PNG laden (/tmp/qa8403-test.png) > stempel plaatsen > Continue > op step-identity op 'Back' klikken.

15. [middel] (image-flow) Review-preview van afbeelding: vervormd beeld en zegel-mockup op verkeerde positie/schaal
   PNG 1200x900 laden > stempel plaatsen op ~40%/40% > Continue > naam invullen > Continue naar 'Review and sign' > preview-pane meten; daarna mockup 50px slepen en via Back+Continue opnieuw renderen.

16. [middel] (image-flow) Niet-decodeerbare afbeelding: onafgevangen promise-rejection en stil doodlopend plaatsingsscherm
   Bestand met geldige PNG-magic + 2000 random bytes (/tmp/qa8403-garbage.png) kiezen via #ds-doc-input.

17. [laag] (image-flow) Afgeknotte PNG rendert grotendeels blanco zonder waarschuwing en is gewoon signeerbaar
   Eerste 4000 van 32647 bytes van een geldige PNG (/tmp/qa8403-trunc.png) kiezen via #ds-doc-input.

18. [polijst] (image-flow) Copy op bestandskeuze-stap verzwijgt dat afbeeldingen ook een visuele stempel krijgen
   sign.html openen > modus kiezen > tekst boven de dropzone lezen, daarna een PNG laden.

19. [middel] (hash-only) Corrupt bestand met %PDF-magic strandt stil op de plaatsingsstap (unhandled InvalidPDFException)
   Kies op /sign.html (modus 'Sign it myself') een bestand waarvan de bytes met %PDF beginnen maar dat geen geldige PDF is. Twee varianten gereproduceerd: /tmp/qa8404/corrupt.pdf en /tmp/qa8404/fake-pdf.

20. [laag] (hash-only) Leeg bestand (0 bytes) is zonder waarschuwing volledig ondertekenbaar
   Kies een 0-byte bestand (/tmp/qa8404/empty.bin) op /sign.html en loop door naar review.

21. [polijst] (hash-only) Stepper toont 'Place' als actieve stap tijdens hash-only-modus
   Laad een niet-PDF (bv. test.txt); step-hash-only wordt actief.

22. [polijst] (hash-only) Review-kop 'Document preview - visual seal' + stamp-caption misleidend in hash-only-modus
   Doorloop hash-only met test.txt tot de reviewstap.

23. [hoog] (cosign-invite) Co-signer met alleen e-mail (naam leeg) wordt stilzwijgend gedropt; flow gaat door als solo-handtekening
   sign.html > modus Co-sign > PDF uploaden > stempel plaatsen > Continue > + Add recipient > alleen e-mail invullen (carol@example.com), naam leeg laten > Continue > naam invullen > Continue.

24. [middel] (cosign-invite) Invite-modus geeft misleidende foutmelding bij rij met e-mail maar zonder naam
   sign.html > modus Request signatures (invite) > PDF uploaden > + Add recipient > alleen e-mail (bob@example.com) invullen > Send for signature.

25. [laag] (cosign-invite) Invite-send-gate toont rauwe foutcode 'http_404' aan de gebruiker
   Invite-flow met geldige ontvanger (Bob, bob@example.com) > Send for signature tegen een server zonder backend (statische server, POST envelope faalt met 404).

26. [polijst] (cosign-invite) Validatie-foutmelding in recipients-stap wordt niet gewist na succesvolle Continue of terug-navigatie
   Cosign-flow > recipient met ongeldig e-mailadres > Continue (fout verschijnt) > adres fixen of rij naamloos maken > Continue (gaat door naar identity) > Back.

27. [hoog] (edge-inputs) Corrupte/afgeknotte PDF met geldige %PDF-header strandt op leeg Place-scherm zonder foutmelding (uncaught InvalidPDFException)
   sign.html > mode 'Sign it myself' > kies een bestand dat begint met '%PDF-1.7' gevolgd door garbage (/tmp/qa8406-garbagebody.pdf), of een halverwege afgeknotte geldige PDF (/tmp/qa8406-truncated.pdf, 

28. [middel] (edge-inputs) Stempel kan niet geplaatst worden op pagina 31+ van een groot document; cap-melding legt dat niet uit en page-nav toont verkeerd totaal
   sign.html > 'Sign it myself' > 45-pagina A4-PDF gegenereerd met pdf-lib (/tmp/qa8406-big45.pdf, 12.6 KB).

29. [laag] (edge-inputs) 0-byte bestand krijgt zonder waarschuwing een hash-only attestatie; Continue staat aan voor een leeg document
   sign.html > 'Sign it myself' > kies 0-byte bestand /tmp/qa8406-empty.pdf.

30. [polijst] (edge-inputs) PDF met kapotte header valt stil terug naar hash-only zonder uitleg dat het bestand als PDF onleesbaar is
   sign.html > 'Sign it myself' > bestand met .pdf-naam maar zonder %PDF-magic (/tmp/qa8406-badheader.pdf, 4 KB garbage).

31. [hoog] (mobiel-a11y) Co-signer met alleen e-mail wordt stilzwijgend weggegooid; flow wordt zonder waarschuwing een persoonlijke handtekening
   iPhone 14-viewport: kies 'Sign together' (cosign), kies PDF, plaats stempel, Continue. Op de Co-signers-stap: tik '+ Add recipient', vul ALLEEN het e-mailveld (collega@example.com), laat naam leeg, ti

32. [middel] (mobiel-a11y) Geplaatste tekst/datum-annotatie is op touch niet opnieuw te bewerken (alleen dblclick gewired)
   PDF geladen, '+ Text' getikt, 'Eerste' getypt, Enter (commit). Daarna 2x snel tikken op de annotatie: eenmaal via rauwe touchscreen.tap-coördinaten (80ms interval) en eenmaal via locator.tap 2x.

33. [middel] (mobiel-a11y) Meerdere tap-doelen in de plaats-stap onder het 24px-minimum (WCAG 2.5.8) en ver onder iOS 44pt
   PDF geladen in de plaats-stap op 390px; alle interactieve elementen gemeten via getBoundingClientRect.

34. [middel] (mobiel-a11y) Annotaties en stempel zijn niet met toetsenbord te bedienen (verplaatsen/resizen/bewerken pointer-only)
   Tekst-annotatie aangemaakt en gecommit; daarna attributen en event-wiring geinspecteerd en taborder doorlopen.

35. [laag] (mobiel-a11y) Pagina-actiebalk (verplaats/roteer/verwijder) blijft op touch permanent op 30% zichtbaarheid
   PDF geladen op iPhone 14-profiel (touch, geen hover); computed opacity van .ds-page-bar uitgelezen.

