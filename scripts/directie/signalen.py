#!/usr/bin/env python3
"""Directiesignalen: de staat van Paramant in een oogopslag, zonder model.

Dit script meet, het oordeelt niet met een taalmodel. Het stelt een vaste lijst
vragen aan GitHub (via gh) en aan productie (via curl), zet elke uitkomst om in
een ernst (rood, oranje, groen), een meting en een voorstel van een zin, en
schrijft dat als JSON naar stdout. Met --tekst komt er leesbare tekst uit.

Exit 0 als er niets rood is, 1 als er wel iets rood is, 2 bij een fout in het
script zelf. Zo kan een cron of een latere ronde op de exitcode sturen.

Gebruik:
    python3 scripts/directie/signalen.py            # JSON
    python3 scripts/directie/signalen.py --tekst    # leesbaar
    python3 scripts/directie/signalen.py --repo eigenaar/repo

Afhankelijkheden: Python 3 standaardbibliotheek, plus de commando's gh en curl.
Meer niet, met opzet: dit moet ook draaien op een kale machine.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys
import zipfile
from datetime import datetime, timezone

# Drempels. Bewust bovenaan en met een reden, zodat een discussie over "wanneer
# is iets rood" hier gevoerd wordt en niet verstopt zit in een if.

# Een pull request die langer dan dit open staat is geen werk meer maar voorraad.
PR_OUD_UREN = 72
# Dependabot: een openstaande update is hinder, een oude is een risico.
DEPENDABOT_OUD_UREN = 14 * 24
# Gefaalde workflow-runs tellen we over dit venster.
RUNS_VENSTER_UREN = 24
# De heartbeat draait op :17, dus elk uur een uitslag. Is de laatste afgeronde
# run ouder dan dit, dan is er minstens een ronde overgeslagen en meet niemand
# meer mee. Twee uur, niet zes: een alarm dat een halve dag stil mag staan is
# geen alarm.
HEARTBEAT_ROOD_UREN = 2
# Responstijd van de homepage.
HOMEPAGE_ORANJE_S = 1.0
HOMEPAGE_ROOD_S = 2.5

GH_TIMEOUT = 60
CURL_TIMEOUT = 15

PRODUCTIE_HEALTH = "https://paramant.app/health"
PRODUCTIE_HOME = "https://paramant.app/"

# De zes hosts waar de ParaID-uitgifteroute dicht hoort te zijn. ParaID is uit
# het product gehaald; blijft de route ergens antwoorden, dan draait daar oude
# code of stuurt een proxy verkeer naar iets wat er niet meer hoort te zijn.
PARAID_DENY_PAD = "/v1/paraid/issue-document"
PARAID_HOSTS = [
    "paramant.app",
    "relay.paramant.app",
    "health.paramant.app",
    "legal.paramant.app",
    "finance.paramant.app",
    "iot.paramant.app",
]

# Het uurlijkse alarm. Sinds PR #338 draait dat in .github/workflows/heartbeat.yml
# en is product-heartbeat.yml alleen nog de gate op pull requests. De drie oude
# kanariestappen bestaan daar niet meer, dus zoeken naar hun stapnamen leverde
# drie keer oranje "geen uitslag" op terwijl er niets stuk was.
HEARTBEAT_WORKFLOW = "heartbeat.yml"
PR_GATE_WORKFLOW = "product-heartbeat.yml"
# De job draait alleen bij een handmatige start of als deze repositoryvariabele
# op true staat.
HEARTBEAT_VARIABELE = "HEARTBEAT_ENABLED"
# Zonder deze twee gaat de run rood met de naam van de sleutel, met opzet.
HEARTBEAT_SLEUTELS = ("PARAMANT_CANARY_KEY", "PARASIGN_CANARY_KEY")
# De titel die de workflow zelf aan zijn alarmissue geeft.
HEARTBEAT_ISSUE_TITEL = "Heartbeat rood"
# De stappen van scripts/heartbeat/run.mjs, gegroepeerd zoals de directie ze
# kent. parasign zijn er in het script twee: een receipt over /v1 en de publieke
# tekenceremonie over /v2. Hier is dat een signaal, want het product is pas heel
# als ze allebei kloppen.
HEARTBEAT_STAPPEN = [
    ("surface", ("surface",)),
    ("parasend", ("parasend",)),
    ("parasign", ("parasign-receipt", "parasign-public-sign")),
]

ROOD, ORANJE, GROEN = "rood", "oranje", "groen"
ERNST_ORDE = {ROOD: 0, ORANJE: 1, GROEN: 2}

# Conclusies van GitHub Actions die we als kapot lezen.
KAPOT = {"failure", "timed_out", "startup_failure", "action_required"}


# ---------------------------------------------------------------- hulpmiddelen

def nu() -> datetime:
    return datetime.now(timezone.utc)


def tijdstip(waarde: str | None) -> datetime | None:
    """ISO-8601 uit de GitHub-API naar een datetime, of None."""
    if not waarde:
        return None
    tekst = waarde.strip().replace("Z", "+00:00")
    try:
        stempel = datetime.fromisoformat(tekst)
    except ValueError:
        return None
    if stempel.tzinfo is None:
        stempel = stempel.replace(tzinfo=timezone.utc)
    if stempel.year < 1970:  # GitHub schrijft 0001-01-01 voor "nog niet"
        return None
    return stempel


def uren_geleden(stempel: datetime | None) -> float | None:
    if stempel is None:
        return None
    return (nu() - stempel).total_seconds() / 3600.0


def duur(uren: float | None) -> str:
    if uren is None:
        return "onbekend"
    if uren < 1:
        return f"{uren * 60:.0f} min"
    if uren < 48:
        return f"{uren:.1f} uur"
    return f"{uren / 24:.1f} dagen"


def gh_json(args: list[str]) -> tuple[object | None, str | None]:
    """Draai gh met een --json-vlag en geef de geparste uitvoer terug."""
    try:
        klaar = subprocess.run(
            ["gh", *args],
            capture_output=True, text=True, timeout=GH_TIMEOUT,
        )
    except FileNotFoundError:
        return None, "gh is niet geinstalleerd"
    except subprocess.TimeoutExpired:
        return None, f"gh gaf geen antwoord binnen {GH_TIMEOUT}s"
    if klaar.returncode != 0:
        fout = (klaar.stderr or klaar.stdout or "").strip().splitlines()
        return None, fout[-1] if fout else f"gh eindigde met code {klaar.returncode}"
    if not klaar.stdout.strip():
        return None, "gh gaf een lege uitvoer"
    try:
        return json.loads(klaar.stdout), None
    except json.JSONDecodeError as exc:
        return None, f"gh gaf geen geldige JSON ({exc})"


def gh_bytes(args: list[str]) -> tuple[bytes | None, str | None]:
    """Draai gh en geef de ruwe uitvoer terug. Nodig voor het bewijsartefact van
    de heartbeat: dat is een zipbestand, geen JSON."""
    try:
        klaar = subprocess.run(["gh", *args], capture_output=True, timeout=GH_TIMEOUT)
    except FileNotFoundError:
        return None, "gh is niet geinstalleerd"
    except subprocess.TimeoutExpired:
        return None, f"gh gaf geen antwoord binnen {GH_TIMEOUT}s"
    if klaar.returncode != 0:
        fout = (klaar.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        return None, fout[-1] if fout else f"gh eindigde met code {klaar.returncode}"
    if not klaar.stdout:
        return None, "gh gaf een lege uitvoer"
    return klaar.stdout, None


def curl_meting(url: str, methode: str = "GET", body: str | None = None) -> dict:
    """Statuscode en responstijd van een URL. Geen redirects volgen: we willen
    weten wat deze host zelf antwoordt, niet waar hij naartoe wijst."""
    cmd = [
        "curl", "-s", "-S", "-o", os.devnull,
        "-w", "%{http_code} %{time_total}",
        "--max-time", str(CURL_TIMEOUT),
    ]
    if methode != "GET":
        cmd += ["-X", methode]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "--data", body]
    cmd.append(url)
    try:
        klaar = subprocess.run(cmd, capture_output=True, text=True, timeout=CURL_TIMEOUT + 10)
    except FileNotFoundError:
        return {"url": url, "status": None, "seconden": None, "fout": "curl is niet geinstalleerd"}
    except subprocess.TimeoutExpired:
        return {"url": url, "status": None, "seconden": None, "fout": "curl liep vast"}
    if klaar.returncode != 0:
        fout = (klaar.stderr or "").strip().splitlines()
        return {
            "url": url, "status": None, "seconden": None,
            "fout": fout[-1] if fout else f"curl eindigde met code {klaar.returncode}",
        }
    delen = klaar.stdout.split()
    if len(delen) != 2:
        return {"url": url, "status": None, "seconden": None, "fout": "curl gaf een onleesbare meting"}
    try:
        return {"url": url, "status": int(delen[0]), "seconden": float(delen[1]), "fout": None}
    except ValueError:
        return {"url": url, "status": None, "seconden": None, "fout": "curl gaf een onleesbare meting"}


def signaal(sleutel: str, naam: str, ernst: str, meting: str, voorstel: str, **details) -> dict:
    return {
        "sleutel": sleutel,
        "naam": naam,
        "ernst": ernst,
        "meting": meting,
        "voorstel": voorstel,
        "details": details,
    }


# ------------------------------------------------------------------ pull requests

def check_rollup(pr: dict) -> dict:
    """Tel de checks van een pull request. gh levert CheckRun (conclusion) en
    StatusContext (state) door elkaar, dus beide lezen."""
    telling = {"gefaald": [], "loopt": [], "geslaagd": 0, "overgeslagen": 0, "totaal": 0}
    for check in pr.get("statusCheckRollup") or []:
        telling["totaal"] += 1
        naam = check.get("name") or check.get("context") or "naamloze check"
        staat = (check.get("status") or "").upper()
        uitkomst = (check.get("conclusion") or check.get("state") or "").upper()
        if uitkomst in {"FAILURE", "TIMED_OUT", "STARTUP_FAILURE", "ACTION_REQUIRED", "ERROR"}:
            telling["gefaald"].append(naam)
        elif uitkomst in {"SUCCESS", "NEUTRAL"}:
            telling["geslaagd"] += 1
        elif uitkomst in {"SKIPPED", "CANCELLED"}:
            telling["overgeslagen"] += 1
        elif staat in {"IN_PROGRESS", "QUEUED", "WAITING", "PENDING", "REQUESTED"} or not uitkomst:
            telling["loopt"].append(naam)
        else:
            telling["loopt"].append(naam)
    return telling


def signalen_pull_requests(repo: str) -> list[dict]:
    velden = "number,title,author,createdAt,isDraft,headRefName,url,statusCheckRollup"
    data, fout = gh_json([
        "pr", "list", "--repo", repo, "--state", "open", "--limit", "100", "--json", velden,
    ])
    if fout is not None:
        return [signaal(
            "pull-requests", "open pull requests", ORANJE,
            f"niet gemeten: {fout}",
            "Controleer of gh is ingelogd op deze machine en draai het script opnieuw.",
            bron="gh pr list",
        )]

    prs = data or []
    dependabot, mensen = [], []
    for pr in prs:
        login = ((pr.get("author") or {}).get("login") or "").lower()
        (dependabot if "dependabot" in login else mensen).append(pr)

    uit: list[dict] = []

    for pr in sorted(mensen, key=lambda p: p.get("createdAt") or ""):
        nummer = pr.get("number")
        leeftijd = uren_geleden(tijdstip(pr.get("createdAt")))
        telling = check_rollup(pr)
        titel = (pr.get("title") or "").strip()

        if telling["gefaald"]:
            ernst = ROOD
            meting = (
                f"PR #{nummer} staat {duur(leeftijd)} open, "
                f"{len(telling['gefaald'])} van {telling['totaal']} checks rood "
                f"({', '.join(telling['gefaald'][:3])})"
            )
            voorstel = f"Repareer de gefaalde checks van PR #{nummer} of sluit hem."
        elif telling["loopt"]:
            ernst = ORANJE
            meting = (
                f"PR #{nummer} staat {duur(leeftijd)} open, "
                f"{len(telling['loopt'])} van {telling['totaal']} checks lopen nog"
            )
            voorstel = f"Wacht de lopende checks van PR #{nummer} af en beoordeel daarna."
        elif telling["totaal"] == 0:
            ernst = ORANJE
            meting = f"PR #{nummer} staat {duur(leeftijd)} open zonder enige check"
            voorstel = f"Zoek uit waarom PR #{nummer} geen checks heeft voordat je hem beoordeelt."
        elif leeftijd is not None and leeftijd > PR_OUD_UREN:
            ernst = ORANJE
            meting = (
                f"PR #{nummer} is groen maar staat al {duur(leeftijd)} open "
                f"(drempel {PR_OUD_UREN} uur)"
            )
            voorstel = f"Merge PR #{nummer} of sluit hem, groen en oud is voorraad."
        else:
            ernst = GROEN
            meting = f"PR #{nummer} is groen en {duur(leeftijd)} oud"
            voorstel = f"Beoordeel PR #{nummer} wanneer het uitkomt."

        if pr.get("isDraft"):
            meting += " (concept)"

        uit.append(signaal(
            f"pr-{nummer}", f"PR #{nummer} {titel[:60]}", ernst, meting, voorstel,
            nummer=nummer, url=pr.get("url"), branch=pr.get("headRefName"),
            concept=bool(pr.get("isDraft")),
            leeftijd_uren=None if leeftijd is None else round(leeftijd, 2),
            checks={
                "totaal": telling["totaal"], "geslaagd": telling["geslaagd"],
                "overgeslagen": telling["overgeslagen"],
                "gefaald": telling["gefaald"], "loopt": telling["loopt"],
            },
            auteur=(pr.get("author") or {}).get("login"),
            bron="gh pr list --json statusCheckRollup",
        ))

    # Dependabot als een signaal, niet als tien. De vraag is niet welke update,
    # de vraag is of er updates staan te wachten en hoe lang al.
    if not dependabot:
        uit.append(signaal(
            "dependabot", "open dependabot-PRs", GROEN,
            "geen open dependabot-PRs",
            "Niets doen, de afhankelijkheden zijn bij.",
            aantal=0, bron="gh pr list --json author",
        ))
    else:
        leeftijden = [uren_geleden(tijdstip(pr.get("createdAt"))) for pr in dependabot]
        oudste = max([u for u in leeftijden if u is not None], default=None)
        nummers = [pr.get("number") for pr in dependabot]
        rood = oudste is not None and oudste > DEPENDABOT_OUD_UREN
        uit.append(signaal(
            "dependabot", "open dependabot-PRs", ROOD if rood else ORANJE,
            f"{len(dependabot)} open, oudste {duur(oudste)} "
            f"(#{', #'.join(str(n) for n in nummers[:6])})",
            (
                "Werk de dependabot-PRs weg, de oudste ligt over de "
                f"{DEPENDABOT_OUD_UREN // 24} dagen."
                if rood else
                "Loop de dependabot-PRs langs en merge wat groen is."
            ),
            aantal=len(dependabot), nummers=nummers,
            oudste_uren=None if oudste is None else round(oudste, 2),
            bron="gh pr list --json author",
        ))

    return uit


# --------------------------------------------------------------- workflow-runs

def signaal_gefaalde_runs(repo: str) -> dict:
    velden = "databaseId,workflowName,conclusion,status,createdAt,headBranch,event,url"
    data, fout = gh_json([
        "run", "list", "--repo", repo, "--limit", "100", "--json", velden,
    ])
    if fout is not None:
        return signaal(
            "workflow-runs", f"gefaalde runs laatste {RUNS_VENSTER_UREN} uur", ORANJE,
            f"niet gemeten: {fout}",
            "Controleer of gh is ingelogd op deze machine en draai het script opnieuw.",
            bron="gh run list",
        )

    gefaald = []
    for run in data or []:
        if (run.get("conclusion") or "").lower() not in KAPOT:
            continue
        leeftijd = uren_geleden(tijdstip(run.get("createdAt")))
        if leeftijd is None or leeftijd > RUNS_VENSTER_UREN:
            continue
        gefaald.append({
            "workflow": run.get("workflowName"),
            "branch": run.get("headBranch"),
            "event": run.get("event"),
            "conclusie": run.get("conclusion"),
            "uren_geleden": round(leeftijd, 2),
            "url": run.get("url"),
        })

    if not gefaald:
        return signaal(
            "workflow-runs", f"gefaalde runs laatste {RUNS_VENSTER_UREN} uur", GROEN,
            f"0 gefaalde runs in {RUNS_VENSTER_UREN} uur",
            "Niets doen, CI is schoon.",
            aantal=0, bron="gh run list --json conclusion",
        )

    op_main = [r for r in gefaald if r["branch"] in {"main", "master"}]
    namen = sorted({r["workflow"] or "onbekend" for r in gefaald})
    if op_main:
        ernst, voorstel = ROOD, (
            f"Zoek uit waarom {op_main[0]['workflow']} op main faalt, main hoort altijd groen te zijn."
        )
    else:
        ernst, voorstel = ORANJE, (
            "Laat de eigenaar van de branch de gefaalde runs oppakken, main is niet geraakt."
        )
    return signaal(
        "workflow-runs", f"gefaalde runs laatste {RUNS_VENSTER_UREN} uur", ernst,
        f"{len(gefaald)} gefaalde run{'' if len(gefaald) == 1 else 's'}, "
        f"{len(op_main)} op main ({', '.join(namen[:4])})",
        voorstel,
        aantal=len(gefaald), aantal_op_main=len(op_main), runs=gefaald[:20],
        bron="gh run list --json conclusion",
    )


# ------------------------------------------------------------------- heartbeat

def workflow_runs(repo: str, bestand: str, events: tuple, cache: dict,
                  limiet: int = 25) -> list[dict]:
    """De runs van een workflow, per event opgevraagd en op tijd gesorteerd.

    Per event, niet in een kale lijst: op een drukke dag bestaan de laatste
    twintig runs van een workflow bijna helemaal uit pull_request-runs, en dan
    verdwijnt de geplande run waar het hier om gaat achter de horizon."""
    sleutel = (bestand, events, limiet)
    if sleutel in cache:
        return cache[sleutel]
    velden = "databaseId,conclusion,status,createdAt,updatedAt,event,url,headBranch"
    gezien: set = set()
    runs: list[dict] = []
    for event in events:
        data, fout = gh_json([
            "run", "list", "--repo", repo, "--workflow", bestand,
            "--event", event, "--limit", str(limiet), "--json", velden,
        ])
        if fout is not None:
            continue
        for run in data or []:
            nummer = run.get("databaseId")
            if nummer in gezien:
                continue
            gezien.add(nummer)
            runs.append(run)
    runs.sort(key=lambda r: r.get("createdAt") or "", reverse=True)
    cache[sleutel] = runs
    return runs


def laatste_afgeronde(runs: list[dict]) -> dict | None:
    for run in runs:
        if (run.get("status") or "") == "completed":
            return run
    return None


def heartbeat_schakelaar(repo: str) -> tuple[bool | None, str | None, str | None]:
    """Staat de uurlijkse run aan? Geeft (aan, waarde, fout).

    De job draagt `if: github.event_name == 'workflow_dispatch' || vars.
    HEARTBEAT_ENABLED == 'true'`. Staat die variabele niet op true, dan doet de
    geplande run niets en zegt een groene of afwezige uitslag niets over
    productie. Dan is de vraag of het alarm aan hoort te staan, niet of het
    groen is."""
    data, fout = gh_json(["api", f"repos/{repo}/actions/variables/{HEARTBEAT_VARIABELE}"])
    if fout is None and isinstance(data, dict) and data.get("value") is not None:
        waarde = str(data["value"]).strip()
        return waarde.lower() == "true", waarde, None
    # Een 404 op deze route is geen meetfout maar een uitslag: de variabele
    # bestaat niet, dus de schakelaar staat uit.
    if fout and "404" in fout:
        return False, None, None
    # Terugval voor een token dat de losse route niet mag lezen maar de lijst
    # wel. Levert die ook niets op, dan is het echt niet gemeten.
    lijst, fout_lijst = gh_json(["variable", "list", "--repo", repo, "--json", "name,value"])
    if fout_lijst is None and isinstance(lijst, list):
        for variabele in lijst:
            if (variabele.get("name") or "") == HEARTBEAT_VARIABELE:
                waarde = str(variabele.get("value") or "").strip()
                return waarde.lower() == "true", waarde, None
        return False, None, None
    return None, None, fout or fout_lijst


def ontbrekende_sleutels(repo: str) -> list[str] | None:
    """Welke van de twee verplichte kanarie-secrets ontbreken. None als de lijst
    niet te lezen is met dit token. GitHub geeft alleen de namen terug, nooit de
    waarden, dus dit is een veilige vraag."""
    data, fout = gh_json(["api", f"repos/{repo}/actions/secrets?per_page=100"])
    if fout is not None or not isinstance(data, dict):
        return None
    aanwezig = {(s.get("name") or "") for s in data.get("secrets") or []}
    return [naam for naam in HEARTBEAT_SLEUTELS if naam not in aanwezig]


def heartbeat_bewijs(repo: str, run_id: int) -> tuple[dict | None, str | None]:
    """summary.json uit het bewijsartefact van een run.

    Waarom het artefact en niet de stapstatus uit de jobs-API: de proefstap
    draait met continue-on-error, zodat de browserhelft en de upload daarna nog
    gebeuren, en GitHub meldt zo'n stap daarna als conclusion success. Run
    33656533245 is daar het bewijs van: de stap "Proof run" staat op success
    terwijl summary.json parasend en beide parasign-stappen rood noemt. Wie de
    jobs-API gelooft, meldt een dode kanarie groen."""
    data, fout = gh_json(["api", f"repos/{repo}/actions/runs/{run_id}/artifacts"])
    if fout is not None:
        return None, fout
    artefacten = [
        a for a in (data or {}).get("artifacts") or []
        if str(a.get("name") or "").startswith("heartbeat-evidence")
    ]
    levend = [a for a in artefacten if not a.get("expired")]
    if not levend:
        return None, (
            "het bewijsartefact is verlopen" if artefacten
            else "deze run heeft geen bewijsartefact"
        )
    rauw, fout = gh_bytes(["api", f"repos/{repo}/actions/artifacts/{levend[0].get('id')}/zip"])
    if fout is not None:
        return None, fout
    try:
        with zipfile.ZipFile(io.BytesIO(rauw)) as zip_bestand:
            naam = next(
                (n for n in zip_bestand.namelist() if n.rsplit("/", 1)[-1] == "summary.json"),
                None,
            )
            if naam is None:
                return None, "het bewijsartefact bevat geen summary.json"
            return json.loads(zip_bestand.read(naam).decode("utf-8")), None
    except (zipfile.BadZipFile, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"het bewijsartefact is onleesbaar ({exc})"


def signalen_heartbeat(repo: str, cache_runs: dict) -> list[dict]:
    """Het uurlijkse alarm: eerst de schakelaar, dan pas de uitslag."""
    aan, waarde, fout = heartbeat_schakelaar(repo)

    if fout is not None:
        return [signaal(
            "heartbeat", "uurlijkse heartbeat", ORANJE,
            f"niet gemeten: {fout}",
            "Controleer of gh is ingelogd op deze machine en de repositoryvariabelen mag lezen.",
            workflow=HEARTBEAT_WORKFLOW, variabele=HEARTBEAT_VARIABELE,
            bron="gh api actions/variables",
        )]

    if not aan:
        # Een uitgeschakeld alarm is een stand van zaken, geen storing, en het
        # is een signaal en niet drie: er valt niets te meten zolang de
        # geplande run niets doet.
        ontbreekt = ontbrekende_sleutels(repo)
        stand = (
            f"{HEARTBEAT_VARIABELE} niet gezet" if waarde is None
            else f"{HEARTBEAT_VARIABELE} staat op {waarde}"
        )
        if ontbreekt is None:
            sleutels = "kanarie-sleutels niet te lezen met dit token"
            voorstel = (
                "Zet de kanarie-sleutels, draai heartbeat.yml eenmaal met de hand en zet "
                f"daarna {HEARTBEAT_VARIABELE} op true, in die volgorde."
            )
        elif ontbreekt:
            sleutels = f"kanarie-sleutels ontbreken ({', '.join(ontbreekt)})"
            voorstel = (
                f"Zet {' en '.join(ontbreekt)}, draai heartbeat.yml eenmaal met de hand en "
                f"zet daarna {HEARTBEAT_VARIABELE} op true, in die volgorde."
            )
        else:
            sleutels = "kanarie-sleutels staan er wel"
            voorstel = (
                "Draai heartbeat.yml eenmaal met de hand, en zet daarna "
                f"{HEARTBEAT_VARIABELE} op true zodra die run groen is."
            )
        return [signaal(
            "heartbeat", "uurlijkse heartbeat", ORANJE,
            f"heartbeat uitgeschakeld: {stand}, {sleutels}; volgorde in docs/heartbeat.md",
            voorstel,
            workflow=HEARTBEAT_WORKFLOW, variabele=HEARTBEAT_VARIABELE, waarde=waarde,
            ontbrekende_sleutels=ontbreekt, documentatie="docs/heartbeat.md",
            bron="gh api actions/variables + actions/secrets",
        )]

    runs = workflow_runs(repo, HEARTBEAT_WORKFLOW, ("schedule", "workflow_dispatch"), cache_runs)
    run = laatste_afgeronde(runs)
    if run is None:
        return [signaal(
            "heartbeat", "uurlijkse heartbeat", ROOD,
            f"{HEARTBEAT_VARIABELE} staat aan, maar {HEARTBEAT_WORKFLOW} heeft geen afgeronde run",
            "Start heartbeat.yml met de hand en zoek uit waarom de geplande run niet loopt.",
            workflow=HEARTBEAT_WORKFLOW, variabele=HEARTBEAT_VARIABELE,
            bron="gh run list --workflow heartbeat.yml",
        )]

    run_id = run.get("databaseId")
    conclusie = (run.get("conclusion") or "").lower()
    bewijs, fout_bewijs = heartbeat_bewijs(repo, run_id)
    uitslagen = {}
    if isinstance(bewijs, dict):
        for stap in bewijs.get("steps") or []:
            if stap.get("name"):
                uitslagen[stap["name"]] = stap
    dry_run = bool((bewijs or {}).get("dry_run"))
    # Faalde de run terwijl elke proefstap groen is, dan zat de storing in de
    # browserhelft of de linkcheck. Is er wel een rode proefstap, dan is de run
    # daardoor gevallen en hoeft een groene stap daar niet ook nog voor te
    # boeten: dat rode signaal staat er al.
    alles_groen = bool(uitslagen) and all(s.get("ok") for s in uitslagen.values())
    klaar = tijdstip((bewijs or {}).get("at")) or tijdstip(run.get("updatedAt"))
    leeftijd = uren_geleden(klaar)

    uit: list[dict] = []
    for naam, deelstappen in HEARTBEAT_STAPPEN:
        details = {
            "workflow": HEARTBEAT_WORKFLOW,
            "run_id": run_id,
            "url": run.get("url"),
            "event": run.get("event"),
            "run_conclusie": conclusie,
            "stappen": list(deelstappen),
            "afgerond": None if klaar is None else klaar.isoformat().replace("+00:00", "Z"),
            "leeftijd_uren": None if leeftijd is None else round(leeftijd, 2),
            "bron": "gh api actions/artifacts/<id>/zip (summary.json)",
        }
        gevonden = [uitslagen[d] for d in deelstappen if d in uitslagen]

        if not gevonden:
            reden = fout_bewijs or "de stap staat niet in summary.json"
            uit.append(signaal(
                f"heartbeat-{naam}", f"heartbeat {naam}",
                ROOD if conclusie in KAPOT else ORANJE,
                f"geen uitslag in run {run_id} ({reden}), de run zelf eindigde als "
                f"{conclusie or 'onbekend'}",
                f"Open run {run_id} en kijk waarom {naam} geen bewijs schreef; een stap "
                "zonder bewijs telt hier niet als groen.",
                **details,
            ))
            continue

        kapot = [s for s in gevonden if not s.get("ok")]
        bewijzen = sum(int(s.get("proofs") or 0) for s in gevonden)
        details["proofs"] = bewijzen
        details["deelstappen"] = [
            {"naam": s.get("name"), "ok": bool(s.get("ok")),
             "oorzaak": s.get("cause"), "proofs": s.get("proofs")}
            for s in gevonden
        ]

        if kapot:
            oorzaken = "; ".join(
                f"{s.get('name')}: {s.get('cause') or 'zonder opgegeven oorzaak'}" for s in kapot
            )
            ernst = ROOD
            meting = f"rood in run {run_id}, {duur(leeftijd)} geleden ({oorzaken})"
            voorstel = (
                f"Repareer {naam} voordat een klant het merkt: "
                f"{kapot[0].get('cause') or 'zie de run'}."
            )
        elif dry_run:
            ernst = ORANJE
            meting = (
                f"run {run_id} was een dry run: de bedrading klopt, maar er is niets "
                "over productie bewezen"
            )
            voorstel = f"Draai heartbeat.yml zonder HEARTBEAT_DRY_RUN, anders meet {naam} niets."
        elif leeftijd is not None and leeftijd > HEARTBEAT_ROOD_UREN:
            ernst = ROOD
            meting = (
                f"groen, maar de laatste uitslag is {duur(leeftijd)} oud "
                f"(drempel {HEARTBEAT_ROOD_UREN} uur, run {run_id})"
            )
            voorstel = (
                "De uurlijkse run slaat over; kijk of de schedule van heartbeat.yml nog "
                "loopt en of de repository niet inactief is verklaard."
            )
        elif conclusie in KAPOT and alles_groen:
            ernst = ORANJE
            meting = (
                f"groen met {bewijzen} bewijzen, maar run {run_id} eindigde als {conclusie}: "
                "er faalde iets buiten de drie proefstappen"
            )
            voorstel = (
                f"Kijk in run {run_id} welke stap buiten de proefrun faalde, de browserhelft "
                "of de externe links."
            )
        elif leeftijd is None:
            ernst = ORANJE
            meting = f"groen met {bewijzen} bewijzen in run {run_id}, maar zonder tijdstip"
            voorstel = f"Controleer met de hand hoe oud de laatste uitslag van {naam} is."
        else:
            ernst = GROEN
            meting = f"groen, {bewijzen} bewijzen, {duur(leeftijd)} geleden (run {run_id})"
            voorstel = "Niets doen, de heartbeat bewijst dit stuk product."

        uit.append(signaal(f"heartbeat-{naam}", f"heartbeat {naam}", ernst, meting, voorstel, **details))

    return uit


def signaal_heartbeat_issue(repo: str) -> dict:
    """Staat het alarmissue van de heartbeat open?

    De workflow opent er een bij rood en sluit hem zelf zodra een run weer groen
    is. Staat hij open, dan is productie rood geweest en heeft niemand het
    afgemaakt, ook als de laatste run intussen niet meer draait."""
    data, fout = gh_json([
        "issue", "list", "--repo", repo, "--state", "open", "--limit", "100",
        "--json", "number,title,url,createdAt,updatedAt",
    ])
    if fout is not None:
        return signaal(
            "heartbeat-issue", f"open issue {HEARTBEAT_ISSUE_TITEL}", ORANJE,
            f"niet gemeten: {fout}",
            "Controleer of gh is ingelogd op deze machine en draai het script opnieuw.",
            bron="gh issue list",
        )
    treffers = [
        i for i in (data or [])
        if (i.get("title") or "").strip() == HEARTBEAT_ISSUE_TITEL
    ]
    if not treffers:
        return signaal(
            "heartbeat-issue", f"open issue {HEARTBEAT_ISSUE_TITEL}", GROEN,
            f"geen open issue met de titel {HEARTBEAT_ISSUE_TITEL}",
            "Niets doen, het alarm heeft niets openstaan.",
            aantal=0, bron="gh issue list --json title",
        )
    eerste = treffers[0]
    nummer = eerste.get("number")
    leeftijd = uren_geleden(tijdstip(eerste.get("createdAt")))
    return signaal(
        "heartbeat-issue", f"open issue {HEARTBEAT_ISSUE_TITEL}", ROOD,
        f"issue #{nummer} staat {duur(leeftijd)} open ({eerste.get('url')})",
        f"Lees issue #{nummer}, repareer wat daar rood staat; de heartbeat sluit hem zelf "
        "zodra een run weer groen is.",
        nummer=nummer, url=eerste.get("url"), aantal=len(treffers),
        leeftijd_uren=None if leeftijd is None else round(leeftijd, 2),
        bron="gh issue list --json title",
    )


def signaal_pr_gate(repo: str, repo_wortel: str, cache_runs: dict) -> dict:
    """product-heartbeat.yml, wat het sinds PR #338 nog is: de gate op pull
    requests. Geen kanarie meer, dus geen uitspraak over productie."""
    pad = os.path.join(repo_wortel, ".github", "workflows", PR_GATE_WORKFLOW)
    try:
        with open(pad, "r", encoding="utf-8") as fh:
            inhoud = fh.read()
    except OSError:
        return signaal(
            "pr-gate-heartbeat", "PR-gate product-heartbeat", ORANJE,
            f"{PR_GATE_WORKFLOW} staat niet in .github/workflows",
            "Bevestig of de browsergate bewust weg is; zonder die gate merkt niemand een "
            "kapotte pagina voor de merge.",
            workflow=PR_GATE_WORKFLOW, bron=".github/workflows",
        )
    if not re.search(r"^\s{2}pull_request:", inhoud, re.M):
        return signaal(
            "pr-gate-heartbeat", "PR-gate product-heartbeat", ORANJE,
            f"{PR_GATE_WORKFLOW} heeft geen pull_request-trigger meer",
            "Zet de pull_request-trigger terug, anders draait de browsergate niet voor een merge.",
            workflow=PR_GATE_WORKFLOW, bron=".github/workflows",
        )
    if re.search(r"^\s{2}schedule:", inhoud, re.M):
        return signaal(
            "pr-gate-heartbeat", "PR-gate product-heartbeat", ORANJE,
            f"{PR_GATE_WORKFLOW} heeft weer een schedule-trigger",
            "Haal de schedule uit de PR-gate; het uurlijkse alarm hoort op een plek te "
            "staan, in heartbeat.yml.",
            workflow=PR_GATE_WORKFLOW, bron=".github/workflows",
        )

    runs = workflow_runs(repo, PR_GATE_WORKFLOW, ("pull_request", "push"), cache_runs, limiet=20)
    run = laatste_afgeronde(runs)
    if run is None:
        return signaal(
            "pr-gate-heartbeat", "PR-gate product-heartbeat", ORANJE,
            "de gate staat er, maar heeft geen afgeronde run op push of pull_request",
            "Kijk of de gate nog draait; een gate die niet loopt is geen gate.",
            workflow=PR_GATE_WORKFLOW, bron="gh run list --workflow product-heartbeat.yml",
        )
    conclusie = (run.get("conclusion") or "").lower()
    leeftijd = uren_geleden(tijdstip(run.get("updatedAt")))
    if conclusie in KAPOT:
        ernst = ORANJE
        voorstel = (
            f"Repareer de gate op {run.get('headBranch') or 'de branch'}; hij zegt niets over "
            "productie, maar hij laat wel een kapotte pagina door."
        )
    elif conclusie == "success":
        ernst = GROEN
        voorstel = "Niets doen, de browsergate draait en is groen."
    else:
        ernst = ORANJE
        voorstel = f"Kijk waarom de gate eindigde als {conclusie or 'onbekend'}."
    return signaal(
        "pr-gate-heartbeat", "PR-gate product-heartbeat", ernst,
        f"{conclusie or 'onbekend'} op {run.get('headBranch') or 'onbekende branch'}, "
        f"{duur(leeftijd)} geleden (run {run.get('databaseId')})",
        voorstel,
        workflow=PR_GATE_WORKFLOW, run_id=run.get("databaseId"), url=run.get("url"),
        event=run.get("event"), conclusie=conclusie,
        leeftijd_uren=None if leeftijd is None else round(leeftijd, 2),
        bron="gh run list --workflow product-heartbeat.yml",
    )


# ------------------------------------------------------------------- productie

def signaal_health() -> dict:
    meting = curl_meting(PRODUCTIE_HEALTH)
    if meting["fout"]:
        return signaal(
            "productie-health", "productie /health", ROOD,
            f"onbereikbaar: {meting['fout']}",
            "Controleer of paramant.app en de relay draaien, productie antwoordt niet.",
            url=PRODUCTIE_HEALTH, bron="curl",
        )
    status, seconden = meting["status"], meting["seconden"]
    if status == 200:
        ernst, voorstel = GROEN, "Niets doen, productie antwoordt gezond."
    elif 200 <= status < 400:
        ernst, voorstel = ORANJE, f"/health geeft {status} in plaats van 200, kijk of daar een redirect voor staat."
    else:
        ernst, voorstel = ROOD, f"/health geeft {status}, behandel productie als down tot het tegendeel blijkt."
    return signaal(
        "productie-health", "productie /health", ernst,
        f"HTTP {status} in {seconden:.2f} s", voorstel,
        url=PRODUCTIE_HEALTH, status=status, seconden=round(seconden, 3), bron="curl",
    )


def signaal_homepage() -> dict:
    meting = curl_meting(PRODUCTIE_HOME)
    if meting["fout"]:
        return signaal(
            "productie-homepage", "responstijd homepage", ROOD,
            f"onbereikbaar: {meting['fout']}",
            "Controleer de webserver van paramant.app, de homepage laadt niet.",
            url=PRODUCTIE_HOME, bron="curl",
        )
    status, seconden = meting["status"], meting["seconden"]
    if status is None or status >= 400:
        ernst, voorstel = ROOD, f"De homepage geeft {status}, repareer dat voor alles anders."
    elif seconden > HOMEPAGE_ROOD_S:
        ernst, voorstel = ROOD, f"De homepage doet er {seconden:.2f} s over, zoek uit wat er traag is."
    elif seconden > HOMEPAGE_ORANJE_S:
        ernst, voorstel = ORANJE, f"De homepage zit boven {HOMEPAGE_ORANJE_S:.1f} s, houd de laadtijd in de gaten."
    else:
        ernst, voorstel = GROEN, "Niets doen, de homepage laadt snel."
    return signaal(
        "productie-homepage", "responstijd homepage", ernst,
        f"HTTP {status} in {seconden:.2f} s "
        f"(oranje boven {HOMEPAGE_ORANJE_S:.1f} s, rood boven {HOMEPAGE_ROOD_S:.1f} s)",
        voorstel,
        url=PRODUCTIE_HOME, status=status, seconden=round(seconden, 3), bron="curl",
    )


def signalen_paraid_deny() -> list[dict]:
    uit = []
    for host in PARAID_HOSTS:
        url = f"https://{host}{PARAID_DENY_PAD}"
        meting = curl_meting(url, methode="POST", body="{}")
        if meting["fout"]:
            uit.append(signaal(
                f"paraid-deny-{host}", f"ParaID dicht op {host}", ORANJE,
                f"niet gemeten: {meting['fout']}",
                f"Meet {host} opnieuw, zonder antwoord weten we niet of de route dicht is.",
                url=url, verwacht=404, bron="curl -X POST",
            ))
            continue
        status = meting["status"]
        if status == 404:
            ernst = GROEN
            voorstel = "Niets doen, de route is dicht."
        elif status in {401, 403, 405, 410}:
            ernst = ORANJE
            voorstel = f"{host} geeft {status} in plaats van 404, de route bestaat daar nog in een of andere vorm."
        else:
            ernst = ROOD
            voorstel = f"Sluit {PARAID_DENY_PAD} op {host}, hij antwoordt met {status} en hoort 404 te geven."
        uit.append(signaal(
            f"paraid-deny-{host}", f"ParaID dicht op {host}", ernst,
            f"POST met lege body geeft HTTP {status} in {meting['seconden']:.2f} s (verwacht 404)",
            voorstel,
            url=url, status=status, verwacht=404,
            seconden=round(meting["seconden"], 3), bron="curl -X POST",
        ))
    return uit


# ---------------------------------------------------------------------- uitvoer

def tekst_rapport(rapport: dict) -> str:
    samen = rapport["samenvatting"]
    regels = [
        f"PARAMANT directiesignalen  {rapport['gegenereerd']}",
        f"repo {rapport['repo']}",
        f"rood {samen['rood']}   oranje {samen['oranje']}   groen {samen['groen']}",
        "",
    ]
    op_ernst = sorted(rapport["signalen"], key=lambda s: (ERNST_ORDE[s["ernst"]], s["sleutel"]))
    for sig in op_ernst:
        regels.append(f"[{sig['ernst'].upper():<6}] {sig['naam']}")
        regels.append(f"           meting:   {sig['meting']}")
        regels.append(f"           voorstel: {sig['voorstel']}")
        regels.append("")
    if samen["rood"]:
        regels.append(f"Er is {samen['rood']} signaal rood, exitcode 1."
                      if samen["rood"] == 1 else
                      f"Er zijn {samen['rood']} signalen rood, exitcode 1.")
    else:
        regels.append("Niets rood, exitcode 0.")
    return "\n".join(regels)


def repo_wortel() -> str:
    try:
        klaar = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=15,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        if klaar.returncode == 0 and klaar.stdout.strip():
            return klaar.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    # scripts/directie/signalen.py -> twee mappen omhoog is de wortel
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def huidige_repo(wortel: str) -> str:
    data, fout = gh_json(["repo", "view", "--json", "nameWithOwner"])
    if fout is None and isinstance(data, dict) and data.get("nameWithOwner"):
        return data["nameWithOwner"]
    return "Apolloccrypt/paramant-relay"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Meet de staat van Paramant en meld wat rood is.",
    )
    parser.add_argument("--tekst", action="store_true",
                        help="leesbare tekst in plaats van JSON")
    parser.add_argument("--repo", default=None,
                        help="eigenaar/repo voor gh (standaard: de repo van deze werkkopie)")
    args = parser.parse_args(argv)

    wortel = repo_wortel()
    repo = args.repo or huidige_repo(wortel)

    signalen: list[dict] = []
    signalen += signalen_pull_requests(repo)
    signalen.append(signaal_gefaalde_runs(repo))
    cache_runs: dict = {}
    signalen += signalen_heartbeat(repo, cache_runs)
    signalen.append(signaal_heartbeat_issue(repo))
    signalen.append(signaal_pr_gate(repo, wortel, cache_runs))
    signalen.append(signaal_health())
    signalen.append(signaal_homepage())
    signalen += signalen_paraid_deny()

    samenvatting = {
        ROOD: sum(1 for s in signalen if s["ernst"] == ROOD),
        ORANJE: sum(1 for s in signalen if s["ernst"] == ORANJE),
        GROEN: sum(1 for s in signalen if s["ernst"] == GROEN),
    }
    rapport = {
        "gegenereerd": nu().replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "repo": repo,
        "wortel": wortel,
        "samenvatting": samenvatting,
        "signalen": signalen,
    }

    if args.tekst:
        print(tekst_rapport(rapport))
    else:
        print(json.dumps(rapport, indent=2, ensure_ascii=False, sort_keys=False))

    return 1 if samenvatting[ROOD] else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001 - een meetscript mag nooit stil sterven
        print(f"signalen.py brak af: {exc}", file=sys.stderr)
        sys.exit(2)
