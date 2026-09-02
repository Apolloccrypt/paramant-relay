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
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

# Drempels. Bewust bovenaan en met een reden, zodat een discussie over "wanneer
# is iets rood" hier gevoerd wordt en niet verstopt zit in een if.

# Een pull request die langer dan dit open staat is geen werk meer maar voorraad.
PR_OUD_UREN = 72
# Dependabot: een openstaande update is hinder, een oude is een risico.
DEPENDABOT_OUD_UREN = 14 * 24
# Gefaalde workflow-runs tellen we over dit venster.
RUNS_VENSTER_UREN = 24
# De kanarie-workflow draait per uur. Wordt de laatste uitslag ouder dan dit,
# dan meet niemand meer mee.
KANARIE_ORANJE_UREN = 6
KANARIE_ROOD_UREN = 24
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

# De kanaries zoals ze in .github/workflows heten. Het script zoekt ze op naam
# op, in de workflow-namen, de job-namen en de stapnamen, zodat het blijft
# werken als een kanarie ooit een eigen workflow wordt.
KANARIES = [
    ("transfer-kanarie", re.compile(r"transfer[\s_-]*(canary|kanarie)", re.I)),
    ("parasign-kanarie", re.compile(r"parasign[\s_-]*(canary|kanarie)", re.I)),
    # Alleen de kanarie tegen productie, niet de heartbeat tegen de checkout.
    ("heartbeat", re.compile(r"heartbeat\s+(against|tegen)\s+\S*paramant", re.I)),
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


# -------------------------------------------------------------------- kanaries

def workflow_map(repo_wortel: str) -> str:
    return os.path.join(repo_wortel, ".github", "workflows")


def lees_workflows(repo_wortel: str) -> list[dict]:
    """Lees de workflowbestanden en haal er de namen uit die we nodig hebben:
    de workflownaam, de jobnamen en de stapnamen. Geen YAML-bibliotheek in de
    standaardbibliotheek, dus dit is een bewust simpele scanner op inspringing.
    Hij hoeft maar een ding te kunnen: name-regels vinden."""
    map_pad = workflow_map(repo_wortel)
    if not os.path.isdir(map_pad):
        return []
    bestanden = []
    for naam in sorted(os.listdir(map_pad)):
        if not naam.endswith((".yml", ".yaml")):
            continue
        pad = os.path.join(map_pad, naam)
        try:
            with open(pad, "r", encoding="utf-8") as fh:
                regels = fh.read().splitlines()
        except OSError:
            continue
        workflow_naam, namen = None, []
        for regel in regels:
            treffer = re.match(r"^(\s*)(?:-\s+)?name:\s*(.+?)\s*$", regel)
            if not treffer:
                continue
            inspringing, waarde = len(treffer.group(1)), treffer.group(2).strip()
            waarde = waarde.strip("'\"")
            if inspringing == 0 and workflow_naam is None:
                workflow_naam = waarde
            namen.append(waarde)
        bestanden.append({
            "bestand": naam,
            "workflow": workflow_naam or naam,
            "namen": namen,
        })
    return bestanden


def jobs_van_run(repo: str, run_id: int, cache: dict) -> list[dict]:
    if run_id in cache:
        return cache[run_id]
    data, fout = gh_json(["api", f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100"])
    jobs = []
    if fout is None and isinstance(data, dict):
        jobs = data.get("jobs") or []
    cache[run_id] = jobs
    return jobs


def signalen_kanaries(repo: str, repo_wortel: str) -> list[dict]:
    workflows = lees_workflows(repo_wortel)
    cache_runs: dict[str, list] = {}
    cache_jobs: dict[int, list] = {}
    uit: list[dict] = []

    for sleutel, patroon in KANARIES:
        treffers = [wf for wf in workflows if any(patroon.search(n) for n in wf["namen"])]
        if not treffers:
            uit.append(signaal(
                f"kanarie-{sleutel}", f"kanarie {sleutel}", ORANJE,
                "geen workflow of stap met deze naam in .github/workflows",
                f"Bevestig of {sleutel} bewust weg is, en haal hem anders uit dit script.",
                bron=".github/workflows",
            ))
            continue

        wf = treffers[0]
        bestand = wf["bestand"]
        if bestand not in cache_runs:
            data, fout = gh_json([
                "run", "list", "--repo", repo, "--workflow", bestand, "--limit", "20",
                "--json", "databaseId,conclusion,status,createdAt,updatedAt,event,url",
            ])
            cache_runs[bestand] = [] if fout is not None else (data or [])
        runs = cache_runs[bestand]

        gevonden = None
        for run in runs:
            if (run.get("status") or "") != "completed":
                continue
            for job in jobs_van_run(repo, run.get("databaseId"), cache_jobs):
                for stap in job.get("steps") or []:
                    if not patroon.search(stap.get("name") or ""):
                        continue
                    conclusie = (stap.get("conclusion") or "").lower()
                    if conclusie in {"", "skipped"}:
                        continue
                    gevonden = {
                        "run_id": run.get("databaseId"),
                        "url": run.get("url"),
                        "event": run.get("event"),
                        "job": job.get("name"),
                        "stap": stap.get("name"),
                        "conclusie": conclusie,
                        "afgerond": stap.get("completed_at") or job.get("completed_at"),
                        "workflow": bestand,
                    }
                    break
                if gevonden:
                    break
            if gevonden:
                break

        if gevonden is None:
            uit.append(signaal(
                f"kanarie-{sleutel}", f"kanarie {sleutel}", ORANJE,
                f"staat in {bestand} maar heeft in de laatste 20 runs geen uitslag gegeven",
                f"Start {bestand} handmatig met gh workflow run en kijk of {sleutel} weer meet.",
                workflow=bestand, bron="gh api actions/runs/<id>/jobs",
            ))
            continue

        leeftijd = uren_geleden(tijdstip(gevonden["afgerond"]))
        conclusie = gevonden["conclusie"]
        if conclusie in KAPOT:
            ernst = ROOD
            voorstel = f"Open de run van {sleutel} en repareer wat er kapot is voordat een klant het merkt."
        elif leeftijd is not None and leeftijd > KANARIE_ROOD_UREN:
            ernst = ROOD
            voorstel = f"De kanarie {sleutel} meet al {duur(leeftijd)} niet meer, zet de geplande run weer aan."
        elif leeftijd is not None and leeftijd > KANARIE_ORANJE_UREN:
            ernst = ORANJE
            voorstel = f"Controleer waarom {sleutel} niet per uur draait, de laatste uitslag is {duur(leeftijd)} oud."
        elif conclusie == "success":
            ernst = GROEN
            voorstel = "Niets doen, de kanarie leeft."
        else:
            ernst = ORANJE
            voorstel = f"Kijk waarom {sleutel} eindigde als {conclusie} in plaats van success."

        uit.append(signaal(
            f"kanarie-{sleutel}", f"kanarie {sleutel}", ernst,
            f"{conclusie}, {duur(leeftijd)} geleden (run {gevonden['run_id']}, {bestand})",
            voorstel,
            **gevonden,
            leeftijd_uren=None if leeftijd is None else round(leeftijd, 2),
            bron="gh api actions/runs/<id>/jobs",
        ))

    return uit


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
    if status >= 400 or status is None:
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
    signalen += signalen_kanaries(repo, wortel)
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
