#!/usr/bin/env python3
"""Droogtest voor scripts/directie/signalen.py, met een gestubde gh.

Het script praat alleen via twee functies met de buitenwereld, gh_json en
gh_bytes. Die worden hier vervangen door een tabel met antwoorden, zodat beide
standen van de heartbeat getest kunnen worden zonder GitHub aan te raken: de
uurlijkse run uit (dan hoort er een oranje signaal te zijn en niet drie
kanaries) en aan (dan horen surface, parasend en parasign hun uitslag uit het
bewijsartefact te halen).

    python3 tests/test_directie_signalen.py
"""

import importlib.util
import io
import json
import sys
import tempfile
import unittest
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'directie' / 'signalen.py'

REPO = 'eigenaar/repo'
NIET_GEVONDEN = 'gh: Not Found (HTTP 404)'


def laad_signalen():
    naam = f'signalen_{uuid.uuid4().hex}'
    spec = importlib.util.spec_from_file_location(naam, SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[naam] = module
    try:
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop(naam, None)


def stempel(uren_geleden):
    tijd = datetime.now(timezone.utc) - timedelta(hours=uren_geleden)
    return tijd.isoformat().replace('+00:00', 'Z')


def bewijs_zip(summary):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zip_bestand:
        zip_bestand.writestr('summary.json', json.dumps(summary))
        zip_bestand.writestr('surface.json', '{}')
    return buffer.getvalue()


class GhStub:
    """Antwoordt op de gh-aanroepen die het script doet, en klaagt over de rest.

    Een onverwachte aanroep is een fout en geen leeg antwoord: anders zou een
    hernoemde vlag stilletjes als 'niet gemeten' doorgaan, en dat is precies de
    soort blindheid die dit script hoort weg te nemen.
    """

    def __init__(self, variabele=None, secrets=(), runs=None, artefacten=None,
                 bewijs=None, issues=()):
        self.variabele = variabele
        self.secrets = list(secrets)
        self.runs = runs or {}
        self.artefacten = artefacten or []
        self.bewijs = bewijs
        self.issues = list(issues)
        self.aanroepen = []

    def json(self, args):
        self.aanroepen.append(list(args))
        regel = ' '.join(args)
        if regel.startswith('api ') and '/actions/variables/' in regel:
            if self.variabele is None:
                return None, NIET_GEVONDEN
            return {'name': 'HEARTBEAT_ENABLED', 'value': self.variabele}, None
        if regel.startswith('variable list'):
            return [], None
        if regel.startswith('api ') and '/actions/secrets' in regel:
            return {'secrets': [{'name': n} for n in self.secrets]}, None
        if regel.startswith('api ') and regel.endswith('/artifacts'):
            return {'artifacts': self.artefacten}, None
        if args[0] == 'run' and args[1] == 'list':
            bestand = args[args.index('--workflow') + 1]
            event = args[args.index('--event') + 1]
            return self.runs.get((bestand, event), []), None
        if args[0] == 'issue' and args[1] == 'list':
            return self.issues, None
        raise AssertionError(f'onverwachte gh-aanroep: {regel}')

    def bytes(self, args):
        self.aanroepen.append(list(args))
        if self.bewijs is None:
            return None, 'geen bewijs in deze stub'
        return self.bewijs, None


def met_stub(stub):
    module = laad_signalen()
    module.gh_json = stub.json
    module.gh_bytes = stub.bytes
    return module


def op_sleutel(signalen):
    return {s['sleutel']: s for s in signalen}


class HeartbeatUitTests(unittest.TestCase):
    def test_uit_geeft_een_oranje_signaal_en_geen_drie_kanaries(self):
        stub = GhStub(variabele=None, secrets=['DOCKERHUB_TOKEN'])
        module = met_stub(stub)

        signalen = module.signalen_heartbeat(REPO, {})

        self.assertEqual(len(signalen), 1)
        sig = signalen[0]
        self.assertEqual(sig['sleutel'], 'heartbeat')
        self.assertEqual(sig['ernst'], module.ORANJE)
        self.assertIn('heartbeat uitgeschakeld', sig['meting'])
        self.assertIn('HEARTBEAT_ENABLED niet gezet', sig['meting'])
        self.assertIn('PARAMANT_CANARY_KEY', sig['meting'])
        self.assertIn('PARASIGN_CANARY_KEY', sig['meting'])
        self.assertIn('docs/heartbeat.md', sig['meting'])
        # Geen enkele run opgevraagd: een uitgeschakeld alarm kost een vraag.
        self.assertFalse([a for a in stub.aanroepen if a[0] == 'run'])

    def test_uit_met_de_sleutels_al_gezet_zegt_dat_ook(self):
        stub = GhStub(variabele='false',
                      secrets=['PARAMANT_CANARY_KEY', 'PARASIGN_CANARY_KEY'])
        module = met_stub(stub)

        sig = module.signalen_heartbeat(REPO, {})[0]

        self.assertEqual(sig['ernst'], module.ORANJE)
        self.assertIn('HEARTBEAT_ENABLED staat op false', sig['meting'])
        self.assertIn('kanarie-sleutels staan er wel', sig['meting'])

    def test_onleesbare_variabele_is_oranje_niet_gemeten(self):
        stub = GhStub()
        stub.json = lambda args: (None, 'gh: HTTP 403')
        module = laad_signalen()
        module.gh_json = stub.json

        sig = module.signalen_heartbeat(REPO, {})[0]

        self.assertEqual(sig['ernst'], module.ORANJE)
        self.assertIn('niet gemeten', sig['meting'])


def stub_aan(stappen, run_leeftijd_uren=0.2, run_conclusie='success', dry_run=False):
    run = {
        'databaseId': 1234,
        'conclusion': run_conclusie,
        'status': 'completed',
        'createdAt': stempel(run_leeftijd_uren + 0.05),
        'updatedAt': stempel(run_leeftijd_uren),
        'event': 'schedule',
        'url': 'https://github.com/eigenaar/repo/actions/runs/1234',
        'headBranch': 'main',
    }
    summary = {
        'at': stempel(run_leeftijd_uren),
        'ok': run_conclusie == 'success',
        'dry_run': dry_run,
        'run_id': '1234',
        'steps': stappen,
    }
    return GhStub(
        variabele='true',
        runs={('heartbeat.yml', 'schedule'): [run],
              ('heartbeat.yml', 'workflow_dispatch'): []},
        artefacten=[{'id': 77, 'name': 'heartbeat-evidence-1234', 'expired': False}],
        bewijs=bewijs_zip(summary),
    )


GROENE_STAPPEN = [
    {'name': 'surface', 'ok': True, 'proofs': 4},
    {'name': 'parasend', 'ok': True, 'proofs': 6},
    {'name': 'parasign-receipt', 'ok': True, 'proofs': 6},
    {'name': 'parasign-public-sign', 'ok': True, 'proofs': 7},
]


class HeartbeatAanTests(unittest.TestCase):
    def test_verse_groene_run_geeft_drie_groene_stappen(self):
        module = met_stub(stub_aan(GROENE_STAPPEN))

        signalen = op_sleutel(module.signalen_heartbeat(REPO, {}))

        self.assertEqual(sorted(signalen), [
            'heartbeat-parasend', 'heartbeat-parasign', 'heartbeat-surface',
        ])
        for sleutel, sig in signalen.items():
            self.assertEqual(sig['ernst'], module.GROEN, sleutel)
            self.assertIn('run 1234', sig['meting'])
        # parasign telt de twee deelstappen bij elkaar op.
        self.assertIn('13 bewijzen', signalen['heartbeat-parasign']['meting'])

    def test_gefaalde_stap_is_rood_met_de_oorzaak_uit_het_bewijs(self):
        stappen = [
            {'name': 'surface', 'ok': True, 'proofs': 4},
            {'name': 'parasend', 'ok': False, 'proofs': 0,
             'cause': 'secret PARAMANT_CANARY_KEY is not set'},
            {'name': 'parasign-receipt', 'ok': True, 'proofs': 6},
            {'name': 'parasign-public-sign', 'ok': True, 'proofs': 7},
        ]
        module = met_stub(stub_aan(stappen, run_conclusie='failure'))

        signalen = op_sleutel(module.signalen_heartbeat(REPO, {}))

        self.assertEqual(signalen['heartbeat-parasend']['ernst'], module.ROOD)
        self.assertIn('PARAMANT_CANARY_KEY', signalen['heartbeat-parasend']['meting'])
        # De run viel door parasend. Dat rode signaal staat er al, dus surface
        # hoeft daar niet ook nog voor te boeten.
        self.assertEqual(signalen['heartbeat-surface']['ernst'], module.GROEN)

    def test_rode_run_met_groene_proefstappen_is_oranje(self):
        # De proefstap draait met continue-on-error: de run kan vallen op de
        # browserhelft of de linkcheck terwijl alle drie de stappen groen zijn.
        module = met_stub(stub_aan(GROENE_STAPPEN, run_conclusie='failure'))

        signalen = op_sleutel(module.signalen_heartbeat(REPO, {}))

        for sleutel, sig in signalen.items():
            self.assertEqual(sig['ernst'], module.ORANJE, sleutel)
            self.assertIn('buiten de drie proefstappen', sig['meting'])

    def test_uitslag_ouder_dan_twee_uur_is_rood(self):
        module = met_stub(stub_aan(GROENE_STAPPEN, run_leeftijd_uren=3.0))

        signalen = op_sleutel(module.signalen_heartbeat(REPO, {}))

        for sleutel, sig in signalen.items():
            self.assertEqual(sig['ernst'], module.ROOD, sleutel)
            self.assertIn('oud', sig['meting'])

    def test_dry_run_is_nooit_groen(self):
        module = met_stub(stub_aan(GROENE_STAPPEN, dry_run=True))

        signalen = op_sleutel(module.signalen_heartbeat(REPO, {}))

        for sleutel, sig in signalen.items():
            self.assertEqual(sig['ernst'], module.ORANJE, sleutel)
            self.assertIn('dry run', sig['meting'])

    def test_zonder_bewijsartefact_geen_stilzwijgend_groen(self):
        stub = stub_aan(GROENE_STAPPEN)
        stub.artefacten = []
        module = met_stub(stub)

        signalen = op_sleutel(module.signalen_heartbeat(REPO, {}))

        for sleutel, sig in signalen.items():
            self.assertEqual(sig['ernst'], module.ORANJE, sleutel)
            self.assertIn('geen bewijsartefact', sig['meting'])

    def test_aan_zonder_afgeronde_run_is_rood(self):
        stub = stub_aan(GROENE_STAPPEN)
        stub.runs = {('heartbeat.yml', 'schedule'): [],
                     ('heartbeat.yml', 'workflow_dispatch'): []}
        module = met_stub(stub)

        signalen = module.signalen_heartbeat(REPO, {})

        self.assertEqual(len(signalen), 1)
        self.assertEqual(signalen[0]['ernst'], module.ROOD)
        self.assertIn('geen afgeronde run', signalen[0]['meting'])


class IssueTests(unittest.TestCase):
    def test_open_alarmissue_is_rood_met_url(self):
        url = 'https://github.com/eigenaar/repo/issues/350'
        stub = GhStub(issues=[
            {'number': 350, 'title': 'Heartbeat rood', 'url': url,
             'createdAt': stempel(30)},
            {'number': 351, 'title': 'iets anders', 'url': 'x',
             'createdAt': stempel(1)},
        ])
        module = met_stub(stub)

        sig = module.signaal_heartbeat_issue(REPO)

        self.assertEqual(sig['ernst'], module.ROOD)
        self.assertIn(url, sig['meting'])
        self.assertEqual(sig['details']['nummer'], 350)

    def test_zonder_alarmissue_groen(self):
        module = met_stub(GhStub(issues=[{'number': 9, 'title': 'iets anders',
                                          'url': 'x', 'createdAt': stempel(1)}]))

        sig = module.signaal_heartbeat_issue(REPO)

        self.assertEqual(sig['ernst'], module.GROEN)


class PrGateTests(unittest.TestCase):
    def test_gate_in_deze_werkkopie_wordt_als_gate_gelezen(self):
        run = {'databaseId': 9, 'conclusion': 'success', 'status': 'completed',
               'createdAt': stempel(2), 'updatedAt': stempel(2),
               'event': 'pull_request', 'url': 'x', 'headBranch': 'main'}
        stub = GhStub(runs={('product-heartbeat.yml', 'pull_request'): [run],
                            ('product-heartbeat.yml', 'push'): []})
        module = met_stub(stub)

        sig = module.signaal_pr_gate(REPO, str(ROOT), {})

        self.assertEqual(sig['sleutel'], 'pr-gate-heartbeat')
        self.assertEqual(sig['ernst'], module.GROEN)

    def test_gate_met_schedule_is_oranje(self):
        module = met_stub(GhStub())
        with tempfile.TemporaryDirectory() as tmp:
            pad = Path(tmp) / '.github' / 'workflows'
            pad.mkdir(parents=True)
            (pad / 'product-heartbeat.yml').write_text(
                'on:\n  schedule:\n    - cron: "0 * * * *"\n  pull_request:\n    branches: [main]\n',
                encoding='utf-8')

            sig = module.signaal_pr_gate(REPO, tmp, {})

        self.assertEqual(sig['ernst'], module.ORANJE)
        self.assertIn('schedule', sig['meting'])

    def test_verdwenen_gate_is_oranje(self):
        module = met_stub(GhStub())
        with tempfile.TemporaryDirectory() as tmp:
            sig = module.signaal_pr_gate(REPO, tmp, {})

        self.assertEqual(sig['ernst'], module.ORANJE)
        self.assertIn('staat niet in', sig['meting'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
