#!/usr/bin/env python3
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADMIN_SOURCE = ROOT / 'deploy' / 'paramant-admin.py'
ENV_KEYS = (
    'PARAMANT_COMPOSE_PROJECT',
    'COMPOSE_PROJECT_NAME',
    'PARAMANT_DIR',
    'PARAMANT_DOCKER_VOLUMES_DIR',
    'PARAMANT_SECTORS_DIR',
)


@contextmanager
def isolated_env(updates):
    saved = {key: os.environ.get(key) for key in ENV_KEYS}
    for key in ENV_KEYS:
        os.environ.pop(key, None)
    os.environ.update(updates)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def load_admin(script_path, env):
    with isolated_env(env):
        name = f'paramant_admin_{uuid.uuid4().hex}'
        spec = importlib.util.spec_from_file_location(name, script_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
            return module
        finally:
            sys.modules.pop(name, None)


class ParamantAdminPathTests(unittest.TestCase):
    def test_default_install_layout_writes_to_volume_before_users_json_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            install_dir = tmp / 'opt' / 'paramant'
            script_path = install_dir / 'deploy' / 'paramant-admin.py'
            script_path.parent.mkdir(parents=True)
            shutil.copy2(ADMIN_SOURCE, script_path)

            volumes = tmp / 'docker' / 'volumes'
            live_data = volumes / 'paramant_relay-main-data' / '_data'
            live_data.mkdir(parents=True)

            sectors = tmp / 'home' / 'paramant'
            legacy_dir = sectors / 'relay-main'
            legacy_dir.mkdir(parents=True)
            legacy_file = legacy_dir / 'users.json'
            legacy_file.write_text('{"api_keys": [{"key": "stale"}]}\n')

            admin = load_admin(script_path, {
                'PARAMANT_DOCKER_VOLUMES_DIR': str(volumes),
                'PARAMANT_SECTORS_DIR': str(sectors),
            })

            self.assertEqual(admin.COMPOSE_PROJECT, 'paramant')
            self.assertEqual(Path(admin.SECTORS['main']), live_data / 'users.json')

            args = types.SimpleNamespace(label='alice', plan='pro', email='', sector='main')
            admin.cmd_add(args)

            live_users = json.loads((live_data / 'users.json').read_text())
            legacy_users = json.loads(legacy_file.read_text())
            self.assertEqual(len(live_users['api_keys']), 1)
            self.assertEqual(live_users['api_keys'][0]['label'], 'alice')
            self.assertEqual(legacy_users['api_keys'][0]['key'], 'stale')

    def test_explicit_compose_project_override_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            volumes = tmp / 'volumes'
            live_data = volumes / 'customstack_relay-health-data' / '_data'
            live_data.mkdir(parents=True)

            admin = load_admin(ADMIN_SOURCE, {
                'PARAMANT_COMPOSE_PROJECT': 'customstack',
                'PARAMANT_DOCKER_VOLUMES_DIR': str(volumes),
                'PARAMANT_SECTORS_DIR': str(tmp / 'legacy'),
            })

            self.assertEqual(admin.COMPOSE_PROJECT, 'customstack')
            self.assertEqual(Path(admin.SECTORS['health']), live_data / 'users.json')

    def test_legacy_path_is_used_only_when_volume_directory_is_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            sectors = tmp / 'home' / 'paramant'

            admin = load_admin(ADMIN_SOURCE, {
                'PARAMANT_COMPOSE_PROJECT': 'missingstack',
                'PARAMANT_DOCKER_VOLUMES_DIR': str(tmp / 'volumes'),
                'PARAMANT_SECTORS_DIR': str(sectors),
            })

            self.assertEqual(Path(admin.SECTORS['iot']), sectors / 'relay-iot' / 'users.json')


if __name__ == '__main__':
    unittest.main()
