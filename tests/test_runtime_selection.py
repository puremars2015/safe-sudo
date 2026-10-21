import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RuntimeSelectionTests(unittest.TestCase):
    def setUp(self):
        self.runner = load('telegram_request')
        self.setup = load('setup_runtime')
        self.tempdir = tempfile.TemporaryDirectory()
        self.home = Path(self.tempdir.name)
        self.environment = patch.dict(os.environ, {'HERMES_HOME': str(self.home)}, clear=False)
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.tempdir.cleanup()

    def test_legacy_default_is_podman(self):
        self.assertEqual(self.runner.selected_runtime(), 'podman')

    def test_runtime_commands_preserve_sandbox_flags(self):
        for runtime, binary in (('docker', '/usr/bin/docker'), ('podman', '/usr/bin/podman')):
            argv = self.runner.tunnel_run_argv(runtime, 'safe-test', 45678)
            self.assertEqual(argv[0], binary)
            self.assertEqual(argv[1:4], ['run', '--rm', '--name'])
            self.assertIn('--network', argv)
            self.assertEqual(argv[argv.index('--network') + 1], 'host')
            self.assertIn('--read-only', argv)
            self.assertIn('--cap-drop=all', argv)
            self.assertIn('--security-opt=no-new-privileges', argv)
            self.assertEqual(argv[-1], 'http://127.0.0.1:45678')
        self.assertEqual(self.runner.container_remove_argv('docker', 'safe-test'),
                         ['/usr/bin/docker', 'rm', '-f', 'safe-test'])
        self.assertEqual(self.runner.container_exists_argv('docker', 'safe-test'),
                         ['/usr/bin/docker', 'container', 'inspect', 'safe-test'])
        self.assertEqual(self.runner.container_exists_argv('podman', 'safe-test'),
                         ['/usr/bin/podman', 'container', 'exists', 'safe-test'])

    def test_invalid_runtime_config_fails_closed(self):
        self.home.mkdir(exist_ok=True)
        (self.home / 'safe-sudo.json').write_text('{"container_runtime":"/tmp/evil"}', encoding='utf-8')
        with self.assertRaisesRegex(RuntimeError, 'container_runtime_invalid'):
            self.runner.selected_runtime()

    def test_setup_writes_private_profile_config(self):
        fake_binary = self.home / 'docker'
        fake_binary.write_text('', encoding='utf-8')
        fake_binary.chmod(0o700)
        with patch.dict(self.setup.RUNTIMES, {'docker': str(fake_binary)}, clear=False), \
                patch.object(self.setup.subprocess, 'run') as run:
            run.return_value.returncode = 0
            self.setup.verify_runtime('docker')
            path = self.setup.write_runtime('docker')
        self.assertEqual(json.loads(path.read_text(encoding='utf-8')), {'container_runtime': 'docker'})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_setup_rejects_unavailable_runtime(self):
        with patch.dict(self.setup.RUNTIMES, {'podman': str(self.home / 'missing-podman')}, clear=False):
            with self.assertRaisesRegex(ValueError, 'runtime_unavailable'):
                self.setup.verify_runtime('podman')


if __name__ == '__main__':
    unittest.main()
