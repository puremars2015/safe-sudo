import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'sudo_broker.py'

class SafeSudoTests(unittest.TestCase):
    def test_rejects_unknown_action_without_prompt(self):
        self.assertTrue(MODULE.exists(), 'safe sudo broker 尚未實作')
        spec = importlib.util.spec_from_file_location('safe_sudo_broker', MODULE)
        broker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(broker)
        with patch.object(broker, 'prompt_password') as prompt:
            result = broker.run_action('arbitrary-shell')
        self.assertEqual(result['status'], 'invalid_action')
        prompt.assert_not_called()

    def test_identity_uses_stdin_not_argv_and_does_not_cache(self):
        spec = importlib.util.spec_from_file_location('safe_sudo_broker', MODULE)
        broker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(broker)
        from subprocess import CompletedProcess
        secret = b'TEST-ONLY-not-a-real-password'
        with patch.object(broker, 'prompt_password', return_value=secret), patch.object(broker, 'execute_sudo', create=True, return_value=CompletedProcess([], 0, b'0\n', b'')) as execute:
            result = broker.run_action('identity')
        self.assertTrue(result['ok'])
        args, kwargs = execute.call_args
        self.assertEqual(args[0], ['/usr/bin/id', '-u'])
        self.assertEqual(args[1], secret)
        self.assertNotIn(secret.decode(), json.dumps(result))

    def load_broker(self):
        spec = importlib.util.spec_from_file_location('safe_sudo_broker', MODULE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_cancel_does_not_start_sudo(self):
        broker = self.load_broker()
        with patch.object(broker, 'prompt_password', return_value=None), patch.object(broker, 'execute_sudo') as execute:
            result = broker.run_action('identity')
        self.assertFalse(result['ok'])
        execute.assert_not_called()

    def test_no_desktop_does_not_prompt(self):
        broker = self.load_broker()
        with patch.dict('os.environ', {'DISPLAY': ''}), patch.object(broker.subprocess, 'run') as run:
            self.assertIsNone(broker.prompt_password())
        run.assert_not_called()

    def test_sudo_subprocess_has_no_secret_in_args_env(self):
        broker = self.load_broker()
        secret = b'TEST-ONLY-secret'
        with patch.object(broker.subprocess, 'run') as run:
            broker.execute_sudo(['/usr/bin/id', '-u'], secret)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ['/usr/bin/sudo', '-k', '-S', '-p', '', '--', '/usr/bin/id', '-u'])
        self.assertEqual(kwargs['input'], secret + b'\n')
        self.assertNotIn(secret.decode(), repr(args))
        self.assertNotIn(secret.decode(), repr(kwargs['env']))
        self.assertEqual(kwargs['stderr'], broker.subprocess.DEVNULL)
        self.assertNotIn('shell', kwargs)

    def test_sudo_failure_redacts_output(self):
        broker = self.load_broker()
        result = broker.subprocess.CompletedProcess([], 1, b'TEST-SECRET', b'TEST-SECRET')
        with patch.object(broker, 'prompt_password', return_value=b'TEST-SECRET'), patch.object(broker, 'execute_sudo', return_value=result):
            response = broker.run_action('identity')
        self.assertEqual(response['status'], 'sudo_failed')
        self.assertNotIn('TEST-SECRET', json.dumps(response))

    def test_timeout_returns_no_secret(self):
        broker = self.load_broker()
        with patch.object(broker, 'prompt_password', side_effect=broker.subprocess.TimeoutExpired(['zenity'], 130, output=b'TEST-SECRET')):
            response = broker.run_action('identity')
        self.assertEqual(response['status'], 'timeout')
        self.assertNotIn('TEST-SECRET', json.dumps(response))

    def test_unexpected_stdout_not_returned(self):
        broker = self.load_broker()
        result = broker.subprocess.CompletedProcess([], 0, b'PRIVATE', b'')
        with patch.object(broker, 'prompt_password', return_value=b'TEST'), patch.object(broker, 'execute_sudo', return_value=result):
            response = broker.run_action('identity')
        self.assertEqual(response['status'], 'unexpected_output')
        self.assertNotIn('PRIVATE', json.dumps(response))

    def test_plugin_rejects_password_argument(self):
        spec = importlib.util.spec_from_file_location('safe_sudo_plugin', MODULE.parent / '__init__.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module.subprocess, 'run') as run:
            result = json.loads(module.handle_safe_sudo({'action': 'identity', 'password': 'TEST-ONLY'}))
        self.assertEqual(result['status'], 'invalid_arguments')
        run.assert_not_called()

    def test_plugin_identity_routes_to_telegram(self):
        spec = importlib.util.spec_from_file_location('safe_sudo_plugin', MODULE.parent / '__init__.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module, 'start_telegram_request', create=True, return_value={'ok': True, 'status': 'waiting'}) as start, patch.object(module.subprocess, 'run') as desktop:
            result = json.loads(module.handle_safe_sudo({'action': 'identity'}))
        self.assertEqual(result['status'], 'waiting')
        start.assert_called_once_with()
        desktop.assert_not_called()

if __name__ == '__main__':
    unittest.main()
