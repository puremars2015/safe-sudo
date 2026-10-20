import importlib.util
import io
import json
from pathlib import Path
import time
import unittest
from unittest.mock import Mock, patch

import test_telegram_sudo as helpers

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.module = load('telegram_sudo')
        self.command = load('command_sudo')
        self.request = {'command': 'printf "<test>"; exit 7', 'reason': 'test <only>'}
        self.session = self.command.make_session(self.module, '123:TEST_TOKEN', 123456789, self.request)
        self.session.origin = 'https://example.trycloudflare.com'

    def payload(self):
        return {'nonce': self.session.ticket.nonce,
                'init_data': helpers.TelegramSudoTests().signed(auth_date=int(time.time())),
                'password': 'FAKE-ONLY'}

    def test_validation_and_snapshot(self):
        for invalid in ({}, {**self.request, 'password': 'no'},
                        {**self.request, 'command': 'x\x00'},
                        {**self.request, 'command': 'x\u202ey'},
                        {**self.request, 'command': 'x' * 1401}):
            with self.assertRaises(ValueError):
                self.command.validate_request(invalid)
        self.request['command'] = 'changed'
        self.assertEqual(self.session.argv()[-1], 'printf "<test>"; exit 7')
        self.assertIn('&lt;test&gt;', self.session.operation_html)
        self.assertIn('&lt;only&gt;', self.session.operation_html)

    def test_unsigned_origin_override_and_expired_never_spawn(self):
        with patch.object(self.module.subprocess, 'Popen') as spawn:
            for payload, origin in (({**self.payload(), 'init_data': 'unsigned'}, self.session.origin),
                                    (self.payload(), 'https://wrong.example'),
                                    ({**self.payload(), 'command': 'id'}, self.session.origin)):
                self.assertIn(self.session.submit(payload, origin)[0], (400, 403))
            self.session.ticket.expires = time.monotonic() - 1
            self.assertEqual(self.session.submit(self.payload(), self.session.origin)[0], 410)
            spawn.assert_not_called()

    def test_http_single_attempt_password_only_stdin_and_safe_result(self):
        process = Mock()
        process.stdin = io.BytesIO()
        written = []
        process.stdin = Mock(write=lambda data: written.append(data))
        process.stdout = io.BytesIO(b'{"ok":false,"status":"completed","exit_code":7}')
        process.wait.return_value = 0
        payload = self.payload()
        replay = payload.copy()
        with patch.object(self.module.subprocess, 'Popen', return_value=process) as spawn:
            handler = helpers.offline_handler(self.module, self.session, payload)
            handler.do_POST()
            handler.send_response.assert_called_once_with(202)
            self.assertTrue(self.session.finished.wait(2))
            self.assertTrue(self.session.response_complete.is_set())
            self.assertEqual(self.session.result, {'ok': False, 'status': 'completed', 'exit_code': 7})
            self.assertEqual(written, [b'FAKE-ONLY\n'])
            self.assertNotIn('FAKE-ONLY', repr(spawn.call_args))
            self.assertEqual(self.session.submit(replay, self.session.origin)[0], 410)
            self.assertEqual(spawn.call_count, 1)

    def test_missing_root_result_not_success_or_stopped(self):
        process = Mock(stdout=io.BytesIO(b'not-json'))
        process.wait.return_value = 1
        self.session._monitor(process)
        self.assertEqual(self.session.result, {'ok': False, 'status': 'execution_unconfirmed'})

    def test_root_bootstrap_exact_shell_no_password_stdin_or_output(self):
        import contextlib
        import os
        import subprocess
        import sys
        output = io.StringIO()
        with patch.object(os, 'geteuid', return_value=0), \
                patch.object(sys, 'argv', ['bootstrap', self.request['command']]), \
                patch.object(subprocess, 'call', return_value=7) as call, \
                contextlib.redirect_stdout(output):
            exec(compile(self.command.BOOTSTRAP, '<test-bootstrap>', 'exec'), {})
        self.assertEqual(call.call_args.args[0], ['/bin/bash', '--noprofile', '--norc', '-c', self.request['command']])
        self.assertEqual(call.call_args.kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(call.call_args.kwargs['stdout'], subprocess.DEVNULL)
        self.assertEqual(call.call_args.kwargs['stderr'], subprocess.DEVNULL)
        self.assertEqual(call.call_args.kwargs['cwd'], '/')
        self.assertEqual(json.loads(output.getvalue()), {'ok': False, 'status': 'completed', 'exit_code': 7})

    def test_dispatch_and_result_message(self):
        runner = load('telegram_request')
        called = []
        result = runner.serve('command', request=self.request,
                              transport=lambda **kw: called.append(kw) or {'status': 'waiting'})
        self.assertEqual(result['status'], 'waiting')
        self.assertEqual(called, [{'action': 'command', 'request': self.request}])
        self.assertIn('7', runner.result_text('command', {'ok': False, 'status': 'completed', 'exit_code': 7}))
        self.assertNotIn('✅', runner.result_text('command', {'ok': False, 'status': 'execution_unconfirmed'}))
