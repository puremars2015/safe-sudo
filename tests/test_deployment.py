"""Offline only: fake credentials/processes; no sudo, socket or network."""
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
ACTION = 'ymir_deploy_4b8a3af'


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if name == 'telegram_request':
        module.TARGET_USER = 123456789  # Isolated test recipient; no real Telegram calls.
    return module


class DeploymentTests(unittest.TestCase):
    def test_pinned_bootstrap_and_result_contract(self):
        module = load('telegram_sudo')
        self.assertTrue(hasattr(module, 'deploy_argv'), 'fixed pinned bootstrap missing')
        with patch.object(module, 'APPROVED_DEPLOY_SHA256', None), self.assertRaises(ValueError):
            module.deploy_argv()
        with patch.object(module, 'APPROVED_DEPLOY_SHA256', 'a' * 64):
            argv = module.deploy_argv()
        self.assertEqual(argv[:10], ['/usr/bin/sudo', '-k', '-S', '-p', '', '--', '/usr/bin/python3', '-I', '-S', '-c'])
        self.assertIn(module.DEPLOY_SOURCE, argv[10])
        self.assertIn('a' * 64, argv[10])
        compile(argv[10], '<fixed-bootstrap>', 'exec')
        good = {'ok': True, 'status': 'deployed', 'version': '4b8a3af', 'schema_verified': True}
        self.assertEqual(module.sanitize_deploy_result(json.dumps(good).encode(), 0), good)
        for data, rc in ((good, 1), ({**good, 'schema_verified': 1}, 0),
                         ({**good, 'password': 'TEST-SECRET'}, 0),
                         ({**good, 'version': 'bad'}, 0), ({**good, 'ok': False}, 0)):
            result = module.sanitize_deploy_result(json.dumps(data).encode(), rc)
            self.assertFalse(result['ok'])
            self.assertNotIn('TEST-SECRET', json.dumps(result))
        self.assertFalse(module.sanitize_deploy_result(b'{"status":"deployed","status":"failed"}', 0)['ok'])

    def test_async_accept_clears_secret_before_monitor_and_rejects_selectors(self):
        module = load('telegram_sudo')
        self.assertTrue(hasattr(module, 'DeploymentSession'), 'independent deployment session missing')
        stdin = Mock()
        process = Mock(stdin=stdin)
        monitor = Mock()
        with patch.object(module, 'APPROVED_DEPLOY_SHA256', 'a' * 64), patch.object(module, 'verify_init_data', return_value=True), patch.object(module.subprocess, 'Popen', return_value=process) as popen, patch.object(module.threading, 'Thread', return_value=monitor) as thread:
            session = module.DeploymentSession('123:TEST_TOKEN', 1)
            session.origin = 'https://example.trycloudflare.com'
            payload = {'nonce': session.ticket.nonce, 'init_data': 'FAKE', 'password': 'TEST-ONLY'}
            self.assertEqual(session.submit({**payload, 'action': 'identity'}, session.origin)[0], 400)
            self.assertFalse(session.ticket.used)
            def start():
                self.assertEqual(payload, {})
                self.assertNotIn('TEST-ONLY', repr(thread.call_args))
                self.assertFalse(session.finished.is_set())
            monitor.start.side_effect = start
            status, result = session.submit(payload, session.origin)
            self.assertEqual((status, result), (202, {'ok': True, 'status': 'accepted', 'action': ACTION}))
            self.assertTrue(session.accepted.is_set())
            self.assertGreaterEqual(session.execution_deadline - session.accepted_at, 1800)
            stdin.write.assert_called_once_with(b'TEST-ONLY\n')
            stdin.close.assert_called_once()
            self.assertNotIn('TEST-ONLY', repr(popen.call_args))
            self.assertEqual(popen.call_args.kwargs['stderr'], module.subprocess.DEVNULL)
            self.assertEqual(session.submit({'nonce': session.ticket.nonce, 'init_data': 'FAKE', 'password': 'TEST-ONLY'}, session.origin)[0], 410)

    def test_async_http_drains_202_without_waiting_root(self):
        from test_telegram_sudo import offline_handler
        module = load('telegram_sudo')
        self.assertTrue(hasattr(module, 'DeploymentSession'), 'async deployment missing')
        with patch.object(module, 'APPROVED_DEPLOY_SHA256', 'a' * 64), patch.object(module, 'verify_init_data', return_value=True), patch.object(module.subprocess, 'Popen', return_value=Mock()), patch.object(module.threading, 'Thread', return_value=Mock()):
            session = module.DeploymentSession('123:TEST_TOKEN', 1)
            session.origin = 'https://example.trycloudflare.com'
            handler = offline_handler(module, session, {'nonce': session.ticket.nonce, 'init_data': 'FAKE', 'password': 'TEST-ONLY'})
            handler.do_POST()
        handler.send_response.assert_called_once_with(202)
        self.assertTrue(session.response_complete.is_set())
        self.assertFalse(session.finished.is_set())

    def test_monitor_drains_bounded_pipe_and_preserves_real_result(self):
        import os, time
        module = load('telegram_sudo')
        self.assertTrue(hasattr(module, 'monitor_deployment'), 'bounded deployment monitor missing')
        for raw in (json.dumps({'ok': True, 'status': 'deployed', 'version': '4b8a3af', 'schema_verified': True}).encode(), b'TEST-SECRET', b'x' * 9000):
            readfd, writefd = os.pipe()
            stdout = os.fdopen(readfd, 'rb', buffering=0)
            process = Mock(stdout=stdout, stdin=None, pid=999999)
            process.poll.return_value = 0
            process.wait.return_value = 0
            # Oversized data written in a concurrent thread to avoid pipe capacity.
            import threading
            def writer():
                try:
                    os.write(writefd, raw)
                finally:
                    os.close(writefd)
            writer_thread = threading.Thread(target=writer)
            writer_thread.start()
            result = module.monitor_deployment(process, time.monotonic())
            writer_thread.join(1)
            self.assertEqual(result['ok'], raw.startswith(b'{'))
            self.assertNotIn('TEST-SECRET', json.dumps(result))
            self.assertTrue(stdout.closed)

    def test_monitor_timeout_gives_rollback_grace_and_keeps_rollback(self):
        module = load('telegram_sudo')
        self.assertTrue(hasattr(module, 'monitor_deployment'), 'bounded deployment monitor missing')
        process = Mock(pid=999999, stdin=None)
        raw = json.dumps({'ok': False, 'status': 'rolled_back', 'version': '4b8a3af', 'schema_verified': False, 'code': 'rollback_complete'}).encode()
        with patch.object(module.time, 'monotonic', return_value=1900), patch.object(module, 'drain_deploy_stdout', side_effect=[(b'', False), (raw, True)]) as drain, patch.object(module, 'signal_deploy_process') as signal:
            process.poll.return_value = 1
            process.wait.return_value = 1
            result = module.monitor_deployment(process, 100)
        self.assertEqual(result['status'], 'rolled_back')
        self.assertIn('deployment_deadline_exceeded', result['cleanup_errors'])
        self.assertEqual(drain.call_args_list[0].args[1], 1900)
        self.assertEqual(drain.call_args_list[1].args[1], 2020)
        signal.assert_called_once()

    def test_deploy_runner_waits_past_identity_thirty_seconds(self):
        module = load('telegram_sudo')
        runner = load('telegram_request')
        session = module.DeploymentSession('123:TEST_TOKEN', 1)
        session._accept(100)
        session.response_complete.set()
        session.finished = Mock()
        def finish(timeout):
            self.assertGreaterEqual(timeout, 1700)
            session.result = {'ok': True, 'status': 'deployed', 'version': '4b8a3af', 'schema_verified': True}
            return True
        session.finished.wait.side_effect = finish
        session.finished.is_set.return_value = True
        with patch.object(runner.time, 'monotonic', return_value=131):
            self.assertEqual(runner.wait_for_result(session)['status'], 'deployed')

    def test_parent_stdout_contract_and_manual_pending(self):
        module = load('telegram_sudo')
        good = {'ok': True, 'status': 'deployed', 'stage': 'verified',
                'new_image_id': 'sha256:' + 'a' * 64, 'backup_dir': '/var/backups/ymir/20261014',
                'rollback': False, 'checks': {'schema_verified': True, 'api': True, 'runtime_host': True},
                'user_acceptance_pending': ['entra_login', 'pi_sse']}
        self.assertEqual(module.sanitize_deploy_result(json.dumps(good).encode(), 0), good)
        self.assertFalse(module.sanitize_deploy_result(json.dumps({**good, 'checks': {'schema_verified': False}}).encode(), 0)['ok'])
        self.assertFalse(module.sanitize_deploy_result(json.dumps({**good, 'rollback': 0}).encode(), 0)['ok'])
        self.assertFalse(module.sanitize_deploy_result(json.dumps({**good, 'user_acceptance_pending': ['TEST-SECRET']}).encode(), 0)['ok'])
        runner = load('telegram_request')
        self.assertTrue(hasattr(runner, 'result_text'), 'action-specific Bot text missing')
        text = runner.result_text(ACTION, good)
        self.assertIn('API/RuntimeHost', text)
        self.assertIn('Entra', text)
        self.assertIn('Pi SSE', text)
        self.assertNotIn('UID 0', text)

    def test_action_specific_ui_and_launcher(self):
        from test_telegram_sudo import offline_handler
        from test_lifecycle import fake_launch
        module = load('telegram_sudo')
        session = module.DeploymentSession('123:TEST_TOKEN', 1)
        session.origin = 'https://example.trycloudflare.com'
        handler = offline_handler(module, session, {})
        handler.path = '/'
        handler.do_GET()
        page = handler.wfile.getvalue().decode()
        self.assertIn('Ymir 4b8a3af', page)
        self.assertIn('RuntimeHost', page)
        self.assertIn('短暫中斷', page)
        self.assertIn('失敗', page)
        self.assertNotIn('不會重新部署或修改 Ymir', page)
        self.assertIn('部署已受理，請回 Telegram 等結果', (ROOT / 'web/app.js').read_text())
        runner = load('telegram_request')
        with patch.object(runner, 'session_module', return_value=Mock(deployment_approved=Mock(return_value=False))), patch.object(runner, 'bot_token') as token:
            self.assertEqual(runner.launch_request(ACTION)['status'], 'deployment_not_approved')
        token.assert_not_called()
        plugin = load('__init__')
        child = Mock()
        child.stdout.readline.return_value = b'{"ok":true,"status":"waiting"}\n'
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.select.return_value = [True]
        with patch.object(plugin.subprocess, 'Popen', return_value=child) as popen, patch.object(plugin.selectors, 'DefaultSelector', return_value=selector):
            plugin.start_telegram_request(ACTION)
        self.assertEqual(popen.call_args.args[0][-1], ACTION)

    def test_deploy_launch_and_message_text_readback(self):
        from test_lifecycle import fake_launch
        with fake_launch() as f:
            f['session'].action = ACTION
            module = Mock(deployment_approved=Mock(return_value=True), DeploymentSession=Mock(return_value=f['session']), make_server=Mock(return_value=f['server']))
            f['response'].read.return_value = json.dumps({'ok': True, 'scope': ACTION, 'requires_signed_telegram': True}).encode()
            expected = {'ok': True, 'status': 'deployed', 'checks': {'schema_verified': True}, 'user_acceptance_pending': ['entra_login', 'pi_sse']}
            f['wait'].return_value = expected
            with patch.object(f['runner'], 'session_module', return_value=module):
                result = f['runner'].launch_request(ACTION)
            self.assertEqual(result['status'], 'deployed')
            module.DeploymentSession.assert_called_once()
            messages = [payload['text'] for method, payload in f['calls'] if method in ('sendMessage', 'editMessageText')]
            self.assertIn('真的部署', messages[0])
            self.assertIn('API/RuntimeHost', messages[-1])
            self.assertIn('尚未測試', messages[-1])
            self.assertNotIn('UID 0', messages[-1])

    def test_bootstrap_fake_filesystem_security_and_exit(self):
        import hashlib, os, runpy, stat, sys
        from contextlib import ExitStack, redirect_stdout
        from io import StringIO
        from types import SimpleNamespace
        module = load('telegram_sudo')
        reviewed = b'# PURE FAKE REVIEWED BYTES; never executed'
        pin = hashlib.sha256(reviewed).hexdigest()
        for scenario in ('new', 'existing', 'mismatch', 'source_oversize', 'parent_writable', 'parent_user', 'symlink', 'stored_user', 'stored_writable', 'stored_hash', 'exit_zero'):
            with self.subTest(scenario=scenario):
                records = {}
                positions = {}
                writes = []
                counter = [0]
                def opened(path, flags, *args, **kw):
                    if path == module.DEPLOY_SOURCE:
                        record = ['source', reviewed, stat.S_IFREG | 0o600, 1000]
                        if scenario == 'mismatch':
                            record[1] = b'WRONG'
                        if scenario == 'source_oversize':
                            record[1] = b'x' * 262145
                    elif flags & os.O_DIRECTORY:
                        if scenario == 'symlink' and path == 'ymir-deploy':
                            raise OSError('TEST-SECRET')
                        record = ['dir', b'', stat.S_IFDIR | 0o755, 0]
                        if path == 'ymir-deploy':
                            if scenario == 'parent_writable':
                                record[2] |= 0o020
                            if scenario == 'parent_user':
                                record[3] = 1000
                    elif flags & os.O_EXCL:
                        if scenario != 'new':
                            raise FileExistsError()
                        record = ['target', b'', stat.S_IFREG | 0o600, 0]
                    else:
                        record = ['stored', reviewed, stat.S_IFREG | 0o600, 0]
                        if scenario == 'stored_user':
                            record[3] = 1000
                        if scenario == 'stored_writable':
                            record[2] |= 0o020
                        if scenario == 'stored_hash':
                            record[1] = b'WRONG'
                    counter[0] += 1
                    records[counter[0]] = record
                    positions[counter[0]] = 0
                    return counter[0]
                def fstat(fd):
                    kind, data, mode, uid = records[fd]
                    return SimpleNamespace(st_mode=mode, st_uid=uid, st_size=len(data), st_nlink=1)
                def read(fd, size):
                    pos = positions[fd]
                    data = records[fd][1][pos:pos + size]
                    positions[fd] += len(data)
                    return data
                def write(fd, view):
                    writes.append(bytes(view))
                    return len(view)
                captured = StringIO()
                with ExitStack() as stack:
                    for name, replacement in {'geteuid': lambda: 0, 'open': opened, 'fstat': fstat,
                                              'read': read, 'write': write, 'close': lambda _: None,
                                              'mkdir': lambda *a, **k: None, 'fsync': lambda _: None}.items():
                        stack.enter_context(patch.object(os, name, side_effect=replacement))
                    chmod = stack.enter_context(patch.object(os, 'fchmod'))
                    execute = Mock(return_value=(b'{"ok":false,"status":"blocked"}', 0 if scenario == 'exit_zero' else 1))
                    stack.enter_context(patch('signal.signal'))
                    stack.enter_context(patch.object(module, 'APPROVED_DEPLOY_SHA256', pin))
                    with redirect_stdout(captured):
                        namespace = {}
                        bootstrap = module.deploy_argv()[10]
                        exec(compile(bootstrap.split('\ntry:\n    main()')[0], '<fake-only>', 'exec'), namespace)
                        namespace['supervise'] = execute
                        try:
                            namespace['main']()
                        except SystemExit as error:
                            self.assertIn(error.code, (0, 1))
                        except BaseException:
                            print(json.dumps({'code': 'bootstrap_rejected'}))
                success = scenario in ('new', 'existing', 'exit_zero')
                self.assertEqual(execute.call_count, int(success))
                if success:
                    self.assertEqual(json.loads(captured.getvalue()), {'ok': False, 'status': 'blocked'})
                    self.assertEqual(execute.call_args.args[0], '/usr/local/libexec/ymir-deploy/' + pin + '.py')
                else:
                    self.assertEqual(json.loads(captured.getvalue())['code'], 'bootstrap_rejected')
                if scenario == 'new':
                    self.assertEqual(b''.join(writes), reviewed)
                    self.assertIn(0o755, [call.args[1] for call in chmod.call_args_list])
                if scenario == 'stored_hash':
                    self.assertEqual(writes, [])

    def test_bot_text_readback_mismatch_keeps_real_root_result(self):
        from test_lifecycle import fake_launch
        for phase in ('initial', 'final'):
            with self.subTest(phase=phase), fake_launch() as f:
                f['session'].action = ACTION
                module = Mock(deployment_approved=Mock(return_value=True), DeploymentSession=Mock(return_value=f['session']), make_server=Mock(return_value=f['server']))
                f['response'].read.return_value = json.dumps({'ok': True, 'scope': ACTION, 'requires_signed_telegram': True}).encode()
                f['wait'].return_value = {'ok': True, 'status': 'deployed', 'checks': {'schema_verified': True}}
                original = f['bot'].side_effect
                def api(token, method, payload):
                    record = original(token, method, payload)
                    if method == 'editMessageText':
                        final = payload.get('reply_markup') == {'inline_keyboard': []}
                        record['text'] = 'WRONG' if final == (phase == 'final') else payload['text']
                    return record
                f['bot'].side_effect = api
                with patch.object(f['runner'], 'session_module', return_value=module):
                    result = f['runner'].launch_request(ACTION)
                if phase == 'initial':
                    self.assertEqual(result['status'], 'request_failed')
                    self.assertEqual(result['stage'], 'telegram_button')
                else:
                    self.assertEqual(result['status'], 'deployed')
                    self.assertIn('button_retirement_failed', result['cleanup_errors'])

    def test_start_error_and_monitor_rescue_never_keep_credentials(self):
        module = load('telegram_sudo')
        for failure in ('stdin', 'close', 'thread', 'popen'):
            with self.subTest(failure=failure):
                stdin = Mock()
                process = Mock(stdin=stdin)
                thread = Mock()
                session = module.DeploymentSession('123:TEST_TOKEN', 1)
                session.origin = 'https://example.trycloudflare.com'
                payload = {'nonce': session.ticket.nonce, 'init_data': 'FAKE', 'password': 'TEST-ONLY'}
                if failure == 'stdin':
                    stdin.write.side_effect = RuntimeError('TEST-SECRET')
                if failure == 'close':
                    stdin.close.side_effect = RuntimeError('TEST-SECRET')
                if failure == 'thread':
                    thread.start.side_effect = RuntimeError('TEST-SECRET')
                else:
                    def starts():
                        self.assertEqual(payload, {})
                        self.assertIsNone(process.stdin)
                    thread.start.side_effect = starts
                with patch.object(module, 'APPROVED_DEPLOY_SHA256', 'a' * 64), patch.object(module, 'verify_init_data', return_value=True), patch.object(module.threading, 'Thread', return_value=thread), patch.object(module.subprocess, 'Popen', side_effect=RuntimeError('TEST-SECRET') if failure == 'popen' else None, return_value=process) as popen:
                    status, result = session.submit(payload, session.origin)
                self.assertEqual(payload, {})
                self.assertNotIn('TEST-SECRET', json.dumps(result))
                if failure == 'popen':
                    self.assertEqual(status, 500)
                    self.assertTrue(session.finished.is_set())
                else:
                    self.assertEqual(status, 202)
                    self.assertIsNone(process.stdin)
                    self.assertEqual(popen.call_args.kwargs['bufsize'], 0)
                    if failure == 'thread':
                        self.assertIs(session.rescue_process, process)
                    else:
                        self.assertFalse(hasattr(session, 'rescue_process'))

    def test_monitor_reader_error_still_grants_guarded_rollback_time(self):
        module = load('telegram_sudo')
        process = Mock(stdin=None)
        process.wait.side_effect = [module.subprocess.TimeoutExpired(['FAKE'], 120), 1]
        with patch.object(module.time, 'monotonic', return_value=1800), patch.object(module, 'drain_deploy_stdout', side_effect=OSError('TEST-SECRET')), patch.object(module, 'signal_deploy_process') as signal:
            result = module.monitor_deployment(process, 100)
        self.assertGreaterEqual(process.wait.call_args_list[0].kwargs['timeout'], 120)
        self.assertEqual([call.kwargs['force'] for call in signal.call_args_list], [False])
        self.assertIn('root_monitor_failed', result['cleanup_errors'])
        self.assertNotIn('TEST-SECRET', json.dumps(result))

    def test_deploy_sigterm_keeps_guarded_root_result_and_cleanup(self):
        import signal
        from test_lifecycle import fake_launch
        with fake_launch() as f:
            f['session'].action = ACTION
            module = Mock(deployment_approved=Mock(return_value=True), DeploymentSession=Mock(return_value=f['session']), make_server=Mock(return_value=f['server']))
            f['response'].read.return_value = json.dumps({'ok': True, 'scope': ACTION, 'requires_signed_telegram': True}).encode()
            handlers = {}
            def register(sig, handler):
                handlers[sig] = handler
                return signal.SIG_DFL
            expected = {'ok': False, 'status': 'rolled_back', 'rollback': True, 'checks': {'schema_verified': True}}
            def waiting(session):
                if not session.accepted.is_set():
                    session.accepted.set()
                    session.accepted_at = 100
                    handlers[signal.SIGTERM](signal.SIGTERM, None)
                session.result = expected.copy()
                session.finished.set()
                return session.result
            f['wait'].side_effect = waiting
            with patch.object(f['runner'], 'session_module', return_value=module), patch.object(signal, 'signal', side_effect=register):
                result = f['runner'].launch_request(ACTION)
            self.assertEqual(result['status'], 'rolled_back')
            self.assertEqual(f['wait'].call_count, 2)
            f['server'].server_close.assert_called_once()
            f['tunnel'].terminate.assert_called_once()

    def test_accepted_deploy_reports_running_nonsecret_state(self):
        module = load('telegram_sudo')
        runner = load('telegram_request')
        session = module.DeploymentSession('123:TEST_TOKEN', 1)
        session._accept(100)
        session.response_complete.set()
        session.result = {'ok': False, 'status': 'rolled_back'}
        session.finished.set()
        session.on_running = Mock()
        with patch.object(runner.time, 'monotonic', return_value=401):
            self.assertEqual(runner.wait_for_result(session)['status'], 'rolled_back')
        session.on_running.assert_called_once_with()
        self.assertNotEqual(session.phase, 'expired')

    def test_monitor_late_wakeup_does_not_replace_completed_root_result(self):
        import os
        module = load('telegram_sudo')
        raw = json.dumps({'ok': True, 'status': 'deployed', 'schema_verified': True}).encode()
        readfd, writefd = os.pipe()
        os.write(writefd, raw)
        os.close(writefd)
        process = Mock(stdout=os.fdopen(readfd, 'rb', buffering=0), stdin=None)
        process.poll.return_value = 0
        process.wait.return_value = 0
        with patch.object(module.time, 'monotonic', return_value=2021), patch.object(module, 'signal_deploy_process') as signal:
            result = module.monitor_deployment(process, 100)
        self.assertEqual(result['status'], 'deployed')
        signal.assert_not_called()

    def test_unapproved_action_is_closed_before_launch(self):
        runner = load('telegram_request')
        transport = Mock()
        module = load('telegram_sudo')
        with patch.object(module, 'APPROVED_DEPLOY_SHA256', None), patch.object(runner, 'session_module', return_value=module):
            self.assertEqual(runner.serve(ACTION, transport=transport),
                             {'ok': False, 'status': 'deployment_not_approved'})
        transport.assert_not_called()
        plugin = load('__init__')
        with patch.object(module, 'APPROVED_DEPLOY_SHA256', None), patch.object(importlib.util, 'module_from_spec', return_value=module), patch.object(importlib.util, 'spec_from_file_location', return_value=Mock()), patch.object(plugin.subprocess, 'Popen') as process:
            self.assertEqual(json.loads(plugin.handle_safe_sudo({'action': ACTION})),
                             {'ok': False, 'status': 'deployment_not_approved'})
        process.assert_not_called()


if __name__ == '__main__':
    unittest.main()
