"""Offline lifecycle regressions: fake credentials, no listeners or containers."""
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from threading import Thread as RealThread

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if name == 'telegram_request':
        module.TARGET_USER = 123456789  # Isolated test recipient; no real Telegram calls.
    return module


class LifecycleTests(unittest.TestCase):
    def test_waiting_ticket_and_ui_share_five_minute_limit(self):
        module = load('telegram_sudo')
        with patch.object(module.time, 'monotonic', return_value=100):
            session = module.Session('123:TEST_TOKEN', 1, executor=lambda _: True)
        self.assertEqual(session.ticket.expires, 400)
        for filename in ('web/index.html', 'README.md', 'telegram_request.py'):
            text = (ROOT / filename).read_text()
            self.assertNotIn('10 分鐘', text)
            self.assertNotIn('+ 600', text)

    def test_predeadline_accept_waits_for_postdeadline_response(self):
        import threading
        module = load('telegram_sudo')
        runner = load('telegram_request')
        clock = [100.0]
        entered, release = threading.Event(), threading.Event()
        observed = []
        def executor(_):
            observed.append(getattr(session, 'phase', None))
            entered.set()
            release.wait(2)
            return True
        with patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(module, 'verify_init_data', return_value=True):
            session = module.Session('123:TEST_TOKEN', 1, executor=executor)
            session.origin = 'https://example.trycloudflare.com'
            clock[0] = 399
            payload = {'nonce': session.ticket.nonce, 'init_data': 'FAKE', 'password': 'TEST-ONLY'}
            worker = threading.Thread(target=session.submit, args=(payload, session.origin))
            worker.start()
            self.assertTrue(entered.wait(1))
            try:
                self.assertEqual(observed, ['running'])
                clock[0] = 401
                results = []
                waiter = threading.Thread(target=lambda: results.append(runner.wait_for_result(session)))
                waiter.start()
                release.set()
                self.assertTrue(session.finished.wait(1))
                self.assertTrue(waiter.is_alive(), 'must drain HTTP response, not only executor')
                session.response_complete.set()
                waiter.join(1)
                self.assertEqual(results, [{'ok': True, 'status': 'verified', 'uid': 0}])
            finally:
                release.set()
                worker.join(2)

    def test_blocked_shutdown_or_stderr_close_does_not_skip_lock_close(self):
        import threading
        for step, code in (('shutdown', 'server_shutdown_timeout'), ('stderr', 'stderr_close_timeout')):
            with self.subTest(step=step), fake_launch() as f:
                release = threading.Event()
                action = f['server'].shutdown if step == 'shutdown' else f['tunnel'].stderr.close
                action.side_effect = lambda: release.wait(2)
                bounded = f['runner'].bounded_cleanup_call
                try:
                    with patch.object(f['runner'], 'bounded_cleanup_call', side_effect=lambda fn: bounded(fn, timeout=0.01)):
                        result = f['runner'].launch_request()
                    self.assertEqual(result['status'], 'verified')
                    self.assertIn(code, result['cleanup_errors'])
                    f['lock'].close.assert_called_once()
                finally:
                    release.set()

    def test_blocked_cleanup_call_has_bounded_nonsecret_result(self):
        import threading
        runner = load('telegram_request')
        self.assertTrue(hasattr(runner, 'bounded_cleanup_call'), 'cleanup close/shutdown can block forever')
        release = threading.Event()
        try:
            self.assertEqual(runner.bounded_cleanup_call(lambda: release.wait(2), timeout=0.01), ('timeout', None))
            self.assertEqual(runner.bounded_cleanup_call(lambda: 7, timeout=1), ('ok', 7))
            def fail():
                raise RuntimeError('TEST-SECRET')
            self.assertEqual(runner.bounded_cleanup_call(fail, timeout=1), ('failed', None))
        finally:
            release.set()

    def test_failed_worker_start_closes_server_without_shutdown_deadlock(self):
        with fake_launch() as f, patch.object(f['runner'].threading, 'Thread', return_value=Mock(start=Mock(side_effect=RuntimeError('TEST-SECRET')))):
            result = f['runner'].launch_request()
            self.assertEqual(result['status'], 'request_failed')
            f['server'].shutdown.assert_not_called()
            f['server'].server_close.assert_called_once()
            f['lock'].close.assert_called_once()

    def test_http_response_completion_follows_flush(self):
        from test_telegram_sudo import offline_handler
        module = load('telegram_sudo')
        session = module.Session('123:TEST_TOKEN', 1, executor=lambda _: True)
        session.origin = 'https://example.trycloudflare.com'
        handler = offline_handler(module, session, {'nonce': session.ticket.nonce, 'init_data': 'FAKE', 'password': 'TEST-ONLY'})
        def flush():
            self.assertTrue(session.finished.is_set())
            self.assertFalse(session.response_complete.is_set())
        handler.wfile = Mock(flush=Mock(side_effect=flush))
        with patch.object(module, 'verify_init_data', return_value=True):
            handler.do_POST()
        handler.send_response.assert_called_once_with(200)
        self.assertTrue(session.response_complete.is_set())

    def test_reset_does_not_extend_signed_auth_lifetime(self):
        from test_telegram_sudo import TelegramSudoTests
        module = load('telegram_sudo')
        signed = TelegramSudoTests().signed(auth_date=1000)
        session = module.Session('123:TEST_TOKEN', 123456789, executor=Mock())
        session.origin = 'https://example.trycloudflare.com'
        session.ticket.expires = 99999  # A reset never relaxes Telegram auth_date.
        with patch.object(module.time, 'time', return_value=1301):
            status, result = session.submit({'nonce': session.ticket.nonce, 'init_data': signed, 'password': 'TEST-ONLY'}, session.origin)
        self.assertEqual(status, 403)
        self.assertFalse(session.ticket.used)
        session.executor.assert_not_called()

    def test_waiting_deadline_rejects_new_submissions(self):
        module = load('telegram_sudo')
        runner = load('telegram_request')
        with patch.object(module.time, 'monotonic', return_value=0):
            session = module.Session('123:TEST_TOKEN', 1, executor=Mock())
        session.origin = 'https://example.trycloudflare.com'
        with patch.object(module.time, 'monotonic', return_value=300), patch.object(module, 'verify_init_data', return_value=True):
            self.assertEqual(runner.wait_for_result(session)['status'], 'expired')
            self.assertEqual(session.submit({'nonce': session.ticket.nonce, 'init_data': 'FAKE', 'password': 'TEST-ONLY'}, session.origin)[0], 410)
        session.executor.assert_not_called()

    def test_unfinished_executor_has_thirty_second_runner_bound(self):
        module = load('telegram_sudo')
        runner = load('telegram_request')
        session = module.Session('123:TEST_TOKEN', 1, executor=lambda _: True)
        session.accepted.set()
        session.accepted_at = 100
        with patch.object(runner.time, 'monotonic', return_value=131):
            self.assertEqual(runner.wait_for_result(session)['status'], 'execution_timeout')

    def test_container_presence_is_reported_without_losing_result(self):
        with fake_launch() as f:
            f['run'].return_value.returncode = 0
            result = f['runner'].launch_request()
            self.assertEqual(result['status'], 'verified')
            self.assertIn('container_removal_unverified', result['cleanup_errors'])

    def test_tunnel_reader_exception_is_not_printed_or_propagated(self):
        with fake_launch() as f:
            def lines():
                yield 'https://example.trycloudflare.com'
                yield 'Registered tunnel connection'
                raise RuntimeError('TEST-SECRET')
            f['tunnel'].stderr.__iter__.return_value = lines()
            result = f['runner'].launch_request()
            self.assertEqual(result['status'], 'verified')
            self.assertNotIn('TEST-SECRET', json.dumps(result))

    def test_response_deadline_keeps_result_and_reports_fixed_drain_code(self):
        module = load('telegram_sudo')
        runner = load('telegram_request')
        session = module.Session('123:TEST_TOKEN', 1, executor=lambda _: True)
        session.accepted_at = 100
        session.accepted.set()
        session.result = {'ok': True, 'status': 'verified', 'uid': 0}
        session.finished.set()
        with patch.object(runner.time, 'monotonic', return_value=131):
            result = runner.wait_for_result(session)
        self.assertEqual(result['status'], 'verified')
        self.assertIn('response_drain_timeout', result.get('cleanup_errors', []))

    def test_reset_ticket_state_keeps_actual_deadline(self):
        with fake_launch() as f, patch.object(f['runner'].time, 'monotonic', side_effect=[100, 100, 100, 130]), patch.object(f['runner'].time, 'time', return_value=1000):
            result = f['runner'].launch_request()
            self.assertEqual(result['status'], 'verified')
            self.assertEqual(f['session'].ticket.expires, 400)
            self.assertEqual(f['state'].call_args_list[0].args[0]['expires_at'], 1270)

    def test_accept_checks_deadline_inside_transition_lock(self):
        module = load('telegram_sudo')
        clock = [299]
        ticket = module.Ticket(ttl=300, now=0)
        class ContendedLock:
            def __enter__(self):
                clock[0] = 301
            def __exit__(self, *args):
                pass
        ticket.lock = ContendedLock()
        with patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]):
            self.assertFalse(ticket.consume(ticket.nonce))
        self.assertFalse(ticket.used)

    def test_launcher_cancellation_errors_do_not_escape(self):
        for step in ('terminate', 'wait', 'kill', 'close'):
            with self.subTest(step=step):
                plugin = load('__init__')
                child = Mock()
                error = RuntimeError('TEST-SECRET')
                if step == 'close':
                    child.stdout.close.side_effect = error
                else:
                    getattr(child, step).side_effect = error
                if step == 'kill':
                    child.wait.side_effect = [plugin.subprocess.TimeoutExpired(['FAKE'], 70), 0]
                selector = Mock()
                selector.__enter__ = Mock(return_value=selector)
                selector.__exit__ = Mock(return_value=False)
                selector.select.return_value = []
                with patch.object(plugin.subprocess, 'Popen', return_value=child), patch.object(plugin.selectors, 'DefaultSelector', return_value=selector):
                    try:
                        result = plugin.start_telegram_request()
                    except Exception:
                        self.fail('launcher exposed cancellation exception')
                self.assertEqual(result['status'], 'request_start_failed')
                self.assertNotIn('TEST-SECRET', json.dumps(result))
                child.stdout.close.assert_called_once()
                self.assertGreaterEqual(child.wait.call_count, 1)

    def test_launcher_timeout_allows_cleanup_then_reaps_after_kill(self):
        plugin = load('__init__')
        child = Mock()
        child.wait.side_effect = [plugin.subprocess.TimeoutExpired(['FAKE'], 70), 0]
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.select.return_value = []
        with patch.object(plugin.subprocess, 'Popen', return_value=child), patch.object(plugin.selectors, 'DefaultSelector', return_value=selector):
            result = plugin.start_telegram_request()
        self.assertEqual(result['status'], 'request_start_failed')
        child.terminate.assert_called_once()
        self.assertGreaterEqual(child.wait.call_args_list[0].kwargs['timeout'], 65)
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_count, 2)
        child.stdout.close.assert_called_once()

    def test_executor_timeout_is_fixed_code_and_bounded(self):
        import subprocess
        module = load('telegram_sudo')
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired(['FAKE'], 20, output=b'TEST-SECRET', stderr=b'TEST-SECRET')) as run, patch.object(module, 'verify_init_data', return_value=True):
            session = module.Session('123:TEST_TOKEN', 1)
            session.origin = 'https://example.trycloudflare.com'
            payload = {'nonce': session.ticket.nonce, 'init_data': 'FAKE', 'password': 'TEST-ONLY'}
            status, result = session.submit(payload, session.origin)
            self.assertEqual(result['status'], 'execution_timeout')
            self.assertEqual(status, 200)
            self.assertEqual(payload, {})
            self.assertNotIn('TEST-SECRET', json.dumps(result))
            self.assertEqual(run.call_args.kwargs['timeout'], 20)
            self.assertEqual(run.call_args.kwargs['stderr'], subprocess.DEVNULL)
            self.assertFalse(session.response_complete.is_set())

    def test_final_button_record_must_match_and_keep_real_result(self):
        for mismatch in ('message', 'chat', 'keyboard', 'state'):
            with self.subTest(mismatch=mismatch), fake_launch() as f:
                expected = {'ok': True, 'status': 'verified', 'uid': 0}
                def complete(session):
                    session.result = expected.copy()
                    session.finished.set()
                    session.accepted.set()
                    session.accepted_at = 0
                    session.response_complete.set()
                    return session.result
                f['wait'].side_effect = complete
                original = f['bot'].side_effect
                def api(token, method, payload):
                    data = original(token, method, payload)
                    if payload.get('reply_markup') == {'inline_keyboard': []}:
                        if mismatch == 'message':
                            data['message_id'] = 99
                        elif mismatch == 'chat':
                            data['chat']['id'] = 99
                        elif mismatch == 'keyboard':
                            data['reply_markup'] = {'inline_keyboard': [[{'text': 'old'}]]}
                    return data
                f['bot'].side_effect = api
                if mismatch == 'state':
                    f['state'].side_effect = [None, OSError('TEST-SECRET'), OSError('TEST-SECRET')]
                result = f['runner'].launch_request()
                self.assertEqual(result['status'], 'verified')
                self.assertTrue(result['ok'])
                self.assertIn('cleanup_errors', result)
                self.assertNotIn('TEST-SECRET', json.dumps(result))

    def test_sigterm_unwinds_through_final_cleanup(self):
        import signal
        handlers = {}
        def register(sig, handler):
            handlers[sig] = handler
            return signal.SIG_DFL
        with fake_launch() as f, patch.object(signal, 'signal', side_effect=register):
            def cancel(session):
                handler = handlers.get(signal.SIGTERM)
                if callable(handler):
                    handler(signal.SIGTERM, None)
                return {'ok': False, 'status': 'missing_cancellation_handler'}
            f['wait'].side_effect = cancel
            result = f['runner'].launch_request()
            self.assertEqual(result['status'], 'cancelled')
            f['server'].server_close.assert_called_once()
            f['tunnel'].terminate.assert_called_once()
            f['lock'].close.assert_called_once()
            self.assertTrue(any(p.get('reply_markup') == {'inline_keyboard': []} for _, p in f['calls']))
            self.assertEqual(handlers[signal.SIGTERM], signal.SIG_DFL)

    def test_cleanup_failures_are_isolated_and_preserve_sudo_result(self):
        failures = ('shutdown', 'server_close', 'remove', 'terminate', 'wait', 'kill', 'stderr_close', 'lock_close')
        for failure in failures:
            with self.subTest(failure=failure), fake_launch() as f:
                error = RuntimeError('TEST-SECRET')
                if failure in ('shutdown', 'server_close'):
                    getattr(f['server'], failure).side_effect = error
                elif failure == 'remove':
                    f['run'].side_effect = f['runner'].subprocess.TimeoutExpired(['FAKE'], 20)
                elif failure in ('terminate', 'kill'):
                    getattr(f['tunnel'], failure).side_effect = error
                    f['tunnel'].wait.side_effect = f['runner'].subprocess.TimeoutExpired(['FAKE'], 2)
                elif failure == 'wait':
                    f['tunnel'].wait.side_effect = error
                elif failure == 'stderr_close':
                    f['tunnel'].stderr.close.side_effect = error
                else:
                    f['lock'].close.side_effect = error
                try:
                    result = f['runner'].launch_request()
                except Exception:
                    self.fail('cleanup failure escaped')
                self.assertEqual(result['status'], 'verified')
                self.assertTrue(result['ok'])
                self.assertIn('cleanup_errors', result)
                self.assertNotIn('TEST-SECRET', json.dumps(result))
                f['server'].shutdown.assert_called_once()
                f['server'].server_close.assert_called_once()
                f['tunnel'].terminate.assert_called_once()
                self.assertGreaterEqual(f['tunnel'].wait.call_count, 1)
                f['tunnel'].stderr.close.assert_called_once()
                f['lock'].close.assert_called_once()
                self.assertTrue(any(call.args[0][1:3] == ['container', 'exists'] for call in f['run'].call_args_list))

    def test_https_probe_does_not_start_before_tunnel_registration(self):
        import threading
        with fake_launch() as f, patch.object(threading.Event, 'wait', autospec=True, side_effect=lambda event, timeout=None: event.is_set()):
            f['tunnel'].stderr.__iter__ = Mock(return_value=iter(['https://example.trycloudflare.com']))
            result = f['runner'].launch_request()
            self.assertFalse(result['ok'])
            self.assertEqual(result['stage'], 'tunnel')
            f['runner'].urlopen.assert_not_called()

    def test_state_failure_still_disables_button_and_cleans_resources(self):
        with fake_launch() as f:
            f['state'].side_effect = OSError('TEST-SECRET')
            try:
                result = f['runner'].launch_request()
            except Exception:
                self.fail('state failure escaped and skipped button retirement')
            retired = [p for method, p in f['calls'] if p.get('reply_markup') == {'inline_keyboard': []}]
            self.assertEqual(len(retired), 1)
            self.assertEqual(result['status'], 'request_failed')
            self.assertIn('state_write_failed', result['cleanup_errors'])
            f['server'].shutdown.assert_called_once()
            f['server'].server_close.assert_called_once()
            f['lock'].close.assert_called_once()


from contextlib import contextmanager, ExitStack
import json


@contextmanager
def fake_launch():
    runner = load('telegram_request')
    module = load('telegram_sudo')
    session = module.Session('123:TEST_TOKEN', runner.TARGET_USER, executor=lambda _: True)
    server = Mock(server_port=43210)
    module.Session = Mock(return_value=session)
    module.make_server = Mock(return_value=server)
    lock = Mock()
    tunnel = Mock()
    tunnel.poll.return_value = None
    tunnel.stderr = Mock()
    tunnel.stderr.__iter__ = Mock(return_value=iter(['https://example.trycloudflare.com', 'Registered tunnel connection']))
    calls = []
    def api(token, method, payload):
        calls.append((method, payload))
        if method == 'getMe':
            return {'is_bot': True}
        if method == 'getChat':
            return {'id': runner.TARGET_USER, 'type': 'private'}
        return {'message_id': 7, 'chat': {'id': runner.TARGET_USER}, 'reply_markup': payload.get('reply_markup'), 'text': payload.get('text')}
    def thread(**kwargs):
        if getattr(kwargs['target'], '__name__', None) == 'invoke':
            return RealThread(**kwargs)
        obj = Mock()
        if getattr(kwargs['target'], '__name__', None) == 'read_tunnel':
            obj.start.side_effect = kwargs['target']
        return obj
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = json.dumps({'ok': True, 'scope': 'identity', 'requires_signed_telegram': True}).encode()
    with ExitStack() as stack:
        def p(obj, attr, **kw):
            return stack.enter_context(patch.object(obj, attr, **kw))
        p(runner.os, 'umask')
        p(runner.resource, 'setrlimit')
        p(runner.ctypes, 'CDLL', return_value=Mock(prctl=Mock(return_value=0)))
        p(runner.Path, 'open', return_value=lock)
        p(runner.fcntl, 'flock')
        p(runner, 'bot_token', return_value='123:TEST_TOKEN')
        bot = p(runner, 'bot_api', side_effect=api)
        p(runner.importlib.util, 'module_from_spec', return_value=module)
        p(runner.importlib.util, 'spec_from_file_location', return_value=Mock(loader=Mock()))
        p(runner.threading, 'Thread', side_effect=thread)
        p(runner.subprocess, 'Popen', return_value=tunnel)
        run = p(runner.subprocess, 'run', return_value=Mock(returncode=1))
        p(runner, 'urlopen', return_value=response)
        state = p(runner, 'write_state')
        emit = p(runner, 'emit')
        wait = p(runner, 'wait_for_result', return_value={'ok': True, 'status': 'verified', 'uid': 0})
        yield dict(runner=runner, session=session, server=server, lock=lock, tunnel=tunnel,
                   calls=calls, bot=bot, run=run, state=state, emit=emit, wait=wait, response=response)


if __name__ == '__main__':
    unittest.main()
