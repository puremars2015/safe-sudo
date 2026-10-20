import importlib.util
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / 'telegram_sudo.py'


def offline_handler(module, session, payload):
    """Run real HTTP handler logic with in-memory I/O, never bind a socket."""
    import io, json
    from http.server import ThreadingHTTPServer
    from unittest.mock import Mock, patch
    with patch.object(ThreadingHTTPServer, '__init__', return_value=None) as init:
        module.make_server(session, port=0)
    address, handler_type = init.call_args.args
    assert address == ('127.0.0.1', 0)
    handler = handler_type.__new__(handler_type)
    body = json.dumps(payload).encode()
    handler.path = '/submit'
    handler.headers = {'Host': 'example.trycloudflare.com', 'Origin': session.origin,
                       'Content-Type': 'application/json', 'Content-Length': str(len(body))}
    handler.rfile = io.BytesIO(body)
    handler.wfile = io.BytesIO()
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    return handler

class TelegramSudoTests(unittest.TestCase):
    def test_rejects_unsigned_telegram_data(self):
        self.assertTrue(MODULE.exists(), 'Telegram 安全輸入尚未實作')
        spec = importlib.util.spec_from_file_location('telegram_sudo', MODULE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertFalse(module.verify_init_data('user=%7B%22id%22%3A123456789%7D', '123:TEST_TOKEN', 123456789, now=1000))

    def load_module(self):
        spec = importlib.util.spec_from_file_location('telegram_sudo', MODULE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def signed(self, token='123:TEST_TOKEN', user_id=123456789, auth_date=1000, **extras):
        import hashlib, hmac, json
        from urllib.parse import urlencode
        data = {'auth_date': str(auth_date), 'user': json.dumps({'id': user_id}, separators=(',', ':')), **extras}
        check = '\n'.join(f'{key}={data[key]}' for key in sorted(data))
        secret = hmac.new(b'WebAppData', token.encode(), hashlib.sha256).digest()
        data['hash'] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        return urlencode(data)

    def test_accepts_valid_signed_user(self):
        module = self.load_module()
        self.assertTrue(module.verify_init_data(self.signed(), '123:TEST_TOKEN', 123456789, now=1001))

    def test_ticket_accepts_only_once(self):
        module = self.load_module()
        self.assertTrue(hasattr(module, 'Ticket'), '缺少一次性授權票券')
        ticket = module.Ticket(ttl=300, now=1000)
        self.assertTrue(ticket.consume(ticket.nonce, now=1001))
        self.assertFalse(ticket.consume(ticket.nonce, now=1002))

    def test_session_requires_auth_before_running_sudo(self):
        module = self.load_module()
        self.assertTrue(hasattr(module, 'Session'), '缺少 Telegram 密碼處理工作階段')
        called = []
        session = module.Session('123:TEST_TOKEN', 123456789, executor=lambda pw: called.append(pw) or True)
        session.origin = 'https://example.trycloudflare.com'
        status, data = session.submit({'nonce': session.ticket.nonce, 'init_data': 'unsigned', 'password': 'TEST-ONLY'}, session.origin)
        self.assertEqual(status, 403)
        self.assertEqual(called, [])
        self.assertFalse(session.ticket.used)

    def test_http_rejects_unsigned_password_post(self):
        module = self.load_module()
        called = []
        session = module.Session('123:TEST_TOKEN', 123456789, executor=lambda pw: called.append(pw) or True)
        session.origin = 'https://example.trycloudflare.com'
        handler = offline_handler(module, session, {'nonce': session.ticket.nonce, 'init_data': 'unsigned', 'password': 'TEST-ONLY'})
        handler.do_POST()
        handler.send_response.assert_called_once_with(403)
        self.assertEqual(called, [])
        self.assertFalse(session.response_complete.is_set())

    def test_telegram_runner_rejects_unknown_actions_without_network(self):
        runner_path = MODULE.parent / 'telegram_request.py'
        self.assertTrue(runner_path.exists(), '缺少 Telegram 按鈕發送入口')
        spec = importlib.util.spec_from_file_location('telegram_request', runner_path)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        result = runner.serve('shell')
        self.assertEqual(result['status'], 'invalid_action')

    def test_button_uses_https_web_app_not_chat_password_reply(self):
        runner_path = MODULE.parent / 'telegram_request.py'
        spec = importlib.util.spec_from_file_location('telegram_request', runner_path)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        self.assertTrue(hasattr(runner, 'build_button'), '缺少 Telegram Mini App 按鈕')
        button = runner.build_button('https://example.trycloudflare.com', 'a' * 43)
        self.assertEqual(button['inline_keyboard'][0][0]['web_app']['url'], 'https://example.trycloudflare.com/?request=' + 'a' * 43)
        self.assertNotIn('callback_data', button['inline_keyboard'][0][0])

    def test_identity_dispatches_fixed_telegram_operation(self):
        runner_path = MODULE.parent / 'telegram_request.py'
        spec = importlib.util.spec_from_file_location('telegram_request', runner_path)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        import inspect
        self.assertIn('transport', inspect.signature(runner.serve).parameters, 'Telegram request transport 尚未實作')
        called = []
        result = runner.serve('identity', transport=lambda: called.append('identity') or {'ok': True, 'status': 'waiting'})
        self.assertEqual(result['status'], 'waiting')
        self.assertEqual(called, ['identity'])

    def test_rejects_wrong_user_and_stale_or_future_auth(self):
        module = self.load_module()
        for raw in (self.signed(user_id=1), self.signed(auth_date=1), self.signed(auth_date=2000)):
            self.assertFalse(module.verify_init_data(raw, '123:TEST_TOKEN', 123456789, now=1001))

    def test_rejects_wrong_signature_and_duplicate_fields(self):
        module = self.load_module()
        raw = self.signed()
        self.assertFalse(module.verify_init_data(raw, '456:OTHER_TOKEN', 123456789, now=1001))
        self.assertFalse(module.verify_init_data(raw + '&auth_date=1000', '123:TEST_TOKEN', 123456789, now=1001))

    def test_expired_or_incorrect_ticket_does_not_consume(self):
        module = self.load_module()
        ticket = module.Ticket(ttl=10, now=1000)
        self.assertFalse(ticket.consume('wrong', now=1001))
        self.assertFalse(ticket.used)
        self.assertFalse(ticket.consume(ticket.nonce, now=1010))

    def test_concurrent_ticket_allows_only_one_consumer(self):
        module = self.load_module()
        from concurrent.futures import ThreadPoolExecutor
        ticket = module.Ticket(ttl=300)
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: ticket.consume(ticket.nonce), range(32)))
        self.assertEqual(results.count(True), 1)

    def test_valid_session_executes_once_and_retains_no_password(self):
        module = self.load_module()
        import time, json
        called = []
        session = module.Session('123:TEST_TOKEN', 123456789, executor=lambda pw: called.append(pw) or True)
        session.origin = 'https://example.trycloudflare.com'
        payload = {'nonce': session.ticket.nonce, 'init_data': self.signed(auth_date=int(time.time())), 'password': 'TEST-ONLY'}
        replay = payload.copy()
        status, result = session.submit(payload, session.origin)
        self.assertEqual((status, result['status'], result['uid']), (200, 'verified', 0))
        self.assertEqual(payload, {})
        self.assertNotIn('TEST-ONLY', json.dumps(session.result))
        self.assertEqual(called, [b'TEST-ONLY'])
        self.assertEqual(session.submit(replay, session.origin)[0], 410)
        self.assertEqual(len(called), 1)

    def test_wrong_origin_never_executes(self):
        module = self.load_module()
        import time
        called = []
        session = module.Session('123:TEST_TOKEN', 123456789, executor=lambda pw: called.append(pw) or True)
        session.origin = 'https://example.trycloudflare.com'
        payload = {'nonce': session.ticket.nonce, 'init_data': self.signed(auth_date=int(time.time())), 'password': 'TEST-ONLY'}
        self.assertEqual(session.submit(payload, 'https://attacker.example')[0], 403)
        self.assertEqual(called, [])

    def test_newline_password_rejected_before_sudo(self):
        module = self.load_module()
        import time
        called = []
        session = module.Session('123:TEST_TOKEN', 123456789, executor=lambda pw: called.append(pw) or True)
        session.origin = 'https://example.trycloudflare.com'
        payload = {'nonce': session.ticket.nonce, 'init_data': self.signed(auth_date=int(time.time())), 'password': 'TEST\nSECOND'}
        self.assertEqual(session.submit(payload, session.origin)[0], 400)
        self.assertEqual(called, [])

    def test_sudo_exception_never_leaks_password(self):
        module = self.load_module()
        import time, json
        def fail(password):
            raise RuntimeError('TEST-ONLY-password')
        session = module.Session('123:TEST_TOKEN', 123456789, executor=fail)
        session.origin = 'https://example.trycloudflare.com'
        payload = {'nonce': session.ticket.nonce, 'init_data': self.signed(auth_date=int(time.time())), 'password': 'TEST-ONLY-password'}
        status, result = session.submit(payload, session.origin)
        self.assertEqual(result['status'], 'sudo_failed')
        self.assertNotIn('TEST-ONLY-password', json.dumps(result))
        self.assertEqual(payload, {})

if __name__ == '__main__':
    unittest.main()
