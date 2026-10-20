"""Telegram Mini App launcher. Passwords never pass through Bot API messages."""
import argparse
import ctypes
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shlex
import signal
import subprocess
import sys
import threading
import time
from urllib.request import Request, urlopen

# Explicit opt-in: zero is never a valid private Telegram user ID.
TARGET_USER = int(os.environ.get('SAFE_SUDO_TELEGRAM_USER_ID', '0'))
IMAGE = 'docker.io/cloudflare/cloudflared:2026.9.3'
PLUGIN_DIR = Path(__file__).resolve().parent


def build_button(origin, nonce):
    if not re.fullmatch(r'https://[a-z0-9-]+\.trycloudflare\.com', origin) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', nonce):
        raise ValueError('invalid endpoint')
    return {'inline_keyboard': [[{'text': '安全輸入 sudo 密碼', 'web_app': {'url': origin + '/?request=' + nonce}}]]}


def bot_token():
    value = os.environ.get('TELEGRAM_BOT_TOKEN')
    if not value:
        home = Path(os.environ.get('HERMES_HOME', str(Path.home() / '.hermes')))
        path = home / '.env'
        stat = path.stat()
        if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
            raise RuntimeError('private_credentials_required')
        with path.open() as stream:
            for line in stream:
                key, sep, text = line.partition('=')
                if sep and key.strip() in ('TELEGRAM_BOT_TOKEN', 'export TELEGRAM_BOT_TOKEN'):
                    values = shlex.split(text, comments=True)
                    if len(values) == 1:
                        value = values[0]
                    break
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]+:[A-Za-z0-9_-]+', value):
        raise RuntimeError('bot_credential_unavailable')
    return value


def bot_api(token, method, payload):
    try:
        req = Request('https://api.telegram.org/bot' + token + '/' + method,
                      data=json.dumps(payload, ensure_ascii=False).encode(),
                      headers={'Content-Type': 'application/json'}, method='POST')
        with urlopen(req, timeout=15) as response:
            data = json.loads(response.read(262144))
        if data.get('ok') is not True:
            raise RuntimeError('telegram_api_failed')
        return data['result']
    except Exception:
        raise RuntimeError('telegram_api_failed') from None


def write_state(state):
    path = PLUGIN_DIR / 'telegram-state.json'
    temporary = path.with_suffix('.pending')
    temporary.write_text(json.dumps(state, ensure_ascii=False))
    temporary.chmod(0o600)
    os.replace(temporary, path)


def emit(data):
    try:
        print(json.dumps(data, ensure_ascii=False), flush=True)
    except BrokenPipeError:
        pass


def wait_for_result(session):
    session.accepted.wait(max(0, session.ticket.expires - time.monotonic()))
    with session.ticket.lock:
        if not session.accepted.is_set():
            # Close waiting atomically with accept; deadline rejects new input.
            session.ticket.used = True
            session.phase = 'expired'
            return {'ok': False, 'status': 'expired'}
        response_deadline = session.accepted_at + 30
    if getattr(session, 'action', 'identity') == 'command':
        session.response_complete.wait(max(0, response_deadline - time.monotonic()))
        rescue = getattr(session, 'rescue_process', None)
        if rescue is not None:
            session.rescue_process = None
            session._monitor(rescue)
        session.finished.wait()
        return session.result.copy()
    if getattr(session, 'action', 'identity') == 'ymir_deploy_4b8a3af':
        # HTTP accepted is NOT finished deployment. Keep server/tunnel alive.
        reporting_failed = False
        if not getattr(session, 'running_reported', False):
            session.running_reported = True
            try:
                callback = getattr(session, 'on_running', None)
                if callback is not None:
                    callback()
            except Exception:
                reporting_failed = True
        drained = session.response_complete.wait(max(0, response_deadline - time.monotonic()))
        rescue = getattr(session, 'rescue_process', None)
        if rescue is not None:
            session.rescue_process = None
            session._monitor(rescue)
        session.finished.wait(max(0, session.execution_deadline - time.monotonic()))
        # A stale broker deadline is not proof that the root unit stopped.
        # PID1 bounds execution; wait for the root controller's verified exit.
        while not session.finished.is_set():
            session.finished.wait(1)
        if isinstance(session.result, dict):
            result = session.result.copy()
            if reporting_failed:
                result.setdefault('cleanup_errors', []).append('running_state_write_failed')
            if not drained:
                result.setdefault('cleanup_errors', []).append('response_drain_timeout')
            return result
        return {'ok': False, 'status': 'execution_timeout'}
    drained = session.response_complete.wait(max(0, response_deadline - time.monotonic()))
    if session.finished.is_set():
        result = session.result.copy()
        if not drained:
            result.setdefault('cleanup_errors', []).append('response_drain_timeout')
        return result
    return {'ok': False, 'status': 'execution_timeout'}


def result_text(action, result):
    if action == 'command':
        if result.get('status') == 'completed':
            return ('✅ 指令結束' if result.get('ok') else '⚠️ 指令失敗') + '；exit code：' + str(result['exit_code']) + '。\n不回傳指令輸出。表單已停用；下次操作須重新輸入密碼。背景工作不在此完成證明範圍。'
        return '⚠️ 未確認指令完成（可能未開始或仍在執行），請由管理者檢查，勿直接重試。表單已停用。'
    if action == 'ymir_deploy_4b8a3af':
        if result.get('ok') is True and result.get('status') in ('deployed', 'already_deployed'):
            text = ('✅ Ymir 4b8a3af：root 部署結果顯示 API/RuntimeHost 切換驗證通過。'
                    if result['status'] == 'deployed' else '✅ Ymir 4b8a3af 已是目前版本；root 部署結果驗證通過。')
        elif result.get('status') == 'rolled_back':
            text = '⚠️ Ymir 4b8a3af 部署失敗；root 腳本回報已回復舊版本。'
        elif result.get('status') in ('blocked', 'deployment_not_approved'):
            text = '⚠️ Ymir 4b8a3af 部署被安全 gate 阻擋；未確認新版本部署成功。'
        elif result.get('status') == 'planned':
            text = '⚠️ Ymir 4b8a3af 只有部署計畫；沒有確認部署完成。'
        else:
            text = '⚠️ Ymir 4b8a3af 未取得可驗證的成功部署結果；請由管理者檢查部署／回復狀態。'
        pending = result.get('user_acceptance_pending', [])
        if pending:
            names = []
            if any(item in pending for item in ('entra_login', 'real_entra_login')):
                names.append('真 Entra 登入')
            if any(item in pending for item in ('pi_sse', 'real_pi_sse')):
                names.append('真 Pi SSE')
            if 'existing_data_decryption' in pending:
                names.append('既有資料與加密設定解密')
            text += '\n待人工驗收：' + '、'.join(names) + '；尚未測試，不宣稱通過。'
        else:
            text += '\n此 root 結果不代表真 Entra 登入／Pi SSE 或全部人工驗收完成。'
        return text + '\n此單次表單已停用；密碼不保存，也不授予後續任意 root 權限。'
    return ('✅ Telegram 表單 sudo 身分驗證成功（UID 0）。密碼未保存；本次沒有部署或修改 Ymir。'
            if result.get('ok') else '⚠️ 此安全表單已停用。沒有授予後續 root 權限；請勿輸入或傳送聊天密碼。')


def bounded_cleanup_call(action, timeout=2):
    # A reader may hold the stderr I/O lock if container removal failed.
    # Daemon cleanup workers cannot keep this short-lived process alive.
    done = threading.Event()
    outcome = [('failed', None)]
    def invoke():
        try:
            outcome[0] = ('ok', action())
        except Exception:
            pass  # Never retain/print exception context.
        finally:
            done.set()
    try:
        threading.Thread(target=invoke, daemon=True).start()
    except Exception:
        return ('failed', None)
    if not done.wait(timeout):
        return ('timeout', None)
    return outcome[0]


class RequestCancelled(BaseException):
    pass


def command_module():
    spec = importlib.util.spec_from_file_location('safe_sudo_command', PLUGIN_DIR / 'command_sudo.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def launch_request(action='identity', request=None):
    if TARGET_USER <= 0:
        return {'ok': False, 'status': 'telegram_user_not_configured'}
    if action not in ('identity', 'ymir_deploy_4b8a3af', 'command'):
        return {'ok': False, 'status': 'invalid_action'}
    if action == 'command':
        request = command_module().validate_request(request)
    if action == 'ymir_deploy_4b8a3af' and not session_module().deployment_approved():
        return {'ok': False, 'status': 'deployment_not_approved'}
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
        return {'ok': False, 'status': 'privacy_setup_failed'}
    lock = (PLUGIN_DIR / 'telegram-request.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        return {'ok': False, 'status': 'request_already_active'}
    server = None
    worker_started = False
    tunnel = None
    container = 'hermes-safe-sudo-' + secrets.token_hex(6)
    state = {'request_id': secrets.token_hex(8), 'chat_id': TARGET_USER, 'status': 'starting', 'pid': os.getpid()}
    token = None
    message_id = None
    stage = 'credentials'
    session = None
    result = {'ok': False, 'status': 'request_failed', 'stage': stage}
    old_sigterm = None
    signal_installed = False
    def cancel(signum, frame):
        # Only the main thread installs this; repeated TERM must not interrupt cleanup.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise RequestCancelled()
    try:
        if threading.current_thread() is threading.main_thread():
            old_sigterm = signal.signal(signal.SIGTERM, cancel)
            signal_installed = True
        token = bot_token()
        bot = bot_api(token, 'getMe', {})
        chat = bot_api(token, 'getChat', {'chat_id': TARGET_USER})
        if bot.get('is_bot') is not True or chat.get('id') != TARGET_USER or chat.get('type') != 'private':
            raise RuntimeError('private_chat_required')
        module = session_module()
        if action == 'command':
            session = command_module().make_session(module, token, TARGET_USER, request)
        else:
            session = module.Session(token, TARGET_USER) if action == 'identity' else module.DeploymentSession(token, TARGET_USER)
        server = module.make_server(session, port=0)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        worker_started = True
        state['port'] = server.server_port
        stage = 'tunnel'
        env = {key: value for key, value in os.environ.items() if key in (
            'HOME', 'PATH', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'TMPDIR',
            'LANG', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME',
        )}
        tunnel = subprocess.Popen([
            '/usr/bin/podman', 'run', '--rm', '--name', container, '--network', 'host',
            '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', IMAGE,
            'tunnel', '--no-autoupdate', '--protocol', 'http2', '--url',
            f'http://127.0.0.1:{server.server_port}',
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, text=True, env=env, cwd=str(Path.home()))
        address = []
        found = threading.Event()
        connected = threading.Event()
        def read_tunnel():
            try:
                for line in tunnel.stderr:
                    match = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com', line)
                    if match and not address:
                        address.append(match.group())
                        found.set()
                    if 'Registered tunnel connection' in line:
                        connected.set()
            except Exception:
                pass  # Never print raw tunnel errors or exception context.
        reader = threading.Thread(target=read_tunnel, daemon=True)
        reader.start()
        if not found.wait(45) or not connected.wait(15) or tunnel.poll() is not None:
            raise RuntimeError('tunnel_failed')
        session.origin = address[0]
        state['public_origin'] = session.origin
        stage = 'https_probe'
        ready = False
        # Fresh Quick Tunnel DNS may become visible after tunnel registration.
        # Readiness remains HTTPS+certificate+exact-schema verified; no bypass.
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                req = Request(session.origin + '/health', headers={'User-Agent': 'curl/8.0'})
                with urlopen(req, timeout=5) as response:
                    data = json.loads(response.read(4096))
                if data == {'ok': True, 'scope': action, 'requires_signed_telegram': True}:
                    ready = True
                    break
            except Exception:
                pass
            if tunnel.poll() is not None:
                break
            time.sleep(1)
        if not ready:
            raise RuntimeError('https_probe_failed')
        session.ticket.expires = time.monotonic() + 300
        markup = build_button(session.origin, session.ticket.nonce)
        stage = 'telegram_button'
        text = ('Telegram 安全 sudo 輸入\n\n按下方按鈕，在 Telegram 內的遮罩表單輸入，不需 VM 桌面。'
                '\n本次只執行 id -u，確認 root 身分；不會修改或重新部署 Ymir。'
                '\n一次性表單，5 分鐘失效。請勿將密碼傳到聊天。'
                '\n\n表單使用 HTTPS，經 Cloudflare TLS 代理，非端對端加密。')
        if action == 'ymir_deploy_4b8a3af':
            text = ('Ymir 4b8a3af 安全部署授權\n\n本次真的部署 Ymir 4b8a3af，不是 id -u。'
                    '\n備份資料與金鑰（SQL、keyring／workspaces）；補齊已審查的 migration 歷史紀錄（不變更資料表，不執行任意 migration）；切換 API/RuntimeHost 與 origin。'
                    '\n可能短暫中斷；失敗將回復舊版本，保留 DB／env／其他服務。'
                    '\n在 Telegram 遮罩表單輸入；請勿將密碼傳到聊天。'
                    '\n一次性表單，5 分鐘失效；受理不代表部署完成，請回 Telegram 等待結果。'
                    '\nHTTPS 經 Cloudflare TLS 代理，非端對端加密。')
        if action == 'command':
            text = ('單次任意 root 指令授權\n\n用途：\n' + request['reason'] +
                    '\n\n完整指令（bash，工作目錄 /）：\n' + request['command'] +
                    '\n\n請逐字核對。指令可修改系統或建立持續權限。'
                    '\n在遮罩表單輸入密碼，不要傳到聊天。5 分鐘內有效，只嘗試一次。'
                    '\n不回傳 stdout/stderr；無自動執行逾時。勿啟動背景工作／持續 shell。'
                    '\nHTTPS 經 Cloudflare TLS 代理，非端對端加密。')
        sent = bot_api(token, 'sendMessage', {'chat_id': TARGET_USER, 'text': text,
                        'reply_markup': markup, 'protect_content': True,
                        'link_preview_options': {'is_disabled': True}})
        message_id = sent['message_id']
        # Verify the exact remote message exists, and read the edited Message record back.
        verified = bot_api(token, 'editMessageText', {'chat_id': TARGET_USER, 'message_id': message_id,
                            'text': text + '\n\n✅ HTTPS 入口已驗證，可使用下方按鈕。',
                            'reply_markup': markup, 'link_preview_options': {'is_disabled': True}})
        if (verified.get('message_id') != message_id or verified.get('chat', {}).get('id') != TARGET_USER or verified.get('reply_markup') != markup
                or (action in ('command', 'ymir_deploy_4b8a3af') and verified.get('text') != text + '\n\n✅ HTTPS 入口已驗證，可使用下方按鈕。')):
            raise RuntimeError('button_verification_failed')
        state.update({'message_id': message_id, 'status': 'waiting', 'expires_at': time.time() + max(0, session.ticket.expires - time.monotonic())})
        write_state(state)
        emit({'ok': True, 'status': 'waiting', 'request_id': state['request_id'], 'message_id': message_id, 'chat_id': TARGET_USER, 'public_origin': session.origin})
        stage = 'input'
        if action == 'ymir_deploy_4b8a3af':
            def report_running():
                state.update({'status': 'running', 'action': action,
                              'execution_deadline': time.time() + max(0, session.execution_deadline - time.monotonic())})
                state.pop('expires_at', None)  # Input expiry never expires accepted execution.
                write_state(state)
            session.on_running = report_running
        result = wait_for_result(session)
        return result
    except (Exception, RequestCancelled) as error:
        result = {'ok': False, 'status': 'cancelled' if isinstance(error, RequestCancelled) else 'request_failed', 'stage': stage}
        if session is not None:
            with session.ticket.lock:
                session.ticket.used = True
            if session.accepted.is_set():
                result = wait_for_result(session)
        return result
    finally:
        errors = result.setdefault('cleanup_errors', [])
        def attempt(code, action, bounded=False):
            try:
                if bounded:
                    outcome, value = bounded_cleanup_call(action)
                    if outcome != 'ok':
                        errors.append(code.replace('_failed', '_timeout') if outcome == 'timeout' else code)
                    return value
                return action()
            except Exception:
                errors.append(code)
                return None
        if signal_installed:
            attempt('signal_ignore_failed', lambda: signal.signal(signal.SIGTERM, signal.SIG_IGN))
        if session is not None:
            with session.ticket.lock:
                session.ticket.used = True
        if token and message_id:
            def retire_button():
                status_text = result_text(action, result)
                record = bot_api(token, 'editMessageText', {
                    'chat_id': TARGET_USER, 'message_id': message_id, 'text': status_text,
                    'reply_markup': {'inline_keyboard': []}})
                if (not isinstance(record, dict) or record.get('message_id') != message_id
                        or record.get('chat', {}).get('id') != TARGET_USER
                        or record.get('reply_markup', {'inline_keyboard': []}) != {'inline_keyboard': []}
                         or (action in ('command', 'ymir_deploy_4b8a3af') and record.get('text') != status_text)):
                    raise RuntimeError('button_retirement_unverified')
            attempt('button_retirement_failed', retire_button)
        if server:
            if worker_started:
                attempt('server_shutdown_failed', server.shutdown, bounded=True)
            attempt('server_close_failed', server.server_close)
        if tunnel:
            attempt('tunnel_terminate_failed', tunnel.terminate)
            if attempt('tunnel_wait_failed', lambda: tunnel.wait(timeout=2)) is None:
                attempt('tunnel_kill_failed', tunnel.kill)
                attempt('tunnel_reap_failed', lambda: tunnel.wait(timeout=2))
            attempt('container_remove_failed', lambda: subprocess.run(
                ['/usr/bin/podman', 'rm', '-f', container],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5))
            check = attempt('container_verify_failed', lambda: subprocess.run(
                ['/usr/bin/podman', 'container', 'exists', container],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3))
            if check is not None and check.returncode != 1:
                errors.append('container_removal_unverified')
            if tunnel.stderr:
                attempt('stderr_close_failed', tunnel.stderr.close, bounded=True)
        state.update({'status': result['status'], 'result': result})
        attempt('state_write_failed', lambda: write_state(state))
        attempt('lock_close_failed', lock.close)
        if signal_installed:
            attempt('signal_restore_failed', lambda: signal.signal(signal.SIGTERM, old_sigterm))
        if not errors:
            result.pop('cleanup_errors', None)


def session_module():
    spec = importlib.util.spec_from_file_location('telegram_sudo_session', PLUGIN_DIR / 'telegram_sudo.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def serve(action='identity', transport=None, request=None):
    if action == 'ymir_deploy_4b8a3af' and not session_module().deployment_approved():
        return {'ok': False, 'status': 'deployment_not_approved'}
    if action not in ('identity', 'ymir_deploy_4b8a3af', 'command'):
        return {'ok': False, 'status': 'invalid_action'}
    try:
        if action == 'command':
            request = command_module().validate_request(request)
            return transport(action=action, request=request) if transport else launch_request(action=action, request=request)
        if transport is not None:
            return transport() if action == 'identity' else transport(action=action)
        return launch_request() if action == 'identity' else launch_request(action=action)
    except Exception:
        return {'ok': False, 'status': 'request_failed'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Telegram Mini App safe sudo input; no password parameters')
    parser.add_argument('action', choices=['identity', 'ymir_deploy_4b8a3af', 'command'])
    args = parser.parse_args()
    try:
        request = json.loads(sys.stdin.buffer.read(16385)) if args.action == 'command' else None
        result = serve(args.action, request=request)
    except Exception:
        result = {'ok': False, 'status': 'invalid_arguments'}
    emit(result)
    raise SystemExit(0 if result.get('ok') else 1)
