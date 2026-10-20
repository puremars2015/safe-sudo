"""Telegram Mini App password transport; never accepts chat passwords."""
import hashlib
import hmac
import json
import time
from urllib.parse import parse_qsl
import secrets
import threading
import subprocess
import re

DEPLOY_ACTION = 'ymir_deploy_4b8a3af'
APPROVED_DEPLOY_SHA256 = None  # Legacy deployment action is disabled in this distribution.
DEPLOY_SOURCE = '/nonexistent/safe-sudo-disabled-deployment.py'
DEPLOY_TIMEOUT = 1800
DEPLOY_ROLLBACK_GRACE = 120
IDENTITY_OPERATION_HTML = '<p>操作：只以 root 執行 <code>id -u</code>，確認 sudo 可用。<strong>不會重新部署或修改 Ymir。</strong></p>'
DEPLOY_OPERATION_HTML = ('<p><strong>本次真的部署 Ymir 4b8a3af，不是 id -u。</strong>'
                         '備份資料與金鑰（SQL、keyring、workspaces）；'
                         '補齊已審查的 migration 歷史紀錄（不變更資料表，不執行任意 migration）；'
                         '切換 API/RuntimeHost 與 origin，可能短暫中斷；失敗回復舊版本。'
                         '保留既有資料、env 與其他服務。受理不代表部署完成，請回 Telegram 等結果。</p>')


def deployment_approved():
    return isinstance(APPROVED_DEPLOY_SHA256, str) and re.fullmatch(r'[0-9a-f]{64}', APPROVED_DEPLOY_SHA256) is not None


# Only stdlib under Python -I -S. No imports from source directory.
# Values below are substituted from constants, NEVER HTTP/tool parameters.
DEPLOY_BOOTSTRAP = r'''
import hashlib, json, os, re, signal, stat, subprocess, sys, time
TERMINATING = False

def request_stop(signum, frame):
    global TERMINATING
    TERMINATING = True

signal.signal(signal.SIGTERM, request_stop)

# PID1, not the unprivileged broker, owns timeout and whole-cgroup killing.
def unit_stopped(unit):
    try:
        query = subprocess.run(['/usr/bin/systemctl', '--system', '--no-ask-password',
                                'show', '--property=ActiveState', '--property=MainPID', unit],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=2, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
        if query.returncode != 0 or len(query.stdout) > 1024:
            return False
        props = dict(line.split('=', 1) for line in query.stdout.decode('ascii').splitlines())
        return props == {'ActiveState': props.get('ActiveState'), 'MainPID': '0'} and props['ActiveState'] in ('inactive', 'failed')
    except Exception:
        return False

def stop_unit(unit):
    try:
        return subprocess.run(['/usr/bin/systemctl', '--system', '--no-ask-password',
                               '--no-block', 'stop', unit], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=2).returncode == 0
    except Exception:
        return False

def read_output(process):
    try:
        return os.read(process.stdout.fileno(), 65536)
    except BlockingIOError:
        return b''

def supervise(stored):
    unit = 'hermes-ymir-4b8a3af-' + PIN[:16] + '-' + str(os.getpid()) + '.service'
    if not re.fullmatch(r'hermes-ymir-4b8a3af-[0-9a-f]{16}-[1-9][0-9]*\.service', unit):
        raise ValueError()
    argv = ['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--service-type=exec',
            '--unit=' + unit, '--property=RuntimeMaxSec=1800s', '--property=TimeoutStopSec=120s',
            '--property=KillMode=control-group', '--property=KillSignal=SIGTERM',
            '--property=FinalKillSignal=SIGKILL', '--property=SendSIGKILL=yes',
            '--uid=root', '--gid=root', '--working-directory=/', '--property=WorkingDirectory=/',
            '--setenv=HERMES_DEPLOY_UNIT=' + unit,
            '/usr/bin/python3', '-I', '-S', stored]
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, cwd='/', start_new_session=True,
                               env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'}, bufsize=0)
    deadline = time.monotonic() + 1800
    raw = bytearray()
    reader_failed = False
    # Any control/query failure keeps the root controller alive. No unproven
    # stopped/success response, nor killing the launcher to simulate job exit.
    try:
        os.set_blocking(process.stdout.fileno(), False)
    except Exception:
        reader_failed = True
    while True:
        try:
            raw.extend(read_output(process)[:max(0, 8193 - len(raw))])
        except Exception:
            reader_failed = True
        if TERMINATING or reader_failed or time.monotonic() >= deadline:
            # Stop can race the initial submission. Retry the same exact unit;
            # repeated stop joins PID1's stop job and never grants a new grace.
            stop_unit(unit)
        try:
            launcher_done = process.poll() is not None
        except Exception:
            reader_failed = True
            launcher_done = False
        if launcher_done and unit_stopped(unit):
            # A failed/not-yet-loaded unit must not be mistaken for stopped
            # while systemd-run is still submitting its start transaction.
            try:
                while True:
                    tail = read_output(process)
                    if not tail:
                        break
                    raw.extend(tail[:max(0, 8193 - len(raw))])
            except Exception:
                reader_failed = True
            rc = process.wait()
            process.stdout.close()
            if reader_failed:
                raise ValueError()
            return bytes(raw), rc
        time.sleep(0.1)
SOURCE = __SOURCE__
PIN = __PIN__
LIMIT = 262144

def read_verified(fd, stored=False):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size > LIMIT:
        raise ValueError()
    if stored and (st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1):
        raise ValueError()
    chunks = []
    remaining = LIMIT + 1
    while remaining:
        chunk = os.read(fd, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b''.join(chunks)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != PIN:
        raise ValueError()
    return data

def main():
    if os.geteuid() != 0:
        raise ValueError()
    fd = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        data = read_verified(fd)
    finally:
        os.close(fd)
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in ('usr', 'local', 'libexec', 'ymir-deploy'):
            created = False
            try:
                os.mkdir(component, 0o755, dir_fd=parent)
                created = True
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            st = os.fstat(child)
            if st.st_uid != 0 or st.st_mode & 0o022 or not stat.S_ISDIR(st.st_mode):
                os.close(child)
                raise ValueError()
            if created:
                os.fchmod(child, 0o755)  # Broker umask is 077; root parent must be 0755.
            os.close(parent)
            parent = child
        name = PIN + '.py'
        try:
            target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        except FileExistsError:
            target = None
        if target is not None:
            try:
                os.fchmod(target, 0o600)
                view = memoryview(data)
                while view:
                    count = os.write(target, view)
                    if count <= 0:
                        raise ValueError()
                    view = view[count:]
                os.fsync(target)
            finally:
                os.close(target)
            os.fsync(parent)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            read_verified(fd, stored=True)
        finally:
            os.close(fd)
    finally:
        os.close(parent)
    # The immutable root-owned parent prevents path replacement by the caller.
    raw, rc = supervise('/usr/local/libexec/ymir-deploy/' + PIN + '.py')
    if len(raw) > 8192:
        raise ValueError()
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError()
    sys.stdout.write(raw.decode('utf-8'))
    sys.stdout.flush()
    sys.exit(rc)

try:
    main()
except SystemExit as error:
    # Reviewed deployer may emit its final JSON then exit nonzero for failure.
    # Never stringify a user-controlled SystemExit message.
    sys.exit(error.code if type(error.code) is int else (0 if error.code is None else 1))
except BaseException:
    print(json.dumps({'ok': False, 'status': 'blocked', 'version': '4b8a3af', 'schema_verified': False, 'code': 'bootstrap_rejected'}))
    sys.exit(1)
'''


def deploy_argv():
    if not deployment_approved():
        raise ValueError('deployment_not_approved')
    source = DEPLOY_BOOTSTRAP.replace('__SOURCE__', repr(DEPLOY_SOURCE)).replace('__PIN__', repr(APPROVED_DEPLOY_SHA256))
    return ['/usr/bin/sudo', '-k', '-S', '-p', '', '--', '/usr/bin/python3', '-I', '-S', '-c', source]


DEPLOY_RESULT_KEYS = frozenset({'ok', 'status', 'version', 'schema_verified', 'code',
                               'stage', 'new_image_id', 'backup_dir', 'rollback',
                               'checks', 'user_acceptance_pending'})
DEPLOY_RESULT_CODES = frozenset({'bootstrap_rejected', 'gate_blocked', 'deployment_failed', 'rollback_complete', 'rollback_failed'})
DEPLOY_STAGES = frozenset({'preflight', 'backup', 'stage', 'switch', 'verify', 'verified', 'rollback', 'complete', 'blocked', 'failed'})
DEPLOY_CHECKS = frozenset({'schema_verified', 'schema', 'schema_gate', 'bundle_hash', 'backup',
                         'native_sql_backup', 'keyring_backup', 'workspaces_backup', 'no_jobs',
                         'baseline', 'api', 'api_health', 'runtime_host', 'runtime_host_health',
                         'origin', 'rollback', 'boot_install', 'dependencies_preserved', 'exact_image', 'runtime_release'})
DEPLOY_PENDING = frozenset({'entra_login', 'pi_sse', 'real_entra_login', 'real_pi_sse', 'existing_data_decryption'})


def sanitize_deploy_result(raw, returncode):
    invalid = {'ok': False, 'status': 'invalid_root_result'}
    try:
        if not isinstance(raw, bytes) or len(raw) > 8192:
            return invalid
        def unique(pairs):
            data = dict(pairs)
            if len(data) != len(pairs):
                raise ValueError()
            return data
        data = json.loads(raw, object_pairs_hook=unique)
        if (not isinstance(data, dict) or not set(data) <= DEPLOY_RESULT_KEYS
                or not {'ok', 'status'} <= set(data) or type(data['ok']) is not bool
                or ('schema_verified' in data and type(data['schema_verified']) is not bool)
                or ('version' in data and data['version'] != '4b8a3af')
                or data['status'] not in {'planned', 'deployed', 'already_deployed', 'blocked', 'failed', 'rolled_back'}
                or ('code' in data and data['code'] not in DEPLOY_RESULT_CODES)
                or ('stage' in data and data['stage'] not in DEPLOY_STAGES)
                or ('rollback' in data and type(data['rollback']) is not bool)):
            return invalid
        if 'new_image_id' in data and (not isinstance(data['new_image_id'], str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', data['new_image_id'])):
            return invalid
        if 'backup_dir' in data and (not isinstance(data['backup_dir'], str) or not re.fullmatch(r'/var/backups/ymir/[A-Za-z0-9_-]{1,96}', data['backup_dir'])):
            return invalid
        checks = data.get('checks', {})
        if not isinstance(checks, dict) or not set(checks) <= DEPLOY_CHECKS or any(type(value) is not bool for value in checks.values()):
            return invalid
        pending = data.get('user_acceptance_pending', [])
        if not isinstance(pending, list) or len(pending) > 4 or any(not isinstance(item, str) or item not in DEPLOY_PENDING for item in pending):
            return invalid
        success = data['status'] in {'deployed', 'already_deployed'}
        schema = data.get('schema_verified', checks.get('schema_verified', checks.get('schema_gate', checks.get('schema'))))
        if data['ok'] != success or (success and (returncode != 0 or schema is not True or not all(checks.values()))):
            return invalid
        if data['status'] == 'planned' and returncode != 0:
            return invalid
        return data
    except (ValueError, TypeError, UnicodeError):
        return invalid


class Ticket:
    def __init__(self, ttl=300, now=None):
        self.nonce = secrets.token_urlsafe(32)
        self.expires = (time.monotonic() if now is None else now) + ttl
        self.used = False
        self.lock = threading.Lock()

    def consume(self, nonce, now=None, on_accept=None):
        if not isinstance(nonce, str):
            return False
        with self.lock:
            current = time.monotonic() if now is None else now
            if self.used or current >= self.expires or not hmac.compare_digest(self.nonce, nonce):
                return False
            self.used = True
            if on_accept is not None:
                on_accept(current)
            return True


def verify_init_data(raw, bot_token, user_id, now=None):
    if not isinstance(raw, str) or len(raw) > 8192:
        return False
    try:
        pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=True)
        data = dict(pairs)
        if len(data) != len(pairs):
            return False
        signature = data.pop('hash')
        check = '\n'.join(f'{key}={data[key]}' for key in sorted(data))
        secret = hmac.new(b'WebAppData', bot_token.encode(), hashlib.sha256).digest()
        expected = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return False
        age = (time.time() if now is None else now) - int(data['auth_date'])
        if not 0 <= age <= 300:
            return False
        user = json.loads(data['user'])
        return type(user.get('id')) is int and user['id'] == user_id
    except (KeyError, ValueError, TypeError, AttributeError):
        return False


def execute_identity(password):
    import subprocess
    completed = subprocess.run(
        ['/usr/bin/sudo', '-k', '-S', '-p', '', '--', '/usr/bin/id', '-u'],
        input=password + b'\n', stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=20, cwd='/', env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'},
    )
    return completed.returncode == 0 and completed.stdout.strip() == b'0'


class Session:
    def __init__(self, bot_token, user_id, executor=None):
        self.bot_token = bot_token
        self.user_id = user_id
        self.executor = executor or execute_identity
        self.ticket = Ticket(ttl=300)
        self.origin = None
        self.finished = threading.Event()
        self.accepted = threading.Event()
        self.response_complete = threading.Event()
        self.accepted_at = None
        self.phase = 'waiting'
        self.result = None

    def _accept(self, current):
        # Called under the ticket lock: consume and running are one transition.
        self.accepted_at = current
        self.phase = 'running'
        self.accepted.set()

    def submit(self, payload, origin):
        denied = (403, {'ok': False, 'status': 'unauthorized'})
        if not self.origin or origin != self.origin:
            return denied
        if not isinstance(payload, dict) or set(payload) != {'nonce', 'init_data', 'password'}:
            return (400, {'ok': False, 'status': 'invalid_request'})
        if not verify_init_data(payload['init_data'], self.bot_token, self.user_id):
            return denied
        password = payload['password']
        if not isinstance(password, str) or not 1 <= len(password) <= 512 or any(c in password for c in '\n\r\x00'):
            return (400, {'ok': False, 'status': 'invalid_request'})
        if not self.ticket.consume(payload['nonce'], on_accept=self._accept):
            return (410, {'ok': False, 'status': 'expired_or_used'})
        try:
            ok = self.executor(password.encode('utf-8')) is True
            self.result = {'ok': ok, 'status': 'verified' if ok else 'sudo_failed'}
            if ok:
                self.result['uid'] = 0
        except subprocess.TimeoutExpired:
            self.result = {'ok': False, 'status': 'execution_timeout'}
        except Exception:
            self.result = {'ok': False, 'status': 'sudo_failed'}
        finally:
            # No claim of perfect memory erasure; avoid retaining password on session.
            payload.clear()
            del password
            self.phase = 'finished'
            self.finished.set()
        return (200, self.result)


def drain_deploy_stdout(process, deadline):
    """Drain a pipe without storing >8193 bytes or printing any raw output."""
    import os
    import selectors
    retained = bytearray()
    eof = False
    fd = process.stdout.fileno()
    os.set_blocking(fd, False)
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            for _, _events in selector.select(timeout=min(0.2, max(0, deadline - time.monotonic()))):
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    eof = True
                    selector.unregister(fd)
                    break
                retained.extend(chunk[:max(0, 8193 - len(retained))])
            if eof:
                if process.poll() is not None:
                    return bytes(retained), True
                time.sleep(0.02)
        # A delayed monitor wakeup must not replace a completed root result
        # with a timeout. Drain already-available bytes without extending time.
        if process.poll() is not None:
            for _ in range(2):
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                retained.extend(chunk[:max(0, 8193 - len(retained))])
            return bytes(retained), True
        return bytes(retained), False


def signal_deploy_process(process, force=False):
    import os
    import signal
    # Notification only: an unprivileged killpg cannot stop root descendants.
    # PID1 controls the root unit; never kill sudo to pretend the root job died.
    if force:
        raise ValueError('root_force_kill_forbidden')
    os.killpg(process.pid, signal.SIGTERM)


def monitor_deployment(process, accepted_at, on_grace=None):
    errors = []
    raw = b''
    result = {'ok': False, 'status': 'execution_timeout'}
    deadline = accepted_at + DEPLOY_TIMEOUT
    def signal(force=False):
        try:
            signal_deploy_process(process, force=force)
        except Exception:
            errors.append('root_kill_failed' if force else 'root_terminate_failed')
    try:
        try:
            raw, done = drain_deploy_stdout(process, deadline)
        except Exception:
            done = False
            errors.append('root_monitor_failed')
        if not done:
            errors.append('deployment_deadline_exceeded')
            signal()
            grace_deadline = time.monotonic() + DEPLOY_ROLLBACK_GRACE
            if on_grace is not None:
                on_grace(grace_deadline)
            try:
                tail, done = drain_deploy_stdout(process, grace_deadline)
                raw = (raw + tail)[:8193]
            except Exception:
                done = False
                errors.append('root_monitor_failed')
                # Reader failure is not permission to kill an accepted root job
                # mid-switch. Preserve the remaining bounded rollback window.
                try:
                    process.wait(timeout=max(0, grace_deadline - time.monotonic()))
                    done = True
                    result = {'ok': False, 'status': 'root_monitor_failed'}
                except Exception:
                    pass
        while not done:
            # Only the privileged controller may certify whole-unit termination.
            # Keep draining/waiting, including after delayed wakeups or pipe errors.
            try:
                tail, done = drain_deploy_stdout(process, time.monotonic() + 1)
                raw = (raw + tail)[:8193]
            except Exception:
                if 'root_monitor_failed' not in errors:
                    errors.append('root_monitor_failed')
                try:
                    process.wait(timeout=1)
                    done = True
                    raw = b''
                except Exception:
                    time.sleep(0.1)
        try:
            rc = process.wait(timeout=2)
        except Exception:
            errors.append('root_reap_failed')
            rc = None
        if done and rc is not None:
            result = sanitize_deploy_result(raw, rc)
    except Exception:
        # No exception, traceback, password or raw stdout reaches the caller.
        result = {'ok': False, 'status': 'root_monitor_failed'}
    finally:
        raw = b''
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    errors.append('root_pipe_close_failed')
    if errors:
        result['cleanup_errors'] = list(dict.fromkeys(errors))
    return result


class DeploymentSession(Session):
    action = DEPLOY_ACTION

    def __init__(self, bot_token, user_id):
        super().__init__(bot_token, user_id)
        self.executor = None  # Deployment NEVER calls identity.
        self.execution_deadline = None

    def _accept(self, current):
        super()._accept(current)
        self.execution_deadline = current + DEPLOY_TIMEOUT + DEPLOY_ROLLBACK_GRACE + 5

    def argv(self):
        return deploy_argv()

    def submit(self, payload, origin):
        process = None
        password = None
        try:
            if self.action == DEPLOY_ACTION and not deployment_approved():
                return (503, {'ok': False, 'status': 'deployment_not_approved'})
            if not self.origin or origin != self.origin:
                return (403, {'ok': False, 'status': 'unauthorized'})
            if not isinstance(payload, dict) or set(payload) != {'nonce', 'init_data', 'password'}:
                return (400, {'ok': False, 'status': 'invalid_request'})
            if not verify_init_data(payload['init_data'], self.bot_token, self.user_id):
                return (403, {'ok': False, 'status': 'unauthorized'})
            password = payload['password']
            if not isinstance(password, str) or not 1 <= len(password) <= 512 or any(c in password for c in '\n\r\x00'):
                return (400, {'ok': False, 'status': 'invalid_request'})
            if not self.ticket.consume(payload['nonce'], on_accept=self._accept):
                return (410, {'ok': False, 'status': 'expired_or_used'})
            process = subprocess.Popen(self.argv(), stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       cwd='/', env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'},
                                       start_new_session=True, bufsize=0)
            try:
                process.stdin.write(password.encode('utf-8') + b'\n')
                process.stdin.flush()
            finally:
                try:
                    process.stdin.close()
                finally:
                    process.stdin = None
            payload.clear()
            password = None
            # Only process/session references go to monitor, never secret values.
            threading.Thread(target=self._monitor, args=(process,), daemon=False).start()
            return (202, {'ok': True, 'status': 'accepted', 'action': self.action})
        except Exception:
            if isinstance(payload, dict):
                payload.clear()
            password = None
            if process is not None:
                # Still guard a process whose stdin/start failed. No HTTP wait for it.
                try:
                    threading.Thread(target=self._monitor, args=(process,), daemon=False).start()
                    return (202, {'ok': True, 'status': 'accepted', 'action': self.action})
                except Exception:
                    # No monitor thread: keep the process in session for runner rescue.
                    self.rescue_process = process
                    return (202, {'ok': True, 'status': 'accepted', 'action': self.action})
            self.result = {'ok': False, 'status': 'deployment_start_failed' if self.action == DEPLOY_ACTION else 'execution_start_failed'}
            self.phase = 'finished'
            self.finished.set()
            return (500, self.result)
        finally:
            if isinstance(payload, dict):
                payload.clear()
            password = None

    def _monitor(self, process):
        def extend_grace(deadline):
            self.execution_deadline = max(self.execution_deadline, deadline + 5)
        self.result = monitor_deployment(process, self.accepted_at, on_grace=extend_grace)
        if self.result.get('status') not in {'planned', 'deployed', 'already_deployed', 'blocked', 'failed', 'rolled_back'}:
            # Missing/corrupt root-controller JSON can mean sudo died while
            # the privileged controller/unit survives. Do not authorize runner
            # cleanup or infer stopped merely from the unprivileged child's rc.
            self.phase = 'supervision_unconfirmed'
            return
        self.phase = 'finished'
        self.finished.set()


def make_server(session, port=0):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pathlib import Path
    from urllib.parse import urlsplit

    class Handler(BaseHTTPRequestHandler):
        server_version = 'SafeSudo'
        sys_version = ''

        def setup(self):
            super().setup()
            self.connection.settimeout(8)

        def log_message(self, *args):
            pass  # Never log URLs, headers, initData or POST bodies.

        def response(self, status, body, content_type='application/json'):
            if isinstance(body, dict):
                body = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store, max-age=0')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self' https://telegram.org; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors https://web.telegram.org https://webk.telegram.org https://webz.telegram.org")
            self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            self.close_connection = True

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == '/health':
                return self.response(200, {'ok': True, 'scope': getattr(session, 'action', 'identity'), 'requires_signed_telegram': True})
            if not session.origin or self.headers.get('Host') != urlsplit(session.origin).netloc:
                return self.response(403, {'ok': False, 'status': 'unauthorized'})
            if time.monotonic() >= session.ticket.expires or session.ticket.used:
                return self.response(410, {'ok': False, 'status': 'expired_or_used'})
            if path not in ('/', '/app.js'):
                return self.response(404, {'ok': False})
            filename, content_type = ('index.html', 'text/html; charset=utf-8') if path == '/' else ('app.js', 'application/javascript; charset=utf-8')
            content = (Path(__file__).parent / 'web' / filename).read_bytes()
            if filename == 'index.html' and getattr(session, 'action', 'identity') == 'command':
                content = content.replace(b'<!--operation-->', session.operation_html.encode('utf-8'))
            elif filename == 'index.html' and getattr(session, 'action', 'identity') == DEPLOY_ACTION:
                content = content.replace(b'<!--operation-->', DEPLOY_OPERATION_HTML.encode('utf-8'))
            else:
                content = content.replace(b'<!--operation-->', IDENTITY_OPERATION_HTML.encode('utf-8'))
            return self.response(200, content, content_type)

        def do_POST(self):
            if urlsplit(self.path).path != '/submit':
                return self.response(404, {'ok': False})
            if not session.origin or self.headers.get('Host') != urlsplit(session.origin).netloc or self.headers.get('Origin') != session.origin:
                return self.response(403, {'ok': False, 'status': 'unauthorized'})
            if self.headers.get('Content-Type') != 'application/json' or self.headers.get('Transfer-Encoding'):
                return self.response(415, {'ok': False})
            try:
                size = int(self.headers.get('Content-Length', '-1'))
                if not 0 < size <= 16384:
                    return self.response(413, {'ok': False})
                def unique_pairs(pairs):
                    result = dict(pairs)
                    if len(result) != len(pairs):
                        raise ValueError('duplicate key')
                    return result
                payload = json.loads(self.rfile.read(size), object_pairs_hook=unique_pairs)
                status, result = session.submit(payload, self.headers.get('Origin'))
                try:
                    return self.response(status, result)
                finally:
                    if (status == 200 and result is session.result) or (status == 202 and session.accepted.is_set()):
                        session.response_complete.set()
            except (ValueError, UnicodeError, TimeoutError):
                return self.response(400, {'ok': False, 'status': 'invalid_request'})
            except Exception:
                return self.response(500, {'ok': False, 'status': 'request_failed'})

    class BoundedServer(ThreadingHTTPServer):
        daemon_threads = True
        block_on_close = False
        slots = threading.BoundedSemaphore(8)

        def process_request(self, request, client_address):
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except Exception:
                self.slots.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self.slots.release()

        def handle_error(self, request, client_address):
            pass  # Do not print exception context from secret-processing requests.

    return BoundedServer(('127.0.0.1', port), Handler)
