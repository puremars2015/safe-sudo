"""Local desktop password broker; no password tool argument or persistent secret."""
import argparse
import json
import os
import resource
import subprocess

ACTIONS = {
    'identity': ['/usr/bin/id', '-u'],
}


def prompt_password():
    if not os.environ.get('DISPLAY'):
        return None
    result = subprocess.run([
        '/usr/bin/zenity', '--password', '--timeout=120',
        '--title=Hermes 安全 sudo 驗證（僅身分檢查）',
        '--text=本次只以 root 執行 /usr/bin/id -u。\n密碼只傳给本機 sudo，不儲存、不送到聊天。\n取消將不執行。',
    ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=130)
    if result.returncode != 0:
        return None
    password = result.stdout.removesuffix(b'\n')
    if not password or len(password) > 4096 or b'\n' in password or b'\x00' in password:
        return None
    return password


def execute_sudo(argv, password):
    return subprocess.run(
        ['/usr/bin/sudo', '-k', '-S', '-p', '', '--'] + argv,
        input=password + b'\n', stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=20, cwd='/',
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'},
    )


def run_action(action):
    if not isinstance(action, str) or action not in ACTIONS:
        return {'ok': False, 'status': 'invalid_action'}
    # Disable dumpability for this short-lived broker before collecting a secret.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    import ctypes
    if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
        return {'ok': False, 'status': 'privacy_setup_failed'}
    try:
        password = prompt_password()
        if password is None:
            return {'ok': False, 'status': 'cancelled_or_no_desktop'}
        try:
            result = execute_sudo(ACTIONS[action], password)
        finally:
            del password
        if result.returncode != 0:
            return {'ok': False, 'status': 'sudo_failed', 'exit_code': result.returncode}
        # Return only validated UID, never raw sudo output or error text.
        if result.stdout.strip() != b'0':
            return {'ok': False, 'status': 'unexpected_output'}
        return {'ok': True, 'status': 'verified', 'uid': 0}
    except subprocess.TimeoutExpired:
        return {'ok': False, 'status': 'timeout'}
    except Exception:
        return {'ok': False, 'status': 'broker_error'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='本機桌面安全 sudo 身分驗證；不接受密碼參數')
    parser.add_argument('action', choices=sorted(ACTIONS))
    args = parser.parse_args()
    result = run_action(args.action)
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result['ok'] else 1)
