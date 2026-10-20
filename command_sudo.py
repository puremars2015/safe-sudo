"""One immutable shell command per Telegram password approval."""
import html
import json
import unicodedata


def validate_request(value):
    if not isinstance(value, dict) or set(value) != {'command', 'reason'}:
        raise ValueError('invalid_request')
    for key, limit in (('command', 1400), ('reason', 400)):
        text = value[key]
        if not isinstance(text, str) or not text.strip() or len(text) > limit:
            raise ValueError('invalid_request')
        if any(unicodedata.category(char).startswith('C') and char not in '\n\t' for char in text):
            raise ValueError('invalid_request')
    return dict(value)


# The shell never receives the password: only sudo reads its pipe. Output is
# deliberately discarded so arbitrary root output cannot leak secrets to chat.
BOOTSTRAP = r'''
import json, os, subprocess, sys
if os.geteuid() != 0:
    sys.exit(1)
try:
    rc = subprocess.call(['/bin/bash', '--noprofile', '--norc', '-c', sys.argv[1]],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, cwd='/',
                         env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    print(json.dumps({'ok': rc == 0, 'status': 'completed', 'exit_code': rc}), flush=True)
except BaseException:
    sys.exit(1)
'''


def make_session(module, token, user_id, request):
    request = validate_request(request)

    class CommandSession(module.DeploymentSession):
        action = 'command'

        def __init__(self):
            super().__init__(token, user_id)
            self.command = request['command']
            self.operation_html = (
                '<p><strong>本次以 root 執行任意指令。請逐字核對；可修改或刪除系統資料。</strong></p>'
                '<p>用途：</p><pre style="white-space:pre-wrap;overflow-wrap:anywhere">' + html.escape(request['reason']) +
                '</pre><p>完整指令（bash，工作目錄 /）：</p>'
                '<pre style="white-space:pre-wrap;overflow-wrap:anywhere">' + html.escape(self.command) +
                '</pre><p>不回傳 stdout/stderr。無自動執行逾時；不要啟動背景工作或持續 shell。'
                '只授權這次指令，但指令本身可能建立持續權限。受理不代表執行完成。</p>')

        def argv(self):
            return ['/usr/bin/sudo', '-k', '-S', '-p', '', '--', '/usr/bin/python3',
                    '-I', '-S', '-c', BOOTSTRAP, self.command]

        def _monitor(self, process):
            # No timeout/kill fiction: losing sudo is not proof root work stopped.
            try:
                raw = process.stdout.read(4097)
                rc = process.wait()
                result = json.loads(raw)
                if (rc != 0 or not isinstance(result, dict) or
                        set(result) != {'ok', 'status', 'exit_code'} or
                        result['status'] != 'completed' or
                        type(result['exit_code']) is not int or type(result['ok']) is not bool or
                        result['ok'] != (result['exit_code'] == 0)):
                    raise ValueError('invalid_result')
                self.result = result
            except Exception:
                self.result = {'ok': False, 'status': 'execution_unconfirmed'}
            finally:
                process.stdout.close()
                self.phase = 'finished'
                self.finished.set()

    return CommandSession()
