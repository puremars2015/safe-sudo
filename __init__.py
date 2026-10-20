"""Telegram safe sudo plugin: no password reaches the Hermes process."""
import json
from pathlib import Path
import selectors
import subprocess
import sys


def start_telegram_request(action='identity', request=None):
    child = subprocess.Popen(
        [sys.executable, str(Path(__file__).parent / 'telegram_request.py'), action],
        stdin=subprocess.PIPE if request is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        if request is not None:
            child.stdin.write(json.dumps(request).encode('utf-8'))
            child.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=270):
                raise TimeoutError
            line = child.stdout.readline(4096)
        data = json.loads(line)
        allowed = {'waiting', 'request_failed', 'request_already_active', 'privacy_setup_failed'}
        if not isinstance(data, dict) or data.get('status') not in allowed:
            raise ValueError('unexpected response')
        return {key: data[key] for key in ('ok', 'status', 'request_id', 'message_id', 'chat_id', 'stage') if key in data}
    except Exception:
        if action == 'command':
            # The child may have sent a form or accepted a root operation.
            return {'ok': False, 'status': 'request_start_unconfirmed'}
        try:
            child.terminate()
        except Exception:
            pass
        try:
            # Runner can drain accepted HTTP work (30s), retire button (15s),
            # and remove/reap its tunnel before launcher escalates to SIGKILL.
            child.wait(timeout=2000 if action == 'ymir_deploy_4b8a3af' else 70)
        except Exception:
            try:
                child.kill()
            except Exception:
                pass
            try:
                child.wait(timeout=5)
            except Exception:
                pass
        return {'ok': False, 'status': 'request_start_failed'}
    finally:
        try:
            child.stdout.close()
        except Exception:
            pass  # Never expose raw child/pipe exception context.


def handle_safe_sudo(params, **kwargs):
    if not isinstance(params, dict) or set(params) != {'action'} or params.get('action') not in ('identity', 'ymir_deploy_4b8a3af'):
        return json.dumps({'ok': False, 'status': 'invalid_arguments'})
    if params['action'] == 'ymir_deploy_4b8a3af':
        import importlib.util
        spec = importlib.util.spec_from_file_location('safe_sudo_session', Path(__file__).parent / 'telegram_sudo.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not module.deployment_approved():
            return json.dumps({'ok': False, 'status': 'deployment_not_approved'})
    return json.dumps(start_telegram_request() if params['action'] == 'identity' else start_telegram_request(params['action']))


def register(ctx):
    ctx.register_tool(
        name='sudo_command', toolset='safe_sudo',
        schema={
            'name': 'sudo_command',
            'description': '向指定 Telegram 管理者要求單次任意 root 指令授權。完整 command/reason 顯示於聊天與 HTTPS 遮罩密碼表單；每次重新輸入密碼，密碼絕不可放入工具或聊天。bash 在 / 執行，無互動 stdin，不回傳 stdout/stderr，只回報 exit code。waiting/accepted 不代表完成；結果由 Telegram 通知。不要啟動背景工作或持續 shell；不要自動重試未確認操作。須事先說明破壞性影響。',
            'parameters': {'type': 'object', 'properties': {
                'command': {'type': 'string', 'minLength': 1, 'maxLength': 1400},
                'reason': {'type': 'string', 'minLength': 1, 'maxLength': 400}},
                'required': ['command', 'reason'], 'additionalProperties': False},
        }, handler=handle_sudo_command,
    )
    ctx.register_tool(
        name='safe_sudo', toolset='safe_sudo',
        schema={
            'name': 'safe_sudo',
            'description': '在指定 Telegram 私人對話傳送安全密碼表單按鈕，使用者在 Telegram Mini App 的遮罩欄位輸入 sudo 密碼，不需 VM 桌面。密碼不經聊天或模型。identity 固定 id -u；ymir_deploy_4b8a3af 需已審查 SHA256 pin，備份資料與金鑰、補齊已審查的 migration 歷史紀錄（不變更資料表）、切換 API/RuntimeHost，失敗回復。waiting／accepted 不代表部署成功；不得將密碼放入參數或聊天。',
            'parameters': {
                'type': 'object',
                'properties': {'action': {'type': 'string', 'enum': ['identity', 'ymir_deploy_4b8a3af']}},
                'required': ['action'], 'additionalProperties': False,
            },
        },
        handler=handle_safe_sudo,
    )


def handle_sudo_command(params, **kwargs):
    import importlib.util
    spec = importlib.util.spec_from_file_location('safe_sudo_command', Path(__file__).parent / 'command_sudo.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        request = module.validate_request(params)
    except ValueError:
        return json.dumps({'ok': False, 'status': 'invalid_arguments'})
    return json.dumps(start_telegram_request('command', request=request))
