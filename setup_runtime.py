"""Select the fixed Docker or Podman runtime used by safe-sudo."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

RUNTIMES = {
    'docker': '/usr/bin/docker',
    'podman': '/usr/bin/podman',
}


def hermes_home():
    return Path(os.environ.get('HERMES_HOME', str(Path.home() / '.hermes')))


def config_path():
    return hermes_home() / 'safe-sudo.json'


def verify_runtime(runtime):
    binary = RUNTIMES.get(runtime)
    if not binary or not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        raise ValueError('runtime_unavailable')
    try:
        completed = subprocess.run(
            [binary, '--version'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10, check=False,
        )
    except Exception:
        raise ValueError('runtime_unavailable') from None
    if completed.returncode != 0:
        raise ValueError('runtime_unavailable')


def write_runtime(runtime):
    if runtime not in RUNTIMES:
        raise ValueError('invalid_runtime')
    path = config_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps({'container_runtime': runtime}, ensure_ascii=False) + '\n'
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent,
                                     prefix='.safe-sudo-', delete=False) as stream:
        stream.write(payload)
        temporary = Path(stream.name)
    try:
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def choose_interactively():
    print('選擇 safe-sudo 的容器 runtime：')
    print('  1) docker')
    print('  2) podman')
    answer = input('請輸入 1 或 2：').strip()
    return {'1': 'docker', '2': 'podman'}.get(answer)


def main():
    parser = argparse.ArgumentParser(description='設定 safe-sudo 的 Docker 或 Podman runtime')
    parser.add_argument('--runtime', choices=sorted(RUNTIMES),
                        help='非互動指定 docker 或 podman')
    args = parser.parse_args()
    runtime = args.runtime or choose_interactively()
    if runtime not in RUNTIMES:
        parser.error('必須選擇 docker 或 podman')
    try:
        verify_runtime(runtime)
        path = write_runtime(runtime)
    except ValueError:
        parser.error(f'{runtime} 不可用：需要可執行的 {RUNTIMES[runtime]} 且 `{runtime} --version` 成功')
    print(f'已選擇 {runtime}，設定寫入 {path}')
    print('請確認沒有進行中的 safe-sudo 操作，再重啟 Hermes gateway 並開啟新對話。')


if __name__ == '__main__':
    main()
