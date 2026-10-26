"""Windows one-click bootstrap without changing PowerShell execution policy."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    os.chdir(ROOT)
    probe = subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'], capture_output=True)
    if probe.returncode:
        desktop = Path(os.environ.get('LOCALAPPDATA', '')) / 'Programs/DockerDesktop/Docker Desktop.exe'
        if os.name != 'nt' or not desktop.exists():
            raise RuntimeError('Start Docker Desktop / Docker Engine before retrying')
        subprocess.Popen([str(desktop)], creationflags=subprocess.CREATE_NO_WINDOW)
        deadline = time.monotonic()+60
        while time.monotonic() < deadline:
            time.sleep(2)
            if subprocess.run(['docker', 'info'], capture_output=True).returncode == 0:
                break
        else:
            raise RuntimeError('Docker did not become ready; finish Desktop startup and retry')
    subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements-dev.txt', '-r', 'requirements-mesh.txt'], check=True)
    import httpx
    if args.verify:
        subprocess.run([sys.executable, '-m', 'pytest', '-q', '--basetemp=.tmp/windows-verification'], check=True)
    from scripts.identity_deploy import up, STATE
    up()
    if args.verify:
        from scripts.verify_identity import run
        run()
    url = 'http://localhost:18081'
    try:
        response = httpx.get(url, timeout=2, trust_env=False)
        if '員工服務' not in response.text:
            raise RuntimeError('Port 18081 belongs to another application; stop it before retrying')
        running = True
    except httpx.HTTPError:
        running = False
    if not running:
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
        with (STATE/'inspector.log').open('a', encoding='utf-8') as log:
            process = subprocess.Popen([sys.executable, str(ROOT/'scripts/security_inspector.py')],
                cwd=ROOT, stdout=log, stderr=log, **options)
        (STATE/'inspector.pid').write_text(str(process.pid))
        deadline = time.monotonic()+25
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('Inspector exited; inspect .tmp/identity/inspector.log and ports 18081/18082/18443')
            try:
                if httpx.get(url, timeout=1, trust_env=False).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(.25)
        else:
            raise RuntimeError('Inspector not ready; inspect .tmp/identity/inspector.log')
    if not args.no_browser:
        webbrowser.open(url)
    print('Employee Portal: '+url+'/portal', flush=True)
    print('Observer: '+url+'/observer', flush=True)
    print('Authorized Inspector: python scripts/open_inspector.py', flush=True)
    print('Original 207 data preserved. Phase 2 / Multi-Location not implemented.', flush=True)


if __name__ == '__main__':
    main()
