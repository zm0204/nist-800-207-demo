"""Open the local privileged Inspector without exposing its capability via an API."""
import argparse
import os
from pathlib import Path
import sys
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--isolated', action='store_true')
    parser.add_argument('--chrome', action='store_true', help='Open Chrome explicitly for Google Password Manager')
    args = parser.parse_args()
    folder, port = ('portal-p0', 18091) if args.isolated else ('identity', 18081)
    key = ROOT/'.tmp'/folder/'operator.key'
    if not key.exists():
        raise SystemExit('Start the corresponding server before opening Inspector.')
    url = f'http://localhost:{port}/inspector#operator='+key.read_text()
    if args.chrome:
        candidates = [Path(os.environ.get(variable, ''))/'Google/Chrome/Application/chrome.exe'
                      for variable in ('PROGRAMFILES', 'PROGRAMFILES(X86)', 'LOCALAPPDATA')]
        chrome = next((path for path in candidates if path.is_file()), None)
        if not chrome:
            raise SystemExit('Chrome not found; open the authorized Inspector in Chrome manually.')
        webbrowser.BackgroundBrowser(str(chrome)).open(url)
    else:
        webbrowser.open(url)


if __name__ == '__main__':
    main()
