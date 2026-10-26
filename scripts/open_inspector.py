"""Open the local privileged Inspector without exposing its capability via an API."""
import argparse
from pathlib import Path
import sys
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--isolated', action='store_true')
    args = parser.parse_args()
    folder, port = ('portal-p0', 18091) if args.isolated else ('identity', 18081)
    key = ROOT/'.tmp'/folder/'operator.key'
    if not key.exists():
        raise SystemExit('Start the corresponding server before opening Inspector.')
    webbrowser.open(f'http://localhost:{port}/inspector#operator='+key.read_text())


if __name__ == '__main__':
    main()
