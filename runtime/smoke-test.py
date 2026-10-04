#!/usr/bin/env python3
"""Offline runtime checks; never scan external targets or require credentials."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def run(argv, *, codes=(0,), timeout=60, env=None):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, env=env)
    if result.returncode not in codes:
        raise RuntimeError(f"{argv[0]} failed ({result.returncode}): {(result.stdout + result.stderr)[-2000:]}")
    return result


def main():
    run(['xalgorix', '--version'])
    lock = json.loads(Path('/usr/local/share/xalgorix/content-lock.json').read_text())
    for name in lock['required']:
        if not shutil.which(name):
            raise RuntimeError(f'missing scanner: {name}')
        command = lock.get('version_commands', {}).get(name) or [name, *lock.get('version_args', {}).get(name, ['--version'])]
        run(command, codes=lock.get('version_exit_codes', {}).get(name, [0]), env={**os.environ, **lock.get('version_env', {}).get(name, {})})
        print(f'OK {name}', flush=True)
    if not Path('/opt/kube-bench/cfg/config.yaml').is_file():
        raise RuntimeError('kube-bench benchmark configuration missing')
    for name in ('go', 'cargo', 'rustc', 'node', 'npm', 'gcc', 'pip', 'pip3',
                 'burpsuite', 'ffuf', 'feroxbuster', 'gvm-cli', 'trufflehog'):
        if shutil.which(name):
            raise RuntimeError(f'unexpected build/unused tool: {name}')
    for name in ('chromium', 'git', 'ssh', 'openssl'):
        run([name, '-V' if name == 'ssh' else '--version'] if name != 'openssl' else ['openssl', 'version'])
    run(['chromium', '--headless', '--no-sandbox', '--disable-gpu', '--dump-dom', 'about:blank'])
    # Exercise discovery exclusively against a local fixture.
    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'<a href="/linked">link</a><script>fetch("/js-route")</script>' if self.path == '/' else b'fixture'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f'http://127.0.0.1:{server.server_port}'
        probe = run(['httpx', '-u', url, '-json', '-silent'])
        if url not in probe.stdout:
            raise RuntimeError('httpx did not discover local fixture')
        crawl = run(['katana', '-u', url, '-d', '2', '-headless', '-no-sandbox',
                     '-system-chrome', '-scp', '/usr/bin/chromium', '-xhr', '-jc', '-silent', '-jsonl', '-rl', '5', '-c', '1'])
        if '/linked' not in crawl.stdout or '/js-route' not in crawl.stdout:
            raise RuntimeError('Katana link/JavaScript discovery missing: ' + crawl.stderr[-1000:])
        run(['nmap', '-sT', '-Pn', '-n', '-p', str(server.server_port), '127.0.0.1'])
    finally:
        server.shutdown()
        server.server_close()
    # Detect broken shared libraries, not just missing files on PATH.
    for root in ('/opt/venvs', '/root/go/bin', '/usr/bin/nmap', '/usr/sbin/masscan'):
        paths = [Path(root)] if Path(root).is_file() else Path(root).rglob('*')
        for path in paths:
            if path.is_file() and not path.is_symlink():
                with path.open('rb') as stream:
                    elf = stream.read(4) == b'\x7fELF'
                if elf:
                    result = subprocess.run(['ldd', str(path)], capture_output=True, text=True)
                    if 'not found' in result.stdout + result.stderr:
                        raise RuntimeError(f'missing library for {path}: {result.stdout}{result.stderr}')
    # Exercise source analysis offline with a local rule and synthetic fixture.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'example.py').write_text('eval(input())\n')
        (root / 'rule.yaml').write_text('rules:\n- id: runtime-eval\n  languages: [python]\n  message: Runtime fixture\n  severity: ERROR\n  pattern: eval(...)\n')
        env = {**os.environ, 'SEMGREP_SEND_METRICS': 'off'}
        result = run(['semgrep', '--config', str(root / 'rule.yaml'), '--metrics=off', '--json', str(root / 'example.py')], env=env)
        if not json.loads(result.stdout)['results']:
            raise RuntimeError('Semgrep fixture finding missing')
        run(['trivy', 'fs', '--scanners', 'secret', '--skip-db-update', '--skip-java-db-update', '--offline-scan', '--format', 'json', directory], env={**os.environ, 'TRIVY_SKIP_VERSION_CHECK': 'true'})
        run(['gitleaks', 'detect', '--no-git', '--source', directory, '--no-banner', '--exit-code', '0'])
    print('OK browser, HTTP/JavaScript discovery, native libraries, source fixture, and removed tools')


if __name__ == '__main__':
    main()
