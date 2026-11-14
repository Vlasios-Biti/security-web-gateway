#!/usr/bin/env python3
"""Run disposable native Squid against loopback fixtures only (sudo required)."""
import grp
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.configure_block_page import patch_squid
from app.services.block_page import render, DEFAULTS


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        body = render({**DEFAULTS, 'company': 'Fixture company'}).encode() if self.path == '/blocked' else b'Allowed fixture'
        self.send_response(200); self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)


def request(port, method, url):
    with socket.create_connection(('127.0.0.1', port), timeout=4) as connection:
        connection.sendall(f'{method} {url} HTTP/1.1\r\nHost: {url.split("://")[-1].split("/")[0]}\r\nConnection: close\r\n\r\n'.encode())
        result = b''
        while b'\r\n\r\n' not in result:
            part = connection.recv(8192)
            if not part: break
            result += part
        return result


def main():
    if os.geteuid() != 0: raise SystemExit('Run with sudo; only temporary files and loopback listeners are used.')
    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    public = ThreadingHTTPServer(('127.0.0.1', 8081), Origin)
    for server in (origin, public): threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]
    account = pwd.getpwnam('proxy')
    try:
        with tempfile.TemporaryDirectory(prefix='swg-squid-contract-') as td:
            folder = Path(td); os.chown(folder, account.pw_uid, account.pw_gid); folder.chmod(0o755)
            origin_port = origin.server_port
            config = f'''http_port 127.0.0.1:{port}
visible_hostname swg-contract.test
pid_filename {folder}/squid.pid
cache_log {folder}/cache.log
access_log none
cache_store_log none
cache deny all
cache_effective_user proxy
cache_effective_group proxy
shutdown_lifetime 0 seconds
acl CONNECT method CONNECT
acl fixture_get url_regex ^http://127\\.0\\.0\\.1:{origin_port}/$
acl fixture_port port {origin_port}
acl fixture_host dst 127.0.0.1/32
http_access allow !CONNECT fixture_get
http_access allow CONNECT fixture_port fixture_host
http_access deny all
'''
            path = folder / 'squid.conf'; path.write_text(patch_squid(config, '127.0.0.1')); path.chmod(0o644)
            subprocess.run(['/usr/sbin/squid', '-k', 'parse', '-f', str(path)], check=True, capture_output=True, timeout=15)
            with (folder/'process.log').open('wb') as log:
                process = subprocess.Popen(['/usr/sbin/squid', '-N', '-f', str(path)], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 15
                    while True:
                        if process.poll() is not None: raise RuntimeError((folder/'process.log').read_text())
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.2): break
                        except OSError:
                            if time.monotonic() > deadline: raise RuntimeError('Squid did not start.')
                            time.sleep(.1)
                    allowed = request(port, 'GET', f'http://127.0.0.1:{origin_port}/')
                    assert allowed.startswith(b'HTTP/1.1 200'), allowed[:500]
                    denied = request(port, 'GET', 'http://forbidden.example.test/')
                    assert denied.split(b' ', 2)[1] in (b'302', b'307'), denied[:500]
                    assert b'Location: http://127.0.0.1:8081/blocked' in denied, denied[:500]
                    branded = request(port, 'GET', 'http://127.0.0.1:8081/blocked')
                    assert branded.startswith(b'HTTP/1.1 200'), branded[:500]
                    denied_tls = request(port, 'CONNECT', 'forbidden.example.test:443')
                    assert denied_tls.startswith(b'HTTP/1.1 403'), denied_tls[:500]
                    assert b'Location:' not in denied_tls, denied_tls[:500]
                    allowed_tls = request(port, 'CONNECT', f'127.0.0.1:{origin_port}')
                    assert allowed_tls.startswith(b'HTTP/1.1 200'), allowed_tls[:500]
                finally:
                    process.terminate()
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
    finally:
        for server in (origin, public): server.shutdown(); server.server_close()
    print('Native Squid: allowed HTTP/CONNECT 200, denied HTTP redirects to branding, denied CONNECT 403: PASS')


if __name__ == '__main__': main()
