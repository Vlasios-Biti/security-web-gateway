"""Authenticated loopback proxy pins browser TCP connections to vetted IPs."""
import base64
import hmac
import secrets
import select
import socket
import socketserver
import threading
import time
from contextlib import contextmanager
from urllib.parse import urlsplit


class Proxy(socketserver.StreamRequestHandler):
    def handle(self):
        if not self.server.slots.acquire(blocking=False):return
        upstream=None
        try:
            self.connection.settimeout(10)
            data=b''
            while b'\r\n\r\n' not in data:
                chunk=self.connection.recv(4096)
                if not chunk:return
                data+=chunk
                if len(data)>65536:return
            header,_,buffered=data.partition(b'\r\n\r\n')
            lines=header.split(b'\r\n')
            parts=lines[0].decode('ascii').strip().split()
            if len(parts)!=3:return
            method,target,version=parts
            headers=[];auth=''
            for line in lines[1:]:
                name,_,value=line.partition(b':')
                if name.lower()==b'proxy-authorization':auth=value.strip().decode('ascii')
                elif name.lower() not in (b'proxy-connection',b'connection'):headers.append(line+b'\r\n')
            if not hmac.compare_digest(auth,self.server.authorization):
                self.connection.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="SWG discovery"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');return
            if method=='CONNECT':
                parsed=urlsplit('//'+target);port=parsed.port or 443
                if port!=443:raise ValueError('Unsupported CONNECT port')
            else:
                if method not in ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'):raise ValueError('Unsupported method')
                parsed=urlsplit(target);port=parsed.port or 80
                if parsed.scheme!='http' or port!=80:raise ValueError('Unsupported HTTP destination')
            if not parsed.hostname or parsed.username or parsed.password:raise ValueError('Invalid target')
            from app.services.discovery import _public_addresses
            addresses=_public_addresses(parsed.hostname,port)
            # Numeric address is used for the actual socket, not a second lookup
            # of the untrusted hostname. Chromium retains TLS SNI/cert validation.
            last_error=None
            for address in addresses:
                try:
                    upstream=socket.create_connection((address,port),timeout=10);break
                except OSError as exc:last_error=exc
            if upstream is None:raise last_error or OSError('No public address reachable')
            if method=='CONNECT':
                self.connection.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            else:
                path=parsed.path or '/'
                if parsed.query:path+='?'+parsed.query
                upstream.sendall(f'{method} {path} HTTP/1.1\r\n'.encode('ascii')+b''.join(headers)+b'Connection: close\r\n\r\n')
            if buffered:upstream.sendall(buffered)
            deadline=time.monotonic()+60;counts={self.connection:0,upstream:0}
            while time.monotonic()<deadline:
                ready,_,_=select.select([self.connection,upstream],[],[],1)
                for src in ready:
                    data=src.recv(65536)
                    if not data:return
                    counts[src]+=len(data)
                    if counts[src]>16*1024*1024:return
                    (upstream if src is self.connection else self.connection).sendall(data)
        except (OSError,ValueError,UnicodeError):
            try:self.connection.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            except OSError:pass
        finally:
            if upstream:upstream.close()
            self.server.slots.release()


class Server(socketserver.ThreadingTCPServer):
    daemon_threads=True
    allow_reuse_address=False


@contextmanager
def discovery_egress_proxy():
    password=secrets.token_hex(24)
    server=Server(('127.0.0.1',0),Proxy)
    server.slots=threading.BoundedSemaphore(32)
    server.authorization='Basic '+base64.b64encode(('swg:'+password).encode()).decode()
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield {'server':f'http://127.0.0.1:{server.server_address[1]}','username':'swg','password':password}
    finally:server.shutdown();server.server_close();thread.join(timeout=2)
