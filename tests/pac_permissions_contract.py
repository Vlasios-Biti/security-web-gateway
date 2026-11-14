#!/usr/bin/env python3
"""Check actual unprivileged file access using disposable Linux files only."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.ensure_pac_access import ensure_pac_access


def reader():
    os.setgroups([]);os.setgid(65534);os.setuid(65534)


def can_read(path):
    result=subprocess.run(['/usr/bin/python3','-I','-c','import pathlib,sys;pathlib.Path(sys.argv[1]).read_bytes()',str(path)],preexec_fn=reader,env={},cwd='/',stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
    return result.returncode==0


def main():
    if os.geteuid()!=0:raise SystemExit('Run this disposable-file test using sudo; no real configuration is accessed.')
    with tempfile.TemporaryDirectory(prefix='swg-pac-permissions-') as td:
        base=Path(td);base.chmod(0o755)
        config=base/'config';config.mkdir(mode=0o750)
        pac=config/'proxy.pac';pac.write_text('function FindProxyForURL(){return "DIRECT";}');pac.chmod(0o644)
        env=config/'production.env';env.write_text('DUMMY_CONFIG=not-a-secret');env.chmod(0o640)
        notifications=config/'notifications.json';notifications.write_text('{"dummy":true}');notifications.chmod(0o640)
        tls=config/'tls';tls.mkdir(mode=0o750);key=tls/'management.key';key.write_text('DUMMY_KEY_NOT_A_REAL_KEY');key.chmod(0o600)
        assert not can_read(pac),'Fixture must reproduce inaccessible parent directory'
        ensure_pac_access(pac)
        assert can_read(pac),'Unprivileged nginx-like reader must read public PAC'
        assert not can_read(env) and not can_read(notifications) and not can_read(key),'Private files must remain inaccessible'
        assert config.stat().st_mode&0o777==0o751
        ensure_pac_access(pac)
        assert env.stat().st_mode&0o777==0o640 and key.stat().st_mode&0o777==0o600
        link=config/'linked.pac';link.symlink_to(env)
        try:ensure_pac_access(link)
        except ValueError:pass
        else:raise AssertionError('Symlink must not make a private target public')
    print('PASS: public PAC readable by an unprivileged UID; env/notifications/TLS key remain private; repair is idempotent and rejects links')


if __name__=='__main__':main()
