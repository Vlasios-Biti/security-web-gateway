#!/usr/bin/env python3
"""Extract only the three expected regular files and verify a portable DB hash."""
import hashlib
import re
import shutil
import sqlite3
import sys
import tarfile
from pathlib import Path


def prepare(archive,destination):
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
    required={'swg.db','metadata.txt','SHA256SUMS.txt'}
    with tarfile.open(archive,'r:gz') as source:
        members=source.getmembers()
        if {m.name for m in members}!=required or len(members)!=3 or any(not m.isfile() for m in members):
            raise ValueError('Archive must contain exactly swg.db, metadata.txt and SHA256SUMS.txt as regular files.')
        if any(m.size>(32*1024**3 if m.name=='swg.db' else 65536) for m in members):raise ValueError('Archive entry too large.')
        if sum(m.size for m in members)+100*1024**2>shutil.disk_usage(destination).free:raise ValueError('Insufficient staging space.')
        for member in members:
            with source.extractfile(member) as incoming,(destination/member.name).open('wb') as target:shutil.copyfileobj(incoming,target)
            (destination/member.name).chmod(0o600)
    lines=(destination/'SHA256SUMS.txt').read_text().splitlines()
    if len(lines)!=1:raise ValueError('Expected one database checksum.')
    digest,name=lines[0].split(maxsplit=1)
    # Older exports used a deleted absolute staging path. Validate the extracted
    # database directly without following any path supplied by the manifest.
    if not re.fullmatch('[0-9a-fA-F]{64}',digest) or Path(name.lstrip('*')).name!='swg.db':raise ValueError('Invalid database checksum manifest.')
    with (destination/'swg.db').open('rb') as stream:computed=hashlib.file_digest(stream,'sha256').hexdigest()
    if computed.lower()!=digest.lower():raise ValueError('Database checksum mismatch.')
    c=sqlite3.connect(destination/'swg.db')
    try:
        if c.execute('PRAGMA integrity_check').fetchone()[0]!='ok' or list(c.execute('PRAGMA foreign_key_check')):raise ValueError('Backup database integrity failed.')
    finally:c.close()


if __name__=='__main__':prepare(sys.argv[1],sys.argv[2]);print('Archive and database verified')
