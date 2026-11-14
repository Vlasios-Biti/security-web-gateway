#!/usr/bin/env python3
"""Create a private archive inode before writing and publish it atomically."""
import os
from pathlib import Path
import tarfile


def export_archive(stage,destination):
    stage=Path(stage);destination=Path(destination).absolute()
    parent=os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY)
    temporary=None
    try:
        import secrets
        temporary='.swg-export-'+secrets.token_hex(16)+'.tmp'
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        with os.fdopen(fd,'wb') as stream:
            with tarfile.open(fileobj=stream,mode='w:gz') as archive:
                for name in ('swg.db','metadata.txt','SHA256SUMS.txt'):
                    archive.add(stage/name,arcname=name,recursive=False)
            stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,destination.name,src_dir_fd=parent,dst_dir_fd=parent)
        temporary=None;os.fsync(parent)
    finally:
        if temporary is not None:
            try:os.unlink(temporary,dir_fd=parent)
            except FileNotFoundError:pass
        os.close(parent)


if __name__=='__main__':
    import sys
    export_archive(sys.argv[1],sys.argv[2])
