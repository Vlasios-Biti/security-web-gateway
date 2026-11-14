#!/usr/bin/env python3
"""Allow anonymous nginx access to the public PAC without exposing config files."""
from pathlib import Path
import os
import stat


def ensure_pac_access(pac_path=Path('/etc/security-web-gateway/proxy.pac')):
    pac_path=Path(pac_path)
    parent=pac_path.parent
    directory=parent.lstat();file=pac_path.lstat()
    if not stat.S_ISDIR(directory.st_mode) or not stat.S_ISREG(file.st_mode) or file.st_nlink!=1:
        raise ValueError('Expected a real PAC file in the standard configuration directory.')
    # Search permission permits access to this known public filename, without
    # directory listing or access to env/notification files protected by 0640.
    os.chmod(pac_path,0o644)
    os.chmod(parent,stat.S_IMODE(directory.st_mode)|stat.S_IXOTH)


if __name__=='__main__':
    ensure_pac_access()
    print('Public PAC is readable; private configuration file permissions are unchanged.')
