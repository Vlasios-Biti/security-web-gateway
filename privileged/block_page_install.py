"""Publish only fixed local branding files, never caller-supplied HTML or paths."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import grp

MODULE=Path('/opt/security-web-gateway/current/app/services/block_page.py')
CONFIG=Path('/etc/security-web-gateway/block-page.json')
PAGE=Path('/etc/security-web-gateway/blocked.html')


def model():
    spec=importlib.util.spec_from_file_location('swg_block_page_model',MODULE)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def replace(path,data,mode):
    fd,temporary=tempfile.mkstemp(prefix='.block-page-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as output:output.write(data);output.flush();os.fsync(output.fileno())
        os.chmod(temporary,mode);os.chown(temporary,0,grp.getgrnam('proxy-mgmt').gr_gid)
        os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def install(value):
    renderer=model();settings=renderer.validate(value)
    page=renderer.render(settings)
    old_page=PAGE.read_bytes() if PAGE.exists() else None
    try:
        replace(PAGE,page,0o644)
        replace(CONFIG,json.dumps(settings,ensure_ascii=False),0o640)
    except Exception:
        if old_page is not None:replace(PAGE,old_page.decode('utf-8'),0o644)
        elif PAGE.exists():PAGE.unlink()
        raise
    return {'ok':True,'message':'Company block page saved.'}
