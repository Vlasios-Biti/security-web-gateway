#!/usr/bin/env python3
import fcntl,grp,hashlib,importlib.util,json,os,re,shutil,sqlite3,subprocess,sys,tempfile
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path('/var/lib/security-web-gateway/prod/candidates')
BACKUPS=Path('/var/lib/security-web-gateway/backups')
LIVE=Path('/etc/squid/managed/security-web-gateway.conf')
DB=Path('/var/lib/security-web-gateway/prod/swg.db')
NGINX=Path('/etc/nginx/sites-available/security-web-gateway')
SQUID=Path('/etc/squid/squid.conf')
LOCK=Path('/run/security-web-gateway/policy-apply.lock')
PAC=Path('/etc/security-web-gateway/proxy.pac')
ENV_FILE=Path('/etc/security-web-gateway/production.env')
PAC_RENDERER=Path('/opt/security-web-gateway/current/app/services/pac_policy.py')
MANAGED_VALIDATOR=Path('/opt/security-web-gateway/current/app/services/managed_config.py')
CID=re.compile(r'^[0-9a-f]{8}-[0-9a-f-]{27}$')

def out(ok,msg,**kw):
    d={'ok':ok,'message':msg}
    d.update(kw)
    print(json.dumps(d))
    sys.stdout.flush()

def run(c,t=30):
    return subprocess.run(c,capture_output=True,text=True,timeout=t,check=False)

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def perms(p):
    try:g=grp.getgrnam('proxy').gr_gid
    except Exception:g=0
    os.chown(p,0,g)
    os.chmod(p,0o640)

def validate():
    p=run(['/usr/sbin/squid','-k','parse'])
    return {
        'ok':p.returncode==0,
        'message':'Squid configuration valid.' if p.returncode==0 else 'Squid validation failed.',
        'error':p.stderr[-2000:] if p.returncode else None,
    }

def backup():
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    d=BACKUPS/f'manual-{stamp}'
    d.mkdir(parents=True,exist_ok=False)
    os.chmod(d,0o700)
    if SQUID.exists():shutil.copy2(SQUID,d/'squid.conf')
    if LIVE.exists():shutil.copy2(LIVE,d/'security-web-gateway.conf')
    if NGINX.exists():shutil.copy2(NGINX,d/'nginx-security-web-gateway.conf')
    pac=Path('/etc/security-web-gateway/proxy.pac')
    if pac.exists():shutil.copy2(pac,d/'proxy.pac')
    if DB.exists():
        con=sqlite3.connect(DB)
        dst=sqlite3.connect(d/'swg.db')
        try:con.backup(dst)
        finally:
            dst.close()
            con.close()
    (d/'manifest.json').write_text(json.dumps({
        'created_at':datetime.now(timezone.utc).isoformat(),
        'files':[x.name for x in d.iterdir()],
    }))
    return {'ok':True,'message':'Configuration backup created.','backup':str(d)}

def _deploy_locked(cid):
    if not CID.fullmatch(cid):raise ValueError('Invalid candidate ID.')
    d=(ROOT/cid).resolve()
    if d.parent!=ROOT.resolve():raise ValueError('Invalid path.')
    conf=d/'security-web-gateway.conf'
    man=d/'manifest.json'
    if conf.is_symlink() or man.is_symlink() or not conf.is_file() or not man.is_file():
        raise ValueError('Candidate missing or unsafe.')
    if conf.stat().st_size>2*1024*1024 or man.stat().st_size>65536:
        raise ValueError('Candidate file too large.')
    manifest=json.loads(man.read_text())
    fd=os.open(conf,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:content=stream.read(2*1024*1024+1)
    expected=manifest.get('sha256')
    if len(content)>2*1024*1024 or expected!=hashlib.sha256(content).hexdigest():raise ValueError('Checksum mismatch or oversized content.')
    spec=importlib.util.spec_from_file_location('swg_managed_validator',MANAGED_VALIDATOR)
    validator=importlib.util.module_from_spec(spec);spec.loader.exec_module(validator)
    validator.validate_managed_config(content.decode('utf-8'))
    base=manifest.get('base_sha256')
    live_sha=sha(LIVE) if LIVE.exists() else hashlib.sha256(b'').hexdigest()
    if base is not None and base!=live_sha:raise ValueError('Live policy changed since candidate creation. Review drift before retrying.')

    BACKUPS.mkdir(parents=True,exist_ok=True)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    b=BACKUPS/f'policy-{stamp}.conf' if LIVE.exists() else None
    if b:
        shutil.copy2(LIVE,b)
        perms(b)

    LIVE.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.security-web-gateway.',dir=str(LIVE.parent))
    with os.fdopen(fd,'wb') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
    perms(Path(tmp))
    os.replace(tmp,LIVE)

    v=validate()
    if not v['ok']:
        if b:
            shutil.copy2(b,LIVE)
            perms(LIVE)
        return {'ok':False,'message':'Squid validation failed; rollback completed.','error':v.get('error')}

    rel=run(['/usr/bin/systemctl','reload','squid'])
    health=run(['/usr/bin/systemctl','is-active','squid'])
    if rel.returncode or health.stdout.strip()!='active':
        if b:
            shutil.copy2(b,LIVE)
            perms(LIVE)
            run(['/usr/bin/systemctl','reload','squid'])
        return {'ok':False,'message':'Squid reload/health failed; rollback completed.'}

    return {'ok':True,'message':'Deployment successful.','backup':str(b) if b else None,'sha256':expected}

def publish_pac(policy):
    # Import only root-owned installed release code; never accept JavaScript,
    # shell commands or a destination path from the unprivileged caller.
    module=PAC_RENDERER
    spec=importlib.util.spec_from_file_location('swg_pac_policy',module)
    renderer=importlib.util.module_from_spec(spec);spec.loader.exec_module(renderer)
    env={}
    for line in ENV_FILE.read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key,value=line.split('=',1);env[key.strip()]=value.strip()
    content=renderer.render_pac(policy,env['SWG_PROXY_IP'],int(env.get('SWG_PROXY_PORT','3128')))
    target=PAC
    with open(LOCK,'a+') as lockf:
        fcntl.flock(lockf.fileno(),fcntl.LOCK_EX)
        BACKUPS.mkdir(parents=True,exist_ok=True)
        previous=None
        if target.exists():
            stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
            previous=BACKUPS/f'pac-{stamp}.pac';shutil.copy2(target,previous);os.chmod(previous,0o600)
        fd,tmp=tempfile.mkstemp(prefix='.proxy-pac-',dir=str(target.parent))
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as stream:
                stream.write(content);stream.flush();os.fsync(stream.fileno())
            os.chmod(tmp,0o644);os.replace(tmp,target)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    return {'ok':True,'message':'Connection policy published.','backup':str(previous) if previous else None}


def _save_notifications_locked(value):
    module=Path('/opt/security-web-gateway/current/app/services/notification_config.py')
    spec=importlib.util.spec_from_file_location('swg_notification_config',module)
    config=importlib.util.module_from_spec(spec);spec.loader.exec_module(config)
    validated=config.validate_settings(value,config.read_settings())
    fd,tmp=tempfile.mkstemp(prefix='.notifications-',dir=str(config.PATH.parent))
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(validated,stream);stream.flush();os.fsync(stream.fileno())
        os.chown(tmp,0,grp.getgrnam('proxy-mgmt').gr_gid);os.chmod(tmp,0o640)
        os.replace(tmp,config.PATH)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return {'ok':True,'message':'Health notification settings saved.'}


def save_notifications(value):
    LOCK.parent.mkdir(parents=True,exist_ok=True)
    with (LOCK.parent/'notifications.lock').open('a+') as stream:
        fcntl.flock(stream.fileno(),fcntl.LOCK_EX)
        try:return _save_notifications_locked(value)
        finally:fcntl.flock(stream.fileno(),fcntl.LOCK_UN)


def deploy(cid):
    LOCK.parent.mkdir(parents=True,exist_ok=True)
    with open(LOCK,'a+') as lockf:
        fcntl.flock(lockf.fileno(),fcntl.LOCK_EX)
        try:
            return _deploy_locked(cid)
        finally:
            fcntl.flock(lockf.fileno(),fcntl.LOCK_UN)


def main():
    try:
        raw=sys.stdin.readline(262145)
        if len(raw)>262144:raise ValueError('Request too large.')
        req=json.loads(raw)
        act=req.get('action')
        if act=='deploy':
            r=deploy(req.get('candidate_id',''))
        elif act=='validate_squid':
            r=validate()
        elif act=='reload_squid':
            v=validate()
            r=v if not v['ok'] else (
                {'ok':True,'message':'Squid validated and reloaded.'}
                if run(['/usr/bin/systemctl','reload','squid']).returncode==0
                else {'ok':False,'message':'Squid reload failed.'}
            )
        elif act=='backup':
            r=backup()
        elif act=='publish_pac':
            r=publish_pac(req.get('policy'))
        elif act in ('install_certificate','renew_self_signed_certificate'):
            module_path=Path('/opt/security-web-gateway/current/privileged/tls_install.py')
            spec=importlib.util.spec_from_file_location('swg_tls_install',module_path)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            LOCK.parent.mkdir(parents=True,exist_ok=True)
            with LOCK.open('a+') as lockf:
                fcntl.flock(lockf.fileno(),fcntl.LOCK_EX)
                operation=module.install if act=='install_certificate' else module.renew_self_signed
                r=operation(req.get('certificate_data',{}))
        elif act=='save_notifications':
            r=save_notifications(req.get('settings'))
        elif act=='save_block_page':
            module_path=Path('/opt/security-web-gateway/current/privileged/block_page_install.py')
            spec=importlib.util.spec_from_file_location('swg_block_page_install',module_path)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            LOCK.parent.mkdir(parents=True,exist_ok=True)
            with LOCK.open('a+') as lockf:
                fcntl.flock(lockf.fileno(),fcntl.LOCK_EX)
                r=module.install(req.get('settings'))
        else:
            raise ValueError('Unsupported action.')
        out(r.pop('ok',False),r.pop('message','Completed.'),**r)
    except Exception as e:
        out(False,str(e))


if __name__=="__main__":
    main()
