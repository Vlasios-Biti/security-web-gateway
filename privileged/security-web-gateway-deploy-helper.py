#!/usr/bin/env python3
import grp,hashlib,json,os,re,shutil,sqlite3,subprocess,sys,tempfile
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path('/var/lib/security-web-gateway/prod/candidates');BACKUPS=Path('/var/lib/security-web-gateway/backups');LIVE=Path('/etc/squid/managed/security-web-gateway.conf');DB=Path('/var/lib/security-web-gateway/prod/swg.db');NGINX=Path('/etc/nginx/sites-available/security-web-gateway');SQUID=Path('/etc/squid/squid.conf');CID=re.compile(r'^[0-9a-f]{8}-[0-9a-f-]{27}$')
def out(ok,msg,**kw):d={'ok':ok,'message':msg};d.update(kw);print(json.dumps(d));sys.stdout.flush()
def run(c,t=30):return subprocess.run(c,capture_output=True,text=True,timeout=t,check=False)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def perms(p):
 try:g=grp.getgrnam('proxy').gr_gid
 except Exception:g=0
 os.chown(p,0,g);os.chmod(p,0o640)
def validate():
 p=run(['/usr/sbin/squid','-k','parse']);return {'ok':p.returncode==0,'message':'Squid configuration valid.' if p.returncode==0 else 'Squid validation failed.','error':p.stderr[-2000:] if p.returncode else None}
def backup():
 stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f');d=BACKUPS/f'manual-{stamp}';d.mkdir(parents=True,exist_ok=False);os.chmod(d,0o700)
 if SQUID.exists():shutil.copy2(SQUID,d/'squid.conf')
 if LIVE.exists():shutil.copy2(LIVE,d/'security-web-gateway.conf')
 if NGINX.exists():shutil.copy2(NGINX,d/'nginx-security-web-gateway.conf')
 if DB.exists():
  con=sqlite3.connect(DB);dst=sqlite3.connect(d/'swg.db')
  try:con.backup(dst)
  finally:dst.close();con.close()
 (d/'manifest.json').write_text(json.dumps({'created_at':datetime.now(timezone.utc).isoformat(),'files':[x.name for x in d.iterdir()]}));return {'ok':True,'message':'Configuration backup created.','backup':str(d)}
def deploy(cid):
 if not CID.fullmatch(cid):raise ValueError('Invalid candidate ID.')
 d=(ROOT/cid).resolve()
 if d.parent!=ROOT.resolve():raise ValueError('Invalid path.')
 conf=d/'security-web-gateway.conf';man=d/'manifest.json'
 if conf.is_symlink() or man.is_symlink() or not conf.is_file() or not man.is_file():raise ValueError('Candidate missing or unsafe.')
 if conf.stat().st_size>2*1024*1024 or man.stat().st_size>65536:raise ValueError('Candidate file too large.')
 expected=json.loads(man.read_text()).get('sha256')
 if expected!=sha(conf):raise ValueError('Checksum mismatch.')
 BACKUPS.mkdir(parents=True,exist_ok=True);stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f');b=BACKUPS/f'policy-{stamp}.conf' if LIVE.exists() else None
 if b:shutil.copy2(LIVE,b);perms(b)
 LIVE.parent.mkdir(parents=True,exist_ok=True);fd,tmp=tempfile.mkstemp(prefix='.security-web-gateway.',dir=str(LIVE.parent));os.close(fd);shutil.copy2(conf,tmp);perms(Path(tmp));os.replace(tmp,LIVE)
 v=validate()
 if not v['ok']:
  if b:shutil.copy2(b,LIVE);perms(LIVE)
  return {'ok':False,'message':'Squid validation failed; rollback completed.','error':v.get('error')}
 rel=run(['/usr/bin/systemctl','reload','squid']);health=run(['/usr/bin/systemctl','is-active','squid'])
 if rel.returncode or health.stdout.strip()!='active':
  if b:shutil.copy2(b,LIVE);perms(LIVE);run(['/usr/bin/systemctl','reload','squid'])
  return {'ok':False,'message':'Squid reload/health failed; rollback completed.'}
 return {'ok':True,'message':'Deployment successful.','backup':str(b) if b else None,'sha256':expected}
try:
 req=json.loads(sys.stdin.readline());act=req.get('action')
 if act=='deploy':r=deploy(req.get('candidate_id',''))
 elif act=='validate_squid':r=validate()
 elif act=='reload_squid':
  v=validate();r=v if not v['ok'] else ({'ok':True,'message':'Squid validated and reloaded.'} if run(['/usr/bin/systemctl','reload','squid']).returncode==0 else {'ok':False,'message':'Squid reload failed.'})
 elif act=='backup':r=backup()
 else:raise ValueError('Unsupported action.')
 out(r.pop('ok',False),r.pop('message','Completed.'),**r)
except Exception as e:out(False,str(e))
