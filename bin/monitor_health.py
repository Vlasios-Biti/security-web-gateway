#!/usr/bin/env python3
import fcntl,json,sys,time
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from app.db import verify_schema,connect
from app.config import DATA_ROOT
from app.services.notifications import settings,process_tests,conditions,update_incidents,deliver
from app.services.expiry import expire_deployed_policy
from app.services.system import live_system_health,cached_system_health
from app.services.performance import latest_performance
from app.services.deployment import drift_status


def main():
    verify_schema();DATA_ROOT.mkdir(parents=True,exist_ok=True)
    with (DATA_ROOT/'health-monitor.lock').open('a+') as stream:
        try:fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return {'busy':True}
        try:expiry=expire_deployed_policy()
        except Exception:expiry={"ok":False,"error":"Expiry worker failed"}
        cfg=settings();process_tests(cfg)
        c=connect()
        try:backup=c.execute("SELECT MAX(timestamp) FROM audit_events WHERE action='SYSTEM_BACKUP' AND result='SUCCESS'").fetchone()[0]
        finally:c.close()
        age=(time.time()-datetime.fromisoformat(backup).replace(tzinfo=timezone.utc).timestamp())/3600 if backup else None
        found=conditions(live_system_health(),latest_performance(),drift_status(),cfg,cached_system_health().get('cache_stale',True),age)
        if not expiry.get('ok'):found['expiry']={'severity':'critical','title':'Scheduled access expiry failed','detail':'Review policy drift and the deploy helper.'}
        update_incidents(found,cfg);result=deliver(cfg)
        c=connect()
        try:
            c.execute("INSERT INTO settings(key,value,updated_at) VALUES('health_monitor_last_run',?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP",(datetime.now(timezone.utc).isoformat(),));c.commit()
        finally:c.close()
        return {'conditions':len(found),'delivery':result,'expiry':expiry}


if __name__=='__main__':
    try:print(json.dumps(main(),sort_keys=True))
    except Exception as exc:
        print(json.dumps({'ok':False,'error':type(exc).__name__}));raise SystemExit(1)
