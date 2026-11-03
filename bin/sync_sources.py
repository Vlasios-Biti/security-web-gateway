#!/usr/bin/env python3
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from app.db import connect,verify_schema,audit
from app.services.discovery import create_run,get_run

def main():
    verify_schema();c=connect()
    try:apps=[dict(x) for x in c.execute("SELECT * FROM applications WHERE status='active' AND auto_monitor=1 AND source_kind IN('official_api','official_url')")]
    finally:c.close()
    changed=0;unchanged=0;failed=0
    for a in apps:
        old=a.get('last_source_version')
        try:
            if a['source_kind']=='official_api':rid=create_run(a['id'],a.get('source_ref') or a['slug'],'official_api','system-sync',catalog_key=a.get('source_ref') or a['slug'])
            else:rid=create_run(a['id'],a['name'],'official_url','system-sync',source_ref=a.get('source_ref'))
            run=get_run(rid);new=run.get('source_version')
            if old and new and old==new:
                c=connect()
                try:c.execute("DELETE FROM discovery_candidates WHERE run_id=?",(rid,));c.execute("UPDATE discovery_runs SET status='discarded',error_text='No source version change' WHERE id=?",(rid,));c.commit()
                finally:c.close()
                unchanged+=1
            else:
                changed+=1;audit('system-sync','APPLICATION_SOURCE_CHANGE','SUCCESS','application',a['id'],None,f'run={rid};old={old};new={new}')
        except Exception as exc:
            failed+=1;audit('system-sync','APPLICATION_SOURCE_SYNC','FAILED','application',a['id'],None,str(exc))
    print(f'apps={len(apps)} changed={changed} unchanged={unchanged} failed={failed}')
    return 1 if failed else 0
if __name__=='__main__':raise SystemExit(main())
