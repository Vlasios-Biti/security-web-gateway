#!/usr/bin/env python3
import json, os, sqlite3, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def migrate(db):
    subprocess.check_call([sys.executable,str(ROOT/'tools/migrate.py'),'--db',str(db),'--root',str(ROOT)])

def main():
    with tempfile.TemporaryDirectory(prefix='swg-v331-') as td:
        td=Path(td);db=td/'swg.db';live=td/'security-web-gateway.conf'
        migrate(db)
        os.environ['SWG_DB_PATH']=str(db)
        os.environ['SWG_DATA_ROOT']=str(td)
        os.environ['SWG_LIVE_MANAGED_CONF']=str(live)
        os.environ['SWG_MODE']='production'
        sys.path.insert(0,str(ROOT))

        from app.db import connect
        from app.services.access_model import create_policy_group,update_policy_group
        from app.services.discovery import discover_har

        c=connect()
        try:
            c.execute("INSERT INTO networks(name,cidr,proxy_enabled,enabled,pending,created_by) VALUES('Pilot','10.10.10.0/24',1,1,0,'test')")
            c.execute("INSERT INTO applications(name,slug,source_kind,status,pending,created_by) VALUES('App','app','manual','active',0,'test')")
            c.commit()
        finally:c.close()
        gid=create_policy_group('Profile','initial',[1],[],[1],'test')
        c=connect();c.execute('UPDATE policy_groups SET pending=0 WHERE id=?',(gid,));c.commit();c.close()
        update_policy_group(gid,'Profile','metadata only',[1],[],[1],'test')
        c=connect();pending=c.execute('SELECT pending FROM policy_groups WHERE id=?',(gid,)).fetchone()['pending'];c.close()
        assert pending==0, 'metadata-only Access Profile edit incorrectly became pending'

        har={"log":{"entries":[
            {"request":{"method":"GET","url":"https://app.example.com/"}},
            {"request":{"method":"POST","url":"https://api.vendor.example/v1/items?token=redacted"}},
            {"request":{"method":"GET","url":"https://www.google-analytics.com/g/collect"}},
        ]}}
        items,version,source=discover_har(json.dumps(har).encode(),'app.example.com')
        by={x['destination']:x for x in items}
        assert by['app.example.com']['recommendation']=='allow'
        assert by['api.vendor.example']['recommendation']=='allow'
        assert by['www.google-analytics.com']['recommendation']=='ignore'
        assert source=='har-upload' and len(version)==16
        print('smoke_v331=PASS')

if __name__=='__main__':main()
