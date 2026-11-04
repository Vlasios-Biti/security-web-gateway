#!/usr/bin/env python3
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='swg-v340-') as td:
        td=Path(td);db=td/'swg.db';live=td/'security-web-gateway.conf'
        subprocess.check_call([sys.executable,str(ROOT/'tools/migrate.py'),'--db',str(db),'--root',str(ROOT)])
        os.environ['SWG_DB_PATH']=str(db)
        os.environ['SWG_DATA_ROOT']=str(td)
        os.environ['SWG_LIVE_MANAGED_CONF']=str(live)
        os.environ['SWG_MODE']='production'
        os.environ['SWG_FQDN']='proxy.test.local'
        os.environ['SWG_PROXY_IP']='127.0.0.1'
        sys.path.insert(0,str(ROOT))

        from app.db import connect
        from app.services.policy_explain import explain_policy
        from app.services.traffic import cleanup_telemetry,refresh_dependency_candidates,refresh_dashboard_cache,dashboard_payload

        empty_cleanup=cleanup_telemetry()
        assert empty_cleanup['events_before']==0 and empty_cleanup['events_after']==0,empty_cleanup

        c=connect()
        try:
            c.execute("INSERT INTO networks(name,cidr,proxy_enabled,enabled,pending,created_by) VALUES('Pilot','10.10.10.0/24',1,1,0,'test')")
            c.execute("INSERT INTO applications(name,slug,provider,seed_domain,source_kind,status,pending,created_by) VALUES('Portal','portal','Vendor','app.example.com','manual','active',0,'test')")
            c.execute("INSERT INTO categories(name,slug,system_managed) VALUES('Portal','portal-cat',0)")
            c.execute("""INSERT INTO rules(rule_type,action,destination,protocol,category_id,management_type,status,pending,reason,fingerprint,created_by,scope_mode)
                         VALUES('domain','ALLOW','app.example.com','HTTPS',1,'custom','active',0,'test','fp-1','test','selected')""")
            c.execute("INSERT INTO application_rules(application_id,rule_id,required,source,confidence,enabled) VALUES(1,1,1,'manual','high',1)")
            c.execute("INSERT INTO application_networks(application_id,network_id) VALUES(1,1)")
            now=time.time()
            events=[
                (now-10,'2026-11-03 20:00:00','10.10.10.25','ALLOW','TCP_TUNNEL',200,1000,'CONNECT','app.example.com:443','app.example.com',443,1,'Pilot',',1,','Portal',1,'app.example.com','h1'),
                (now,'2026-11-03 20:00:10','10.10.10.25','DENY','TCP_DENIED',403,0,'CONNECT','api-new.example.net:443','api-new.example.net',443,1,'Pilot','','',None,'','h2'),
            ]
            for e in events:
                c.execute("""INSERT INTO telemetry_events(epoch,event_time,client_ip,decision,result_code,http_status,bytes,method,destination,destination_host,destination_port,network_id,network_name,application_ids,application_names,matched_rule_id,matched_rule_destination,event_hash)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",e)
            states={
                'dependency_candidate_scan_epoch':str(now-30),
                'telemetry_event_count':'2',
                'telemetry_first_event':'2026-11-03 20:00:00',
                'telemetry_last_event':'2026-11-03 20:00:10',
                'telemetry_last_event_epoch':str(now),
            }
            for key,value in states.items():
                c.execute("""INSERT INTO telemetry_state(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP)
                             ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP""",(key,value))
            c.commit()
        finally:c.close()

        decision=explain_policy('10.10.10.25','app.example.com',443,'CONNECT')
        assert decision['decision']=='ALLOW',decision

        cand=refresh_dependency_candidates()
        assert cand['created']==1,cand
        c=connect()
        try:
            row=c.execute("SELECT destination,confidence,recommendation,status FROM application_dependency_candidates").fetchone()
            assert row and row['destination']=='api-new.example.net' and row['status']=='pending',dict(row) if row else None
        finally:c.close()

        refresh_dashboard_cache((60,))
        dash=dashboard_payload(60)
        assert dash['clients']==1 and dash['denied']==1 and dash['allowed']==1,dash
        assert not dash.get('cache_warming'),dash
        print('smoke_v340=PASS')

if __name__=='__main__':main()
