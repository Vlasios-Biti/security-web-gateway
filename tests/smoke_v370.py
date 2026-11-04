#!/usr/bin/env python3
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def main():
    with tempfile.TemporaryDirectory(prefix="swg-v370-") as td:
        td=Path(td);db=td/"swg.db"
        subprocess.check_call([sys.executable,str(ROOT/"tools/migrate.py"),"--db",str(db),"--root",str(ROOT)])
        os.environ["SWG_DB_PATH"]=str(db)
        os.environ["SWG_DATA_ROOT"]=str(td)
        os.environ["SWG_MODE"]="production"
        os.environ["SWG_PROXY_IP"]="127.0.0.1"
        sys.path.insert(0,str(ROOT))

        from app.db import connect
        from app.services.discovery import approve_run
        from app.services.access_model import get_application,delete_application,create_application

        c=connect()
        try:
            assert c.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]=="014"
            cols={r["name"] for r in c.execute("PRAGMA table_info(discovery_runs)")}
            assert "auto_approve" in cols

            app=c.execute("SELECT * FROM applications WHERE name='Google Maps' AND status='active'").fetchone()
            assert app, "bootstrap Google Maps application missing"
            aid=app["id"]
            cur=c.execute("""INSERT INTO discovery_runs(application_id,query,method,status,source_ref,started_by,auto_approve)
                VALUES(?,?,'browser_auto','ready',?,'test',1)""",(aid,"https://www.google.com/maps","https://www.google.com/maps"))
            rid=cur.lastrowid
            cur=c.execute("""INSERT INTO discovery_candidates(run_id,endpoint_type,destination,protocol,required,source,confidence,selected,already_present)
                VALUES(?,'domain','maps.gstatic.com','HTTPS',1,'browser-runtime','high',1,0)""",(rid,))
            cid=cur.lastrowid
            c.commit()
        finally:
            c.close()

        result=approve_run(rid,[cid],"test")
        assert result["linked"]==1,result

        c=connect()
        try:
            cat=c.execute("SELECT id,name,slug FROM categories WHERE slug='app-google-maps'").fetchone()
            assert cat and cat["name"].startswith("Application: Google Maps"),dict(cat) if cat else None
            dep=c.execute("""SELECT r.destination FROM application_rules ar JOIN rules r ON r.id=ar.rule_id
                WHERE ar.application_id=? AND r.destination='maps.gstatic.com'""",(aid,)).fetchone()
            assert dep, "Google Maps discovery dependency not linked"
        finally:
            c.close()

        delete_application(aid,"test")
        old=get_application(aid)
        assert old is None,old
        new_id=create_application("Google Maps","Google","Recreated application","www.google.com","observed",None,False,"test")
        assert new_id!=aid
        assert get_application(new_id)["name"]=="Google Maps"
        print("smoke_v370=PASS")

if __name__=="__main__":
    main()
