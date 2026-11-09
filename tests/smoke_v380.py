#!/usr/bin/env python3
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def main():
    with tempfile.TemporaryDirectory(prefix="swg-v380-") as td:
        td=Path(td)
        db=td/"swg.db"
        live=td/"managed.conf"
        subprocess.check_call([sys.executable,str(ROOT/"tools/migrate.py"),"--db",str(db),"--root",str(ROOT)])

        os.environ["SWG_DB_PATH"]=str(db)
        os.environ["SWG_DATA_ROOT"]=str(td)
        os.environ["SWG_LIVE_MANAGED_CONF"]=str(live)
        os.environ["SWG_MODE"]="production"
        os.environ["SWG_PROXY_IP"]="127.0.0.1"
        sys.path.insert(0,str(ROOT))

        from app.db import connect
        import app.services.apply as applysvc

        c=connect()
        try:
            assert c.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]=="016"
            cols={r["name"] for r in c.execute("PRAGMA table_info(discovery_runs)")}
            assert {"auto_apply","baseline_dirty"}.issubset(cols),cols
        finally:
            c.close()

        # Operator can save desired state but cannot publish production policy.
        r=applysvc.apply_saved_change("operator",None,"operator test",role="operator")
        assert r["ok"] and not r["applied"] and r["pending_approval"],r

        # A new Save must never silently publish unrelated pre-existing pending policy.
        r=applysvc.apply_saved_change("admin",None,"legacy guard",preexisting_dirty=True,role="admin")
        assert r["ok"] and not r["applied"] and r["pending_approval"],r

        original_reconcile=applysvc.reconcile_pending_if_no_diff
        original_deploy=applysvc.deploy
        try:
            # Metadata-only save should not create a deployment.
            applysvc.reconcile_pending_if_no_diff=lambda: {"cleared":True,"reason":"no effective policy diff"}
            applysvc.deploy=lambda *a,**kw: (_ for _ in ()).throw(AssertionError("deploy must not be called"))
            r=applysvc.apply_saved_change("admin",None,"metadata only",role="admin")
            assert r["ok"] and r["no_effective_change"] and not r["applied"],r

            # Effective Admin save applies immediately.
            applysvc.reconcile_pending_if_no_diff=lambda: {"cleared":False,"reason":"effective policy diff exists"}
            applysvc.deploy=lambda *a,**kw: {"ok":True,"message":"Deployment successful.","backup":"/tmp/backup"}
            r=applysvc.apply_saved_change("admin",None,"direct save",role="admin")
            assert r["ok"] and r["applied"],r

            # Failed validation/apply leaves previous production policy active.
            applysvc.deploy=lambda *a,**kw: {"ok":False,"message":"Squid validation failed; rollback completed."}
            r=applysvc.apply_saved_change("admin",None,"failed save",role="admin")
            assert not r["ok"] and not r["applied"],r
        finally:
            applysvc.reconcile_pending_if_no_diff=original_reconcile
            applysvc.deploy=original_deploy

        c=connect()
        try:
            actions=[dict(x) for x in c.execute("SELECT action,result FROM audit_events WHERE action='SAVE_APPLY'")]
            assert actions,actions
            results={x["result"] for x in actions}
            assert {"PENDING_APPROVAL","BLOCKED_EXISTING_PENDING","NO_EFFECTIVE_CHANGE","SUCCESS","FAILED"}.issubset(results),results
        finally:
            c.close()

        print("smoke_v380=PASS")

if __name__=="__main__":
    main()
