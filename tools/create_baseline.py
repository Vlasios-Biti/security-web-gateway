#!/usr/bin/env python3
import hashlib,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from app.db import connect,verify_schema
from app.services.deployment import current_live,state_snapshot

def main():
 verify_schema();content=current_live()
 if not content.strip():raise SystemExit('Live managed configuration is empty.')
 digest=hashlib.sha256(content.encode()).hexdigest();c=connect()
 try:
  c.execute('BEGIN IMMEDIATE')
  prev=c.execute("SELECT id FROM deployments WHERE status='deployed' ORDER BY id DESC LIMIT 1").fetchone()
  version=f"v{c.execute('SELECT COUNT(*) c FROM deployments').fetchone()['c']+1:04d}"
  c.execute("""INSERT INTO deployments(version,status,created_by,description,config_sha256,config_content,diff_text,state_json,previous_deployment_id,deployed_at)
             VALUES(?,'deployed','system','Trusted cutover baseline',?,?,?, ?,?,CURRENT_TIMESTAMP)""",
            (version,digest,content,'',state_snapshot(),prev['id'] if prev else None))
  c.execute('UPDATE rules SET pending=0');c.execute('UPDATE networks SET pending=0');c.execute('UPDATE applications SET pending=0');c.execute('UPDATE policy_groups SET pending=0');c.execute("DELETE FROM sessions");c.commit();print(version,digest)
 except Exception:c.rollback();raise
 finally:c.close()
if __name__=='__main__':main()
