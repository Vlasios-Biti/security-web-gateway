"""Expire only already-deployed grants without publishing queued desired work."""
import copy
import hashlib
import json
import sqlite3
from datetime import datetime,timezone
from app.db import connect,audit
from app.services.policy_lock import policy_edit_lock


def is_due(value):
    if not value:return False
    try:
        date=datetime.fromisoformat(value.replace('Z','+00:00'))
        if date.tzinfo is None:date=date.replace(tzinfo=timezone.utc)
        return date<=datetime.now(timezone.utc)
    except (ValueError,TypeError):return True


def expire_deployed_policy():
    from app.services.deployment import MODE,deployment_lock,current_live,generate_config,_insert_rows,_publish_snapshot
    if MODE!='production':return {'ok':True,'expired':0,'preview':True}
    with policy_edit_lock(),deployment_lock():
        c=connect()
        try:
            row=c.execute("SELECT state_json,config_sha256 FROM deployments WHERE status='deployed' ORDER BY id DESC LIMIT 1").fetchone()
            if not row:return {'ok':True,'expired':0}
            original=json.loads(row['state_json']);state=copy.deepcopy(original)
            due=[r for r in state.get('rules',[]) if r['status']=='active' and is_due(r.get('expires_at'))]
            if not due:return {'ok':True,'expired':0}
            if hashlib.sha256(current_live().encode()).hexdigest()!=row['config_sha256']:
                audit('system-expiry','POLICY_EXPIRY','FAILED',details_json='{"reason":"live configuration drift"}')
                return {'ok':False,'error':'Live configuration drift prevents safe expiry.'}
            for rule in due:rule['status']='disabled';rule['pending']=0
            memory=sqlite3.connect(':memory:');memory.row_factory=sqlite3.Row
            try:
                for table,rows in state.items():
                    if table not in ('rules','networks','applications','policy_groups','rule_networks','application_rules','application_networks','policy_group_applications','policy_group_rules','policy_group_networks'):raise ValueError('Invalid policy snapshot.')
                    schema=c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
                    if not schema:raise ValueError('Unsupported policy snapshot table.')
                    memory.execute(schema['sql']);_insert_rows(memory,table,rows)
                content=generate_config(memory)
            finally:memory.close()
        finally:c.close()
        result=_publish_snapshot(content,state,'system-expiry',None,f"Expire {len(due)} deployed grants",row['config_sha256'])
        if result.get('ok'):
            c=connect()
            try:
                c.execute('BEGIN IMMEDIATE')
                for before in original['rules']:
                    if not any(x['id']==before['id'] for x in due):continue
                    current=c.execute('SELECT * FROM rules WHERE id=?',(before['id'],)).fetchone()
                    if current and {k:v for k,v in dict(current).items() if k!='pending'}=={k:v for k,v in before.items() if k!='pending'}:
                        c.execute("UPDATE rules SET status='disabled',updated_by='system-expiry',updated_at=CURRENT_TIMESTAMP WHERE id=?",(before['id'],))
                c.commit()
            finally:c.close()
        audit('system-expiry','POLICY_EXPIRY','SUCCESS' if result.get('ok') else 'FAILED',details_json=json.dumps({'count':len(due)}))
        return {'ok':bool(result.get('ok')),'expired':len(due) if result.get('ok') else 0}
