"""Explicit membership corrections; suggestions never publish allow rules."""
import json
from app.db import connect, audit
from app.services.resource_permissions import actor_role, require_application_write


def matches(pattern, host):
    pattern=(pattern or '').lower().rstrip('.');host=host.lower().rstrip('.')
    if pattern.startswith('*.'):return host==pattern[2:] or host.endswith(pattern[1:])
    if pattern.startswith('.'):return host==pattern[1:] or host.endswith(pattern)
    return pattern==host


def catalog(c):
    apps={r['id']:{**dict(r),'domains':[]} for r in c.execute("SELECT id,name,seed_domain,system_managed FROM applications WHERE status='active' ORDER BY name")}
    for row in c.execute("SELECT ar.application_id,r.destination FROM application_rules ar JOIN rules r ON r.id=ar.rule_id WHERE ar.enabled=1 AND r.status='active' AND r.rule_type='domain'"):
        if row['application_id'] in apps:apps[row['application_id']]['domains'].append(row['destination'])
    return list(apps.values())


def suggestions(host, source_id, apps):
    found=[]
    for app in apps:
        if app['id']==source_id:continue
        if matches(app['seed_domain'],host) or (app['seed_domain'] and matches('*.'+app['seed_domain'],host)):
            found.append({'id':app['id'],'name':app['name'],'reason':'matches primary domain'})
        elif any(matches(domain,host) for domain in app['domains']):
            found.append({'id':app['id'],'name':app['name'],'reason':'already listed in this application'})
    return found[:5]


def _authorize(c, source, target, actor):
    if actor_role(c,actor) not in ('admin','operator'):raise ValueError('Access management permission required.')
    if source==target:raise ValueError('Choose a different application.')
    require_application_write(c,source,actor);dest=require_application_write(c,target,actor)
    if dest['status']!='active':raise ValueError('Choose an active destination application.')


def _remember(c, source, target, host, protocol, actor):
    c.execute('INSERT INTO dependency_corrections(source_application_id,destination,protocol,target_application_id,updated_by) VALUES(?,?,?,?,?) ON CONFLICT(source_application_id,destination,protocol) DO UPDATE SET target_application_id=excluded.target_application_id,updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP',(source,host,protocol,target,actor))


def move_dependency(source, rule_id, target, actor):
    c=connect()
    try:
        c.execute('BEGIN IMMEDIATE');_authorize(c,source,target,actor)
        row=c.execute("SELECT ar.*,r.destination,r.protocol,r.rule_type FROM application_rules ar JOIN rules r ON r.id=ar.rule_id WHERE ar.application_id=? AND ar.rule_id=? AND r.status='active'",(source,rule_id)).fetchone()
        if not row or row['rule_type']!='domain':raise ValueError('Active domain dependency not found.')
        c.execute("""INSERT INTO application_rules(application_id,rule_id,required,source,confidence,metadata_json,enabled)
            VALUES(?,?,?,'manual-transfer',?,?,?) ON CONFLICT(application_id,rule_id) DO UPDATE SET enabled=MAX(application_rules.enabled,excluded.enabled)""",(target,rule_id,row['required'],row['confidence'],row['metadata_json'],row['enabled']))
        c.execute('DELETE FROM application_rules WHERE application_id=? AND rule_id=?',(source,rule_id))
        c.execute('UPDATE applications SET pending=1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id IN (?,?)',(actor,source,target))
        _remember(c,source,target,row['destination'],row['protocol'],actor);c.commit()
    except Exception:c.rollback();raise
    finally:c.close()
    audit(actor,'DEPENDENCY_MOVE','SAVED','rule',rule_id,details_json=json.dumps({'from':source,'to':target}))


def move_candidate(candidate_id, target, actor):
    c=connect()
    try:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute("SELECT * FROM application_dependency_candidates WHERE id=? AND status='pending'",(candidate_id,)).fetchone()
        if not row:raise ValueError('Pending candidate not found.')
        source=row['application_id'];_authorize(c,source,target,actor)
        other=c.execute('SELECT * FROM application_dependency_candidates WHERE application_id=? AND destination=? AND protocol=?',(target,row['destination'],row['protocol'])).fetchone()
        if not other:
            c.execute("UPDATE application_dependency_candidates SET application_id=?,confidence='low',confidence_score=MIN(confidence_score,40),recommendation='review' WHERE id=?",(target,candidate_id))
        else:
            if other['status']=='pending':
                for client in c.execute('SELECT * FROM application_dependency_candidate_clients WHERE candidate_id=?',(candidate_id,)).fetchall():
                    c.execute('INSERT INTO application_dependency_candidate_clients(candidate_id,client_ip,first_seen_at,last_seen_at) VALUES(?,?,?,?) ON CONFLICT(candidate_id,client_ip) DO UPDATE SET first_seen_at=MIN(first_seen_at,excluded.first_seen_at),last_seen_at=MAX(last_seen_at,excluded.last_seen_at)',(other['id'],client['client_ip'],client['first_seen_at'],client['last_seen_at']))
                c.execute('UPDATE application_dependency_candidates SET request_count=MAX(request_count,?),last_seen_at=MAX(last_seen_at,?),client_count=(SELECT COUNT(*) FROM application_dependency_candidate_clients WHERE candidate_id=?) WHERE id=?',(row['request_count'],row['last_seen_at'],other['id'],other['id']))
            c.execute("UPDATE application_dependency_candidates SET status='ignored',reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?",(actor,candidate_id))
        _remember(c,source,target,row['destination'],row['protocol'],actor);c.commit()
    except Exception:c.rollback();raise
    finally:c.close()
    audit(actor,'DEPENDENCY_CANDIDATE_MOVE','SUCCESS','dependency_candidate',candidate_id,details_json=json.dumps({'from':source,'to':target}))
