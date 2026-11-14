import re
from app.db import connect

SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(value):
    s=SLUG_RE.sub("-",value.strip().lower()).strip("-")
    return s[:80] or "application"


def _normalize_application_source(seed_domain,source_kind,source_ref,auto_monitor):
    from urllib.parse import urlparse
    from app.security import normalize_domain
    allowed={"manual","builtin","official_api","official_url","observed"}
    if source_kind not in allowed:
        raise ValueError("Invalid application source type.")
    seed=(seed_domain or "").strip()
    if seed:
        seed=normalize_domain(seed,allow_wildcard=False)
    ref=(source_ref or "").strip() or None
    if source_kind=="official_url":
        if not ref:
            raise ValueError("An official HTTPS source URL is required.")
        p=urlparse(ref)
        if p.scheme!="https" or not p.hostname or p.username or p.password or p.port not in (None,443):
            raise ValueError("Official source must be a public HTTPS URL on port 443 without embedded credentials.")
    if auto_monitor and source_kind not in ("official_api","official_url"):
        raise ValueError("Automatic source monitoring is available only for official API/HTTPS sources.")
    return seed or None,ref,bool(auto_monitor)


def list_applications(include_deleted=False):
    c=connect()
    try:
        where="" if include_deleted else "WHERE a.status!='deleted'"
        rows=c.execute(f"""SELECT a.*,
          (SELECT COUNT(*) FROM application_rules ar WHERE ar.application_id=a.id AND ar.enabled=1) dependency_count,
          (SELECT COUNT(*) FROM application_networks an WHERE an.application_id=a.id) direct_network_count,
          (SELECT COUNT(DISTINCT pgn.network_id) FROM policy_group_applications pga
             JOIN policy_groups pg ON pg.id=pga.group_id AND pg.status='active'
             JOIN policy_group_networks pgn ON pgn.group_id=pg.id
             WHERE pga.application_id=a.id) group_network_count
          FROM applications a {where} ORDER BY a.system_managed DESC,a.name""").fetchall()
        out=[]
        for r in rows:
            d=dict(r)
            d["networks"]=[dict(x) for x in c.execute("""SELECT n.* FROM networks n JOIN application_networks an ON an.network_id=n.id
                WHERE an.application_id=? ORDER BY COALESCE(n.vlan_id,99999),n.name""",(r["id"],))]
            d["groups"]=[dict(x) for x in c.execute("""SELECT pg.* FROM policy_groups pg JOIN policy_group_applications pga ON pga.group_id=pg.id
                WHERE pga.application_id=? AND pg.status!='deleted' ORDER BY pg.name""",(r["id"],))]
            out.append(d)
        return out
    finally:c.close()


def get_application(application_id):
    c=connect()
    try:
        r=c.execute("SELECT * FROM applications WHERE id=? AND status!='deleted'",(application_id,)).fetchone()
        if not r:return None
        d=dict(r)
        d["network_ids"]=[x["network_id"] for x in c.execute("SELECT network_id FROM application_networks WHERE application_id=?",(application_id,))]
        d["group_ids"]=[x["group_id"] for x in c.execute("SELECT group_id FROM policy_group_applications WHERE application_id=?",(application_id,))]
        d["networks"]=[dict(x) for x in c.execute("""SELECT n.* FROM networks n JOIN application_networks an ON an.network_id=n.id
            WHERE an.application_id=? ORDER BY COALESCE(n.vlan_id,99999),n.name""",(application_id,))]
        d["groups"]=[dict(x) for x in c.execute("""SELECT pg.* FROM policy_groups pg JOIN policy_group_applications pga ON pga.group_id=pg.id
            WHERE pga.application_id=? AND pg.status!='deleted' ORDER BY pg.name""",(application_id,))]
        d["dependencies"]=[dict(x) for x in c.execute("""SELECT r.*,ar.required,ar.source,ar.confidence,ar.metadata_json,ar.enabled dependency_enabled
             FROM rules r JOIN application_rules ar ON ar.rule_id=r.id WHERE ar.application_id=? AND r.status!='deleted'
             ORDER BY r.rule_type,r.destination""",(application_id,))]
        return d
    finally:c.close()


def create_application(name,provider,description,seed_domain,source_kind,source_ref,auto_monitor,actor,system_managed=False):
    name=name.strip()
    if len(name)<2:raise ValueError("Application name is required.")
    seed_domain,source_ref,auto_monitor=_normalize_application_source(seed_domain,source_kind,source_ref,auto_monitor)
    slug=slugify(name)
    c=connect()
    try:
        base=slug;i=2
        while c.execute("SELECT 1 FROM applications WHERE slug=?",(slug,)).fetchone():
            slug=f"{base}-{i}";i+=1
        cur=c.execute("""INSERT INTO applications(name,slug,provider,description,seed_domain,source_kind,source_ref,system_managed,status,pending,auto_monitor,created_by,updated_by)
            VALUES(?,?,?,?,?,?,?,?, 'active',0,?,?,?)""",
            (name,slug,provider.strip() or None,description.strip() or None,seed_domain,source_kind,source_ref,1 if system_managed else 0,1 if auto_monitor else 0,actor,actor))
        c.commit();return cur.lastrowid
    except Exception:c.rollback();raise
    finally:c.close()


def update_application(application_id,name,provider,description,seed_domain,source_kind,source_ref,auto_monitor,network_ids,actor,policy_group_ids=None):
    c=connect()
    try:
        a=c.execute("SELECT * FROM applications WHERE id=? AND status!='deleted'",(application_id,)).fetchone()
        if not a:raise ValueError("Application policy not found.")
        if len(name.strip())<2:raise ValueError("Application name is required.")
        if c.execute("SELECT 1 FROM applications WHERE name=? AND id!=? AND status!='deleted'",(name.strip(),application_id)).fetchone():raise ValueError("Another application uses this name.")
        seed_domain,source_ref,auto_monitor=_normalize_application_source(seed_domain,source_kind,source_ref,auto_monitor)
        old_networks={x['network_id'] for x in c.execute("SELECT network_id FROM application_networks WHERE application_id=?",(application_id,))}
        old_groups={x['group_id'] for x in c.execute("SELECT group_id FROM policy_group_applications WHERE application_id=?",(application_id,))}
        new_networks={int(x) for x in (network_ids or [])}
        new_groups=old_groups if policy_group_ids is None else {int(x) for x in (policy_group_ids or [])}
        from app.services.resource_permissions import require_application_write,check_profile_membership_changes
        require_application_write(c,application_id,actor)
        check_profile_membership_changes(c,old_groups,new_groups,actor)
        policy_changed=(old_networks!=new_networks or old_groups!=new_groups)
        c.execute("""UPDATE applications SET name=?,provider=?,description=?,seed_domain=?,source_kind=?,source_ref=?,auto_monitor=?,
                  pending=CASE WHEN ? THEN 1 ELSE pending END,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                  (name.strip(),provider.strip() or None,description.strip() or None,seed_domain,source_kind,source_ref,1 if auto_monitor else 0,1 if policy_changed else 0,actor,application_id))
        c.execute("DELETE FROM application_networks WHERE application_id=?",(application_id,))
        for nid in new_networks:c.execute("INSERT INTO application_networks VALUES(?,?)",(application_id,nid))
        if policy_group_ids is not None:
            affected=old_groups|new_groups
            c.execute("DELETE FROM policy_group_applications WHERE application_id=?",(application_id,))
            for gid in new_groups:c.execute("INSERT INTO policy_group_applications(group_id,application_id) VALUES(?,?)",(gid,application_id))
            if policy_changed:
                for gid in affected:c.execute("UPDATE policy_groups SET pending=1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(actor,gid))
        c.commit()
    except Exception:c.rollback();raise
    finally:c.close()


def set_application_status(application_id,status,actor):
    if status not in("active","disabled","deleted"):raise ValueError("Invalid application status.")
    c=connect()
    try:
        row=c.execute("SELECT status FROM applications WHERE id=? AND status!='deleted'",(application_id,)).fetchone()
        if not row:raise ValueError("Application not found.")
        changed=row['status']!=status
        c.execute("UPDATE applications SET status=?,pending=CASE WHEN ? THEN 1 ELSE pending END,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(status,1 if changed else 0,actor,application_id));c.commit()
    finally:c.close()


def delete_application(application_id,actor):
    c=connect()
    try:
        app=c.execute("SELECT * FROM applications WHERE id=? AND status!='deleted'",(application_id,)).fetchone()
        if not app:raise ValueError("Application not found.")
        groups={x["group_id"] for x in c.execute("SELECT group_id FROM policy_group_applications WHERE application_id=?",(application_id,))}
        c.execute("BEGIN IMMEDIATE")
        c.execute("DELETE FROM application_networks WHERE application_id=?",(application_id,))
        c.execute("DELETE FROM policy_group_applications WHERE application_id=?",(application_id,))
        for gid in groups:
            c.execute("UPDATE policy_groups SET pending=1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(actor,gid))
        c.execute("""UPDATE applications
          SET status='deleted',pending=1,name=?,slug=?,updated_by=?,updated_at=CURRENT_TIMESTAMP
          WHERE id=?""",(f"{app['name']} [deleted {application_id}]",f"{app['slug']}-deleted-{application_id}",actor,application_id))
        c.commit()
    except Exception:
        c.rollback();raise
    finally:c.close()


def attach_rule_to_application(application_id,rule_id,source="manual",confidence="high",required=True,metadata_json=None):
    c=connect()
    try:
        c.execute("INSERT OR REPLACE INTO application_rules(application_id,rule_id,required,source,confidence,metadata_json,enabled) VALUES(?,?,?,?,?,?,1)",
                  (application_id,rule_id,1 if required else 0,source,confidence,metadata_json));c.execute("UPDATE applications SET pending=1,updated_at=CURRENT_TIMESTAMP WHERE id=?",(application_id,));c.commit()
    finally:c.close()


def detach_rule_from_application(application_id,rule_id):
    c=connect()
    try:c.execute("DELETE FROM application_rules WHERE application_id=? AND rule_id=?",(application_id,rule_id));c.execute("UPDATE applications SET pending=1,updated_at=CURRENT_TIMESTAMP WHERE id=?",(application_id,));c.commit()
    finally:c.close()


def list_policy_groups(include_deleted=False):
    c=connect()
    try:
        where="" if include_deleted else "WHERE pg.status!='deleted'"
        rows=c.execute(f"""SELECT pg.*,
          (SELECT COUNT(*) FROM policy_group_applications x WHERE x.group_id=pg.id) application_count,
          (SELECT COUNT(*) FROM policy_group_rules x WHERE x.group_id=pg.id) rule_count,
          (SELECT COUNT(*) FROM policy_group_networks x WHERE x.group_id=pg.id) network_count
          FROM policy_groups pg {where} ORDER BY pg.system_managed DESC,pg.name""").fetchall()
        out=[]
        for r in rows:
            d=dict(r)
            d["networks"]=[dict(x) for x in c.execute("""SELECT n.* FROM networks n JOIN policy_group_networks pgn ON pgn.network_id=n.id
                WHERE pgn.group_id=? ORDER BY COALESCE(n.vlan_id,99999),n.name""",(r["id"],))]
            d["applications"]=[dict(x) for x in c.execute("""SELECT a.* FROM applications a JOIN policy_group_applications pga ON pga.application_id=a.id
                WHERE pga.group_id=? AND a.status!='deleted' ORDER BY a.name""",(r["id"],))]
            out.append(d)
        return out
    finally:c.close()


def get_policy_group(group_id):
    c=connect()
    try:
        r=c.execute("SELECT * FROM policy_groups WHERE id=?",(group_id,)).fetchone()
        if not r:return None
        d=dict(r)
        d["application_ids"]=[x["application_id"] for x in c.execute("SELECT application_id FROM policy_group_applications WHERE group_id=?",(group_id,))]
        d["rule_ids"]=[x["rule_id"] for x in c.execute("SELECT rule_id FROM policy_group_rules WHERE group_id=?",(group_id,))]
        d["network_ids"]=[x["network_id"] for x in c.execute("SELECT network_id FROM policy_group_networks WHERE group_id=?",(group_id,))]
        return d
    finally:c.close()


def create_policy_group(name,description,application_ids,rule_ids,network_ids,actor,c=None):
    name=name.strip()
    if len(name)<2:raise ValueError("Policy group name is required.")
    apps={int(x) for x in (application_ids or [])};rules={int(x) for x in (rule_ids or [])};nets={int(x) for x in (network_ids or [])}
    effective=bool(nets and (apps or rules))
    own=c is None
    c=c or connect()
    try:
        if c.execute("SELECT 1 FROM policy_groups WHERE name=? AND status!='deleted'",(name,)).fetchone():raise ValueError("Policy group already exists.")
        cur=c.execute("INSERT INTO policy_groups(name,description,status,pending,created_by,updated_by) VALUES(?,?,'active',?,?,?)",(name,description.strip() or None,1 if effective else 0,actor,actor));gid=cur.lastrowid
        _replace_group_members(c,gid,apps,rules,nets)
        if own:c.commit()
        return gid
    except Exception:
        if own:c.rollback()
        raise
    finally:
        if own:c.close()


def update_policy_group(group_id,name,description,application_ids,rule_ids,network_ids,actor,c=None):
    own=c is None
    c=c or connect()
    try:
        if not c.execute("SELECT 1 FROM policy_groups WHERE id=? AND status!='deleted'",(group_id,)).fetchone():raise ValueError("Policy group not found.")
        if c.execute("SELECT 1 FROM policy_groups WHERE name=? AND id!=? AND status!='deleted'",(name.strip(),group_id)).fetchone():raise ValueError("Another policy group uses this name.")
        old_apps={x['application_id'] for x in c.execute("SELECT application_id FROM policy_group_applications WHERE group_id=?",(group_id,))}
        old_rules={x['rule_id'] for x in c.execute("SELECT rule_id FROM policy_group_rules WHERE group_id=?",(group_id,))}
        old_nets={x['network_id'] for x in c.execute("SELECT network_id FROM policy_group_networks WHERE group_id=?",(group_id,))}
        new_apps={int(x) for x in (application_ids or [])};new_rules={int(x) for x in (rule_ids or [])};new_nets={int(x) for x in (network_ids or [])}
        policy_changed=(old_apps!=new_apps or old_rules!=new_rules or old_nets!=new_nets)
        c.execute("UPDATE policy_groups SET name=?,description=?,pending=CASE WHEN ? THEN 1 ELSE pending END,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(name.strip(),description.strip() or None,1 if policy_changed else 0,actor,group_id))
        _replace_group_members(c,group_id,new_apps,new_rules,new_nets)
        if own:c.commit()
    except Exception:
        if own:c.rollback()
        raise
    finally:
        if own:c.close()


def _replace_group_members(c,gid,application_ids,rule_ids,network_ids):
    c.execute("DELETE FROM policy_group_applications WHERE group_id=?",(gid,));c.execute("DELETE FROM policy_group_rules WHERE group_id=?",(gid,));c.execute("DELETE FROM policy_group_networks WHERE group_id=?",(gid,))
    for aid in {int(x) for x in (application_ids or [])}:c.execute("INSERT INTO policy_group_applications VALUES(?,?)",(gid,aid))
    for rid in {int(x) for x in (rule_ids or [])}:c.execute("INSERT INTO policy_group_rules VALUES(?,?)",(gid,rid))
    for nid in {int(x) for x in (network_ids or [])}:c.execute("INSERT INTO policy_group_networks VALUES(?,?)",(gid,nid))


def set_policy_group_status(group_id,status,actor):
    if status=="deleted":return delete_policy_group(group_id,actor)
    if status not in("active","disabled","deleted"):raise ValueError("Invalid group status.")
    c=connect()
    try:
        row=c.execute("SELECT status FROM policy_groups WHERE id=?",(group_id,)).fetchone()
        if not row or row['status']=='deleted':raise ValueError("Policy group not found or deleted.")
        changed=row['status']!=status
        c.execute("UPDATE policy_groups SET status=?,pending=CASE WHEN ? THEN 1 ELSE pending END,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(status,1 if changed else 0,actor,group_id));c.commit()
    finally:c.close()


def set_network_groups(network_id,group_ids):
    c=connect()
    try:
        c.execute("DELETE FROM policy_group_networks WHERE network_id=?",(network_id,))
        for gid in {int(x) for x in (group_ids or [])}:c.execute("INSERT INTO policy_group_networks(group_id,network_id) VALUES(?,?)",(gid,network_id))
        c.commit()
    finally:c.close()


def network_group_ids(network_id):
    c=connect()
    try:return [x["group_id"] for x in c.execute("SELECT group_id FROM policy_group_networks WHERE network_id=?",(network_id,))]
    finally:c.close()


def effective_network_ids_for_rule(c,rule_id,scope_mode="selected"):
    if scope_mode=="all_proxy":
        return {x["id"] for x in c.execute("SELECT id FROM networks WHERE enabled=1 AND proxy_enabled=1")}
    ids={x["network_id"] for x in c.execute("SELECT network_id FROM rule_networks WHERE rule_id=?",(rule_id,))}
    # Direct application scopes.
    ids.update(x["network_id"] for x in c.execute("""SELECT DISTINCT an.network_id FROM application_rules ar
        JOIN applications a ON a.id=ar.application_id AND a.status='active'
        JOIN application_networks an ON an.application_id=a.id WHERE ar.rule_id=? AND ar.enabled=1""",(rule_id,)))
    # Networks inherited from groups containing the atomic rule.
    ids.update(x["network_id"] for x in c.execute("""SELECT DISTINCT pgn.network_id FROM policy_group_rules pgr
        JOIN policy_groups pg ON pg.id=pgr.group_id AND pg.status='active'
        JOIN policy_group_networks pgn ON pgn.group_id=pg.id WHERE pgr.rule_id=?""",(rule_id,)))
    # Networks inherited from groups containing an application which contains the rule.
    ids.update(x["network_id"] for x in c.execute("""SELECT DISTINCT pgn.network_id FROM application_rules ar
        JOIN applications a ON a.id=ar.application_id AND a.status='active' AND ar.enabled=1
        JOIN policy_group_applications pga ON pga.application_id=a.id
        JOIN policy_groups pg ON pg.id=pga.group_id AND pg.status='active'
        JOIN policy_group_networks pgn ON pgn.group_id=pg.id WHERE ar.rule_id=?""",(rule_id,)))
    return ids


def create_application_dependency(application_id,kind,destination,protocol,actor,reason="Manual application dependency"):
    import hashlib
    from app.security import normalize_domain,normalize_ip
    kind=kind.lower();protocol=protocol.upper()
    if kind not in('domain','ip'):raise ValueError('Dependency type must be domain or ip.')
    if protocol not in('HTTP','HTTPS','BOTH'):raise ValueError('Invalid protocol.')
    destination=normalize_domain(destination) if kind=='domain' else normalize_ip(destination)
    c=connect()
    try:
        c.execute('BEGIN IMMEDIATE')
        from app.services.resource_permissions import require_application_write
        app=require_application_write(c,application_id,actor)
        existing=c.execute("SELECT * FROM rules WHERE rule_type=? AND destination=? AND status!='deleted'",(kind,destination)).fetchone()
        if existing:
            rid=existing['id']
            # Destination objects are shared across applications/profiles. Never
            # widen the global protocol implicitly from one application edit.
            if existing['protocol'] != protocol and existing['protocol'] != 'BOTH':
                raise ValueError(
                    f"Protocol conflict for shared destination {destination}: existing rule is {existing['protocol']}, requested {protocol}. "
                    "Review the shared destination before widening its protocol globally."
                )
        else:
            slug='app-'+app['slug'];c.execute("INSERT OR IGNORE INTO categories(name,slug,system_managed) VALUES(?,?,?)",('Application: '+app['name'],slug,app['system_managed']));cid=c.execute("SELECT id FROM categories WHERE slug=?",(slug,)).fetchone()['id'];mgmt='system' if app['system_managed'] else 'custom';fp=hashlib.sha256(f"{kind}|{destination}|{protocol}|{mgmt}|{cid}".encode()).hexdigest()
            cur=c.execute("""INSERT INTO rules(rule_type,action,destination,protocol,category_id,management_type,status,pending,reason,fingerprint,created_by,updated_by,scope_mode)
                VALUES(?,'ALLOW',?,?,?,?, 'active',1,?,?,?,?,'selected')""",(kind,destination,protocol,cid,mgmt,reason,fp,actor,actor));rid=cur.lastrowid
        c.execute("INSERT OR REPLACE INTO application_rules(application_id,rule_id,required,source,confidence,enabled) VALUES(?,?,1,'manual','high',1)",(application_id,rid));c.execute("UPDATE applications SET pending=1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(actor,application_id));c.commit();return rid
    except Exception:c.rollback();raise
    finally:c.close()


def set_application_dependency_status(application_id,rule_id,status,actor):
    """Change membership state inside one Application Policy only.

    Atomic rules may be shared by multiple applications/profiles. Disabling a
    dependency here must therefore never globally disable the underlying rule.
    """
    if status not in ("active","disabled","deleted"):
        raise ValueError("Invalid dependency status.")
    c=connect()
    try:
        rel=c.execute("SELECT 1 FROM application_rules WHERE application_id=? AND rule_id=?",(application_id,rule_id)).fetchone()
        if not rel:
            raise ValueError("Dependency is not attached to this application.")
        c.execute("BEGIN IMMEDIATE")
        if status=="deleted":
            c.execute("DELETE FROM application_rules WHERE application_id=? AND rule_id=?",(application_id,rule_id))
        else:
            c.execute("UPDATE application_rules SET enabled=? WHERE application_id=? AND rule_id=?",(1 if status=="active" else 0,application_id,rule_id))
        c.execute("UPDATE applications SET pending=1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(actor,application_id))
        c.commit()
    except Exception:
        c.rollback();raise
    finally:
        c.close()


def delete_policy_group(group_id,actor):
    c=connect()
    try:
        row=c.execute("SELECT * FROM policy_groups WHERE id=? AND status!='deleted'",(group_id,)).fetchone()
        if not row:raise ValueError('Access profile not found.')
        c.execute('BEGIN IMMEDIATE')
        for table in ('policy_group_applications','policy_group_rules','policy_group_networks'):
            c.execute('DELETE FROM '+table+' WHERE group_id=?',(group_id,))
        c.execute("UPDATE policy_groups SET name=?,status='deleted',pending=1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(row['name']+' [deleted '+str(group_id)+']',actor,group_id))
        c.commit()
    except Exception:c.rollback();raise
    finally:c.close()
