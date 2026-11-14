import hashlib
import ipaddress
from app.db import connect
from app.security import normalize_domain, normalize_ip, normalize_expiration


def list_networks(enabled_only=True):
    c=connect()
    try:
        q="SELECT * FROM networks"
        if enabled_only:q+=" WHERE enabled=1 AND proxy_enabled=1"
        q+=" ORDER BY COALESCE(vlan_id,99999),name,cidr"
        rows=[dict(r) for r in c.execute(q)]
        for d in rows:
            d["policy_group_ids"]=[x["group_id"] for x in c.execute("SELECT group_id FROM policy_group_networks WHERE network_id=?",(d["id"],))]
            d["policy_groups"]=[dict(x) for x in c.execute("""SELECT pg.* FROM policy_groups pg JOIN policy_group_networks pgn ON pgn.group_id=pg.id
                WHERE pgn.network_id=? AND pg.status!='deleted' ORDER BY pg.name""",(d["id"],))]
        return rows
    finally:c.close()


def get_network(network_id):
    c=connect()
    try:
        r=c.execute("SELECT * FROM networks WHERE id=?",(network_id,)).fetchone()
        if not r:return None
        d=dict(r);d["policy_group_ids"]=[x["group_id"] for x in c.execute("SELECT group_id FROM policy_group_networks WHERE network_id=?",(network_id,))]
        return d
    finally:c.close()


def _validate_network(name,cidr,vlan_id=None):
    name=name.strip()
    if len(name)<2:raise ValueError("Network name is required.")
    if any(ord(ch)<32 or ord(ch)==127 for ch in name):raise ValueError("Network name cannot contain control characters.")
    try:net=ipaddress.ip_network(cidr.strip(),strict=False)
    except ValueError as exc:raise ValueError("Invalid IPv4 network/CIDR.") from exc
    if net.version!=4:raise ValueError("Only IPv4 network scopes are supported.")
    vlan_id=int(vlan_id) if str(vlan_id or "").strip() else None
    if vlan_id is not None and not 1<=vlan_id<=4094:raise ValueError("VLAN ID must be between 1 and 4094.")
    return name,str(net),vlan_id,net


def create_network(name,cidr,actor,reason,change_reference="",vlan_id=None,description="",proxy_enabled=True,clone_from_network_id=None,policy_group_ids=None,c=None):
    name,cidr,vlan_id,net=_validate_network(name,cidr,vlan_id)
    if len(reason.strip())<3:raise ValueError("A change reason is required.")
    own=c is None
    c=c or connect()
    try:
        if c.execute("SELECT 1 FROM networks WHERE name=? OR cidr=?",(name,cidr)).fetchone():raise ValueError("A network with this name or CIDR already exists.")
        if vlan_id is not None and c.execute("SELECT 1 FROM networks WHERE vlan_id=?",(vlan_id,)).fetchone():raise ValueError("This VLAN ID is already assigned to another network policy.")
        for row in c.execute("SELECT cidr FROM networks"):
            if net.overlaps(ipaddress.ip_network(row["cidr"],strict=False)):raise ValueError(f"Network overlaps existing source scope {row['cidr']}.")
        cur=c.execute("""INSERT INTO networks(name,vlan_id,cidr,proxy_enabled,enabled,system_managed,pending,reason,change_reference,description,created_by,updated_by)
            VALUES(?,?,?,?,1,0,1,?,?,?,?,?)""",(name,vlan_id,cidr,1 if proxy_enabled else 0,reason.strip(),change_reference or None,description.strip() or None,actor,actor))
        nid=cur.lastrowid;cloned=0
        if clone_from_network_id:
            src=int(clone_from_network_id)
            if not c.execute("SELECT 1 FROM networks WHERE id=?",(src,)).fetchone():raise ValueError("Clone source network not found.")
            for x in c.execute("SELECT rule_id FROM rule_networks WHERE network_id=?",(src,)):
                c.execute("INSERT OR IGNORE INTO rule_networks(rule_id,network_id) VALUES(?,?)",(x["rule_id"],nid));c.execute("UPDATE rules SET pending=1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(actor,x["rule_id"]));cloned+=1
            for x in c.execute("SELECT application_id FROM application_networks WHERE network_id=?",(src,)):c.execute("INSERT OR IGNORE INTO application_networks VALUES(?,?)",(x["application_id"],nid))
            if policy_group_ids is None:
                for x in c.execute("SELECT group_id FROM policy_group_networks WHERE network_id=?",(src,)):c.execute("INSERT OR IGNORE INTO policy_group_networks VALUES(?,?)",(x["group_id"],nid))
        for gid in {int(x) for x in (policy_group_ids or [])}:c.execute("INSERT OR IGNORE INTO policy_group_networks(group_id,network_id) VALUES(?,?)",(gid,nid))
        if own:c.commit()
        return {"id":nid,"name":name,"vlan_id":vlan_id,"cidr":cidr,"proxy_enabled":bool(proxy_enabled),"cloned_rules":cloned,"policy_groups":len(set(policy_group_ids or []))}
    except Exception:
        if own:c.rollback()
        raise
    finally:
        if own:c.close()


def update_network(network_id,name,cidr,actor,reason,change_reference="",vlan_id=None,description="",proxy_enabled=True,policy_group_ids=None):
    name,cidr,vlan_id,net=_validate_network(name,cidr,vlan_id)
    if len(reason.strip())<3:raise ValueError("A change reason is required.")
    c=connect()
    try:
        if not c.execute("SELECT 1 FROM networks WHERE id=?",(network_id,)).fetchone():raise ValueError("Network not found.")
        if c.execute("SELECT 1 FROM networks WHERE (name=? OR cidr=?) AND id!=?",(name,cidr,network_id)).fetchone():raise ValueError("Another network already uses this name or CIDR.")
        if vlan_id is not None and c.execute("SELECT 1 FROM networks WHERE vlan_id=? AND id!=?",(vlan_id,network_id)).fetchone():raise ValueError("This VLAN ID is already assigned to another network policy.")
        for row in c.execute("SELECT cidr FROM networks WHERE id!=?",(network_id,)):
            if net.overlaps(ipaddress.ip_network(row["cidr"],strict=False)):raise ValueError(f"Network overlaps existing source scope {row['cidr']}.")
        c.execute("""UPDATE networks SET name=?,vlan_id=?,cidr=?,proxy_enabled=?,pending=1,reason=?,change_reference=?,description=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                  (name,vlan_id,cidr,1 if proxy_enabled else 0,reason.strip(),change_reference or None,description.strip() or None,actor,network_id))
        if policy_group_ids is not None:
            c.execute("DELETE FROM policy_group_networks WHERE network_id=?",(network_id,))
            for gid in {int(x) for x in policy_group_ids}:c.execute("INSERT INTO policy_group_networks(group_id,network_id) VALUES(?,?)",(gid,network_id))
        c.commit();return {"id":network_id,"name":name,"vlan_id":vlan_id,"cidr":cidr,"proxy_enabled":bool(proxy_enabled)}
    except Exception:c.rollback();raise
    finally:c.close()


def set_network_enabled(network_id,enabled,actor,reason=""):
    c=connect()
    try:
        if not c.execute("SELECT 1 FROM networks WHERE id=?",(network_id,)).fetchone():raise ValueError("Network not found.")
        c.execute("UPDATE networks SET enabled=?,pending=1,reason=COALESCE(NULLIF(?,''),reason),updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(1 if enabled else 0,reason.strip(),actor,network_id));c.commit()
    finally:c.close()


def delete_network(network_id,actor):
    c=connect()
    try:
        if not c.execute("SELECT 1 FROM networks WHERE id=?",(network_id,)).fetchone():raise ValueError("Network not found.")
        refs=c.execute("""SELECT
          (SELECT COUNT(*) FROM rule_networks WHERE network_id=?)+
          (SELECT COUNT(*) FROM application_networks WHERE network_id=?)+
          (SELECT COUNT(*) FROM policy_group_networks WHERE network_id=?) c""",(network_id,network_id,network_id)).fetchone()["c"]
        if refs:raise ValueError("Network is still assigned to rules, applications or policy groups. Remove assignments first or disable it.")
        c.execute("DELETE FROM networks WHERE id=?",(network_id,));c.commit()
    finally:c.close()


def list_categories(system_only=False):
    c=connect()
    try:
        q="SELECT * FROM categories"+(" WHERE system_managed=1" if system_only else "")+" ORDER BY name"
        return [dict(r) for r in c.execute(q)]
    finally:c.close()


def list_rules(rule_type=None,management=None,include_deleted=False,category_slug=None,standalone_only=False):
    c=connect()
    try:
        wh=[];pa=[]
        if rule_type:wh.append("r.rule_type=?");pa.append(rule_type)
        if management:wh.append("r.management_type=?");pa.append(management)
        if category_slug:wh.append("c.slug=?");pa.append(category_slug)
        if standalone_only:wh.append("NOT EXISTS(SELECT 1 FROM application_rules arx WHERE arx.rule_id=r.id)")
        if not include_deleted:wh.append("r.status!='deleted'")
        clause=(" WHERE "+" AND ".join(wh)) if wh else ""
        rows=c.execute(f"""SELECT r.*,c.name category_name,c.slug category_slug,c.system_managed category_system
          FROM rules r LEFT JOIN categories c ON c.id=r.category_id {clause}
          ORDER BY CASE r.management_type WHEN 'custom' THEN 0 ELSE 1 END,c.name,r.destination""",pa).fetchall()
        out=[]
        for r in rows:
            d=dict(r)
            d["networks"]=[dict(x) for x in c.execute("""SELECT n.* FROM networks n JOIN rule_networks rn ON rn.network_id=n.id WHERE rn.rule_id=? ORDER BY n.name,n.id""",(r["id"],))]
            d["applications"]=[dict(x) for x in c.execute("""SELECT a.* FROM applications a JOIN application_rules ar ON ar.application_id=a.id WHERE ar.rule_id=? AND a.status!='deleted' ORDER BY a.name""",(r["id"],))]
            d["policy_groups"]=[dict(x) for x in c.execute("""SELECT pg.* FROM policy_groups pg JOIN policy_group_rules pgr ON pgr.group_id=pg.id WHERE pgr.rule_id=? AND pg.status!='deleted' ORDER BY pg.name""",(r["id"],))]
            out.append(d)
        return out
    finally:c.close()


def get_rule(rule_id):
    c=connect()
    try:
        r=c.execute("""SELECT r.*,c.name category_name,c.slug category_slug,c.system_managed category_system FROM rules r LEFT JOIN categories c ON c.id=r.category_id WHERE r.id=?""",(rule_id,)).fetchone()
        if not r:return None
        d=dict(r);d["network_ids"]=[x["network_id"] for x in c.execute("SELECT network_id FROM rule_networks WHERE rule_id=?",(rule_id,))]
        d["policy_group_ids"]=[x["group_id"] for x in c.execute("SELECT group_id FROM policy_group_rules WHERE rule_id=?",(rule_id,))]
        return d
    finally:c.close()


def _category(c,kind):
    slug,name=("business","Business") if kind=="domain" else ("explicit-ip","Explicit IP")
    c.execute("INSERT OR IGNORE INTO categories(name,slug,system_managed) VALUES(?,?,0)",(name,slug));return c.execute("SELECT id FROM categories WHERE slug=?",(slug,)).fetchone()["id"]


def _system_category(c,category_slug):
    row=c.execute("SELECT id FROM categories WHERE slug=? AND system_managed=1",(category_slug,)).fetchone()
    if not row:raise ValueError("Invalid protected system category.")
    return row["id"]


def _fingerprint(kind,destination,protocol,management,category_id):return hashlib.sha256(f"{kind}|{destination}|{protocol}|{management}|{category_id}".encode()).hexdigest()


def create_rule(kind,destination,protocol,network_ids,actor,reason,change_reference="",expires_at="",management_type="custom",category_slug=None,scope_mode="selected",policy_group_ids=None):
    expires_at=normalize_expiration(expires_at)
    destination=normalize_domain(destination) if kind=="domain" else normalize_ip(destination);resolved=[]
    protocol=protocol.upper()
    if protocol not in("HTTP","HTTPS","BOTH"):raise ValueError("Invalid protocol.")
    if scope_mode not in("selected","all_proxy"):raise ValueError("Invalid scope mode.")
    if scope_mode=="selected" and not network_ids and not policy_group_ids:raise ValueError("Select at least one network scope, an Access Profile, or All Proxy Networks.")
    if len(reason.strip())<3:raise ValueError("A change reason is required.")
    if management_type not in("custom","system"):raise ValueError("Invalid management type.")
    c=connect()
    try:
        if c.execute("SELECT 1 FROM rules WHERE rule_type=? AND destination=? AND status!='deleted'",(kind,destination)).fetchone():raise ValueError("A rule for this destination already exists.")
        cid=_system_category(c,category_slug) if management_type=="system" else _category(c,kind);fp=_fingerprint(kind,destination,protocol,management_type,cid)
        cur=c.execute("""INSERT INTO rules(rule_type,destination,protocol,category_id,management_type,status,pending,reason,change_reference,expires_at,fingerprint,created_by,updated_by,scope_mode)
          VALUES(?,?,?,?,?,'active',1,?,?,?,?,?,?,?)""",(kind,destination,protocol,cid,management_type,reason.strip(),change_reference or None,expires_at or None,fp,actor,actor,scope_mode));rid=cur.lastrowid
        if scope_mode=="selected":
            for nid in {int(x) for x in network_ids}:c.execute("INSERT INTO rule_networks VALUES(?,?)",(rid,nid))
            for gid in {int(x) for x in (policy_group_ids or [])}:c.execute("INSERT INTO policy_group_rules(group_id,rule_id) VALUES(?,?)",(gid,rid))
        c.commit();return {"id":rid,"destination":destination,"resolved":resolved,"management_type":management_type,"scope_mode":scope_mode,"policy_groups":len(set(policy_group_ids or []))}
    finally:c.close()


def update_rule(rule_id,destination,protocol,network_ids,actor,reason,change_reference="",expires_at="",allow_system=False,category_slug=None,scope_mode="selected",policy_group_ids=None):
    expires_at=normalize_expiration(expires_at)
    c=connect()
    try:
        r=c.execute("SELECT * FROM rules WHERE id=?",(rule_id,)).fetchone()
        if not r or r["status"]=="deleted":raise ValueError("Rule cannot be edited.")
        if r["management_type"]=="system" and not allow_system:raise ValueError("System rule requires administrator privileges.")
        destination=normalize_domain(destination) if r["rule_type"]=="domain" else normalize_ip(destination);resolved=[]
        if c.execute("SELECT 1 FROM rules WHERE rule_type=? AND destination=? AND id!=? AND status!='deleted'",(r["rule_type"],destination,rule_id)).fetchone():raise ValueError("Another rule for this destination already exists.")
        protocol=protocol.upper()
        if protocol not in("HTTP","HTTPS","BOTH"):raise ValueError("Invalid protocol.")
        if scope_mode not in("selected","all_proxy"):raise ValueError("Invalid scope mode.")
        if scope_mode=="selected" and not network_ids and not policy_group_ids:raise ValueError("Select at least one network scope or Access Profile.")
        if len(reason.strip())<3:raise ValueError("A change reason is required.")
        cid=r["category_id"]
        if r["management_type"]=="system" and category_slug:cid=_system_category(c,category_slug)
        fp=_fingerprint(r["rule_type"],destination,protocol,r["management_type"],cid)
        c.execute("""UPDATE rules SET destination=?,protocol=?,category_id=?,pending=1,reason=?,change_reference=?,expires_at=?,fingerprint=?,updated_by=?,updated_at=CURRENT_TIMESTAMP,scope_mode=? WHERE id=?""",
                  (destination,protocol,cid,reason.strip(),change_reference or None,expires_at or None,fp,actor,scope_mode,rule_id))
        c.execute("DELETE FROM rule_networks WHERE rule_id=?",(rule_id,))
        c.execute("DELETE FROM policy_group_rules WHERE rule_id=?",(rule_id,))
        if scope_mode=="selected":
            for nid in {int(x) for x in network_ids}:c.execute("INSERT INTO rule_networks VALUES(?,?)",(rule_id,nid))
            for gid in {int(x) for x in (policy_group_ids or [])}:c.execute("INSERT INTO policy_group_rules(group_id,rule_id) VALUES(?,?)",(gid,rule_id))
        c.commit();return {"id":rule_id,"destination":destination,"resolved":resolved,"scope_mode":scope_mode,"policy_groups":len(set(policy_group_ids or []))}
    finally:c.close()


def set_status(rule_id,status,actor,allow_system=False):
    if status not in("active","disabled","deleted"):raise ValueError("Invalid status.")
    c=connect()
    try:
        r=c.execute("SELECT management_type,status FROM rules WHERE id=?",(rule_id,)).fetchone()
        if not r or r["status"]=="deleted":raise ValueError("Rule cannot be changed.")
        if r["management_type"]=="system" and not allow_system:raise ValueError("System rule requires administrator privileges.")
        c.execute("UPDATE rules SET status=?,pending=1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(status,actor,rule_id));c.commit()
    finally:c.close()


def pending_count():
    c=connect()
    try:
        return sum(c.execute(q).fetchone()["c"] for q in (
            "SELECT COUNT(*) c FROM rules WHERE pending=1","SELECT COUNT(*) c FROM networks WHERE pending=1",
            "SELECT COUNT(*) c FROM applications WHERE pending=1","SELECT COUNT(*) c FROM policy_groups WHERE pending=1"))
    finally:c.close()
