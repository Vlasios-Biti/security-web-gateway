#!/usr/bin/env python3
import argparse, hashlib, ipaddress, json, re, sqlite3, sys
from pathlib import Path
APP_ROOT = Path(__file__).resolve().parents[1]
if str(APP_ROOT) not in sys.path: sys.path.insert(0, str(APP_ROOT))
from app.db import connect, verify_schema
from app.config import SQUID_CONF, GOOGLE_SEARCH_FILE, GOOGLE_MAPS_FILE, LEGACY_BUSINESS_FILE

def fp(*p): return hashlib.sha256("|".join(p).encode()).hexdigest()
def category(c,name,slug,system):
    c.execute("INSERT OR IGNORE INTO categories(name,slug,system_managed) VALUES(?,?,?)",(name,slug,system))
    return c.execute("SELECT id FROM categories WHERE slug=?",(slug,)).fetchone()["id"]
def add_networks(c,text):
    out=[]
    for v in re.findall(r"^\s*acl\s+allowed_clients\s+src\s+([^\s#]+)",text,re.M):
        try: n=ipaddress.ip_network(v,strict=False)
        except Exception: continue
        cidr=str(n)
        if n.is_loopback or cidr=="10.100.254.13/32": continue
        vlan_guess = None
        # Do not invent VLAN metadata from CIDR; it can be set safely from GUI after import.
        c.execute("INSERT OR IGNORE INTO networks(name,vlan_id,cidr,proxy_enabled,enabled,system_managed,pending) VALUES(?,?,?,1,1,1,0)",(f"Restricted {cidr}",vlan_guess,cidr))
        out.append(cidr)
    return out
def nids(c): return [x["id"] for x in c.execute("SELECT id FROM networks WHERE enabled=1 AND proxy_enabled=1 ORDER BY id")]
def attach(c,rid,ids):
    for i in ids: c.execute("INSERT OR IGNORE INTO rule_networks VALUES(?,?)",(rid,i))
def domain_file(c,path,name,slug,management,system,ids):
    cid=category(c,name,slug,system);count=0
    if not path.exists(): return 0
    for ln,raw in enumerate(path.read_text(errors="replace").splitlines(),1):
        val=raw.strip().lower().rstrip(".")
        if not val or val.startswith("#"): continue
        f=fp("domain",val,"BOTH",management,slug)
        c.execute("""INSERT OR IGNORE INTO rules(rule_type,action,destination,protocol,category_id,management_type,status,pending,
                     source_file,source_line,fingerprint,created_by) VALUES('domain','ALLOW',?,?,?,?,'active',0,?,?,?,'baseline-import')""",
                  (val,"BOTH",cid,management,str(path),ln,f))
        r=c.execute("SELECT id FROM rules WHERE fingerprint=?",(f,)).fetchone(); attach(c,r["id"],ids); count+=1
    return count
def ips(c,text,ids):
    cid=category(c,"Explicit IP","explicit-ip",0);count=0
    for acl,proto in (("allowed_http_ips","HTTP"),("allowed_https_ips","HTTPS")):
        for m in re.finditer(rf"^\s*(?:#\s*LEGACY-DISABLED-BY-(?:PROXY-MANAGER|SECURITY-WEB-GATEWAY)\s+)?acl\s+{acl}\s+dst\s+([^\s#]+)",text,re.M):
            try: dest=str(ipaddress.ip_network(m.group(1),strict=False))
            except Exception: continue
            f=fp("ip",dest,proto,"custom","explicit-ip");ln=text[:m.start()].count("\n")+1
            c.execute("""INSERT OR IGNORE INTO rules(rule_type,action,destination,protocol,category_id,management_type,status,pending,
                         source_file,source_line,fingerprint,created_by) VALUES('ip','ALLOW',?,?,?,'custom','active',0,?,?,?,'baseline-import')""",
                      (dest,proto,cid,str(SQUID_CONF),ln,f))
            r=c.execute("SELECT id FROM rules WHERE fingerprint=?",(f,)).fetchone(); attach(c,r["id"],ids); count+=1
    return count
def users(c,legacy):
    if not legacy or not Path(legacy).exists(): return 0
    old=sqlite3.connect(legacy); old.row_factory=sqlite3.Row; count=0
    try:
        if "users" not in {r[0] for r in old.execute("SELECT name FROM sqlite_master WHERE type='table'")}: return 0
        cols={r[1] for r in old.execute("PRAGMA table_info(users)")}
        required={"username","password_hash","role","enabled"}
        if not required.issubset(cols): return 0
        query="SELECT username,password_hash,role,enabled,failed_attempts,locked_until,last_login_at,created_at,updated_at FROM users"
        for r in old.execute(query):
            role=r["role"] if r["role"] in ("viewer","operator","admin","auditor") else "viewer"
            c.execute("""INSERT OR IGNORE INTO users(username,password_hash,role,enabled,failed_attempts,locked_until,last_login_at,created_at,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?)""",(r["username"],r["password_hash"],role,r["enabled"],r["failed_attempts"],r["locked_until"],r["last_login_at"],r["created_at"],r["updated_at"]));count+=1
    finally: old.close()
    return count
def main():
    p=argparse.ArgumentParser();p.add_argument("--legacy-db");a=p.parse_args();verify_schema();text=SQUID_CONF.read_text(errors="replace");c=connect()
    try:
        # Baseline import is intended only for an empty candidate DB.
        existing=c.execute("SELECT COUNT(*) c FROM rules").fetchone()["c"]
        if existing: raise RuntimeError("Baseline import refused: destination database already contains rules.")
        c.execute("BEGIN IMMEDIATE");nets=add_networks(c,text);ids=nids(c)
        d=domain_file(c,GOOGLE_SEARCH_FILE,"Google Search","google-search","system",1,ids)
        d+=domain_file(c,GOOGLE_MAPS_FILE,"Google Maps","google-maps","system",1,ids)
        d+=domain_file(c,LEGACY_BUSINESS_FILE,"Business","business","custom",0,ids)
        i=ips(c,text,ids);u=users(c,a.legacy_db)
        c.execute("INSERT INTO audit_events(actor,action,object_type,result,details_json) VALUES('system','BASELINE_IMPORT','configuration','SUCCESS',?)",
                  (json.dumps({"domains":d,"ips":i,"networks":len(nets),"users":u}),));c.commit()
    except Exception: c.rollback(); raise
    finally: c.close()
    print(json.dumps({"ok":True,"networks":len(nets),"domains":d,"ips":i,"users":u}))
if __name__=="__main__": main()
