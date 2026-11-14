from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
import csv
import hashlib
import ipaddress
import io
import json
import os
import socket
import subprocess
import re
import shutil
import time
import urllib.parse
import zipfile
from xml.sax.saxutils import escape

from app.config import SQUID_ACCESS_LOG, DATA_ROOT, DB_PATH, SQUID_LOG_DIR, PROXY_IP
from app.db import connect
from app.security import csv_cell

_ATTR_CACHE = {"ts": 0.0, "data": None}
_NETWORK_CACHE = {"ts": 0.0, "data": None}
_LOCK_PATH = DATA_ROOT / "telemetry.lock"


def _canonical_ip(value):
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except Exception:
        return (value or "").strip()


_SYSTEM_CLIENT_IPS = tuple(sorted({
    _canonical_ip(PROXY_IP),
    _canonical_ip("127.0.0.1"),
    _canonical_ip("::1"),
} - {""}))


def is_system_client(value):
    return _canonical_ip(value) in _SYSTEM_CLIENT_IPS


def _system_exclusion_sql(column="client_ip"):
    placeholders = ",".join("?" for _ in _SYSTEM_CLIENT_IPS)
    return f"{column} NOT IN ({placeholders})", list(_SYSTEM_CLIENT_IPS)


def _setting(c, key, default):
    r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def _set_state(c, key, value):
    c.execute(
        "INSERT INTO telemetry_state(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP",
        (key, str(value)),
    )


def _get_state(c, key, default=None):
    r = c.execute("SELECT value FROM telemetry_state WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def _decision(result):
    r = (result or "").upper()
    if "DENIED" in r or r.startswith("TCP_DENIED"):
        return "DENY"
    if r.startswith("TCP_") or r.startswith("UDP_"):
        return "ALLOW"
    return "INFO"


def _split_result(result):
    if "/" not in (result or ""):
        return result or "", None
    code, status = result.rsplit("/", 1)
    try:
        return code, int(status)
    except Exception:
        return code, None


def _destination_parts(method, destination, hierarchy):
    host = ""
    port = None
    dest = destination or ""
    if method == "CONNECT":
        # CONNECT authority may be hostname:port or [ipv6]:port.
        if dest.startswith("[") and "]:" in dest:
            host, p = dest[1:].split("]:", 1)
            try: port = int(p)
            except Exception: port = None
        elif ":" in dest:
            host, p = dest.rsplit(":", 1)
            try: port = int(p)
            except Exception: host = dest
        else:
            host = dest
    else:
        try:
            u = urllib.parse.urlsplit(dest)
            host = u.hostname or dest
            port = u.port or (443 if u.scheme == "https" else 80 if u.scheme == "http" else None)
        except Exception:
            host = dest.split("/", 1)[0]
    host = (host or "").strip(".").lower()

    hierarchy_code = hierarchy or ""
    upstream_ip = ""
    if "/" in hierarchy_code:
        hierarchy_code, upstream_ip = hierarchy_code.split("/", 1)
        if upstream_ip in ("-", "0.0.0.0"):
            upstream_ip = ""
    dest_ip = upstream_ip if _is_ip(upstream_ip) else (host if _is_ip(host) else "")
    return host, dest_ip, port, hierarchy_code, upstream_ip


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def parse_squid_line(raw):
    """Parse Squid native access.log into a normalized record.

    Native format fields: timestamp elapsed client result bytes method URL user hierarchy mime.
    We intentionally do not inspect/decrypt HTTPS payloads; CONNECT gives host:port only.
    """
    p = raw.strip().split(None, 9)
    if len(p) < 9:
        return None
    try:
        epoch = float(p[0])
        elapsed = int(p[1])
        when = datetime.fromtimestamp(epoch)
    except Exception:
        return None
    result = p[3]
    try: byte_count = int(p[4])
    except Exception: byte_count = 0
    method = p[5]
    destination = p[6]
    hierarchy = p[8]
    mime = p[9] if len(p) > 9 else ""
    result_code, http_status = _split_result(result)
    host, dest_ip, port, hierarchy_code, upstream_ip = _destination_parts(method, destination, hierarchy)
    return {
        "epoch": epoch,
        "event_time": when.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_ms": elapsed,
        "client_ip": p[2],
        "decision": _decision(result),
        "result_code": result_code,
        "http_status": http_status,
        "bytes": byte_count,
        "method": method,
        "destination": destination,
        "destination_host": host,
        "destination_ip": dest_ip,
        "destination_port": port,
        "hierarchy": hierarchy,
        "hierarchy_code": hierarchy_code,
        "upstream_ip": upstream_ip,
        "mime_type": mime,
        "raw_line": raw.rstrip("\n"),
        "event_hash": hashlib.sha256(raw.rstrip("\n").encode("utf-8", "replace")).hexdigest(),
    }


def _networks(c=None):
    now = time.time()
    if c is None and _NETWORK_CACHE["data"] is not None and now - _NETWORK_CACHE["ts"] < 30:
        return _NETWORK_CACHE["data"]
    own = c is None
    c = c or connect()
    try:
        rows = [dict(r) for r in c.execute(
            "SELECT id,name,vlan_id,cidr FROM networks WHERE enabled=1 AND proxy_enabled=1 ORDER BY COALESCE(vlan_id,99999),name"
        )]
        out = []
        for n in rows:
            try:
                n["obj"] = ipaddress.ip_network(n["cidr"], strict=False)
                out.append(n)
            except Exception:
                pass
        if own:
            _NETWORK_CACHE.update({"ts": now, "data": out})
        return out
    finally:
        if own:
            c.close()


def _attribution_data(c):
    now = time.time()
    if _ATTR_CACHE["data"] is not None and now - _ATTR_CACHE["ts"] < 30:
        return _ATTR_CACHE["data"]
    apps = defaultdict(list)
    app_names = {}
    for r in c.execute("""
        SELECT a.id application_id,a.name application_name,r.id rule_id,r.rule_type,r.destination,r.protocol
        FROM application_rules ar
        JOIN applications a ON a.id=ar.application_id AND a.status='active'
        JOIN rules r ON r.id=ar.rule_id AND r.status='active'
        WHERE ar.enabled=1
        ORDER BY a.system_managed DESC,a.name,r.id
    """):
        d = dict(r)
        apps[d["rule_type"]].append(d)
        app_names[d["application_id"]] = d["application_name"]
    standalone = [dict(r) for r in c.execute("""
        SELECT id rule_id,rule_type,destination,protocol,management_type
        FROM rules WHERE status='active' ORDER BY management_type DESC,id
    """)]
    profiles_by_app = defaultdict(list)
    for r in c.execute("""
        SELECT pga.application_id,pg.name,pgn.network_id
        FROM policy_group_applications pga
        JOIN policy_groups pg ON pg.id=pga.group_id AND pg.status='active'
        JOIN policy_group_networks pgn ON pgn.group_id=pg.id
    """):
        profiles_by_app[r["application_id"]].append((r["name"], r["network_id"]))
    profiles_by_rule = defaultdict(list)
    for r in c.execute("""
        SELECT pgr.rule_id,pg.name,pgn.network_id
        FROM policy_group_rules pgr
        JOIN policy_groups pg ON pg.id=pgr.group_id AND pg.status='active'
        JOIN policy_group_networks pgn ON pgn.group_id=pg.id
    """):
        profiles_by_rule[r["rule_id"]].append((r["name"], r["network_id"]))
    data = {
        "app_rules": apps,
        "app_names": app_names,
        "standalone": standalone,
        "profiles_by_app": profiles_by_app,
        "profiles_by_rule": profiles_by_rule,
    }
    _ATTR_CACHE.update({"ts": now, "data": data})
    return data


def _domain_matches(pattern, host):
    p = (pattern or "").strip().lower().rstrip(".")
    h = (host or "").strip().lower().rstrip(".")
    if not p or not h:
        return False
    if p.startswith("*."):
        p = p[2:]
        return h == p or h.endswith("." + p)
    if p.startswith("."):
        p = p[1:]
        return h == p or h.endswith("." + p)
    return h == p


def _rule_matches(rule, host, dest_ip):
    if rule["rule_type"] == "domain":
        return _domain_matches(rule["destination"], host)
    if not dest_ip:
        return False
    try:
        return ipaddress.ip_address(dest_ip) in ipaddress.ip_network(rule["destination"], strict=False)
    except Exception:
        return dest_ip == rule["destination"]


def _enrich(c, record, networks=None, attrs=None):
    networks = networks or _networks(c)
    attrs = attrs or _attribution_data(c)
    record.update({
        "network_id": None, "network_name": "Unmapped", "vlan_id": None,
        "application_ids": "", "application_names": "",
        "matched_rule_id": None, "matched_rule_destination": "",
        "access_profile_names": "", "traffic_path": "PROXY",
    })
    if is_system_client(record.get("client_ip")):
        record["network_name"] = "System appliance"
        record["access_profile_names"] = "Internal / diagnostic"
        return record
    try:
        cip = ipaddress.ip_address(record["client_ip"])
        for n in networks:
            if cip in n["obj"]:
                record["network_id"] = n["id"]
                record["network_name"] = n["name"]
                record["vlan_id"] = n["vlan_id"]
                break
    except Exception:
        pass

    matched_apps = []
    matched_rule = None
    profiles = set()
    for typ in ("domain", "ip"):
        for r in attrs["app_rules"].get(typ, []):
            if _rule_matches(r, record["destination_host"], record["destination_ip"]):
                if r["application_id"] not in [x[0] for x in matched_apps]:
                    matched_apps.append((r["application_id"], r["application_name"]))
                profiles.update(name for name,nid in attrs["profiles_by_app"].get(r["application_id"], []) if record["network_id"] is not None and nid == record["network_id"])
                if matched_rule is None:
                    matched_rule = r
    if matched_rule is None:
        for r in attrs["standalone"]:
            if _rule_matches(r, record["destination_host"], record["destination_ip"]):
                matched_rule = r
                profiles.update(name for name,nid in attrs["profiles_by_rule"].get(r["rule_id"], []) if record["network_id"] is not None and nid == record["network_id"])
                break
    if matched_apps:
        record["application_ids"] = "," + ",".join(str(x[0]) for x in matched_apps) + ","
        record["application_names"] = " + ".join(x[1] for x in matched_apps)
    if matched_rule:
        record["matched_rule_id"] = matched_rule["rule_id"]
        record["matched_rule_destination"] = matched_rule["destination"]
    record["access_profile_names"] = ", ".join(sorted(profiles))
    return record


def _insert_record(c, r):
    c.execute("""
        INSERT OR IGNORE INTO telemetry_events(
          epoch,event_time,elapsed_ms,client_ip,decision,result_code,http_status,bytes,method,destination,
          destination_host,destination_ip,destination_port,hierarchy,hierarchy_code,upstream_ip,mime_type,
          network_id,network_name,vlan_id,application_ids,application_names,matched_rule_id,matched_rule_destination,
          access_profile_names,traffic_path,raw_line,event_hash
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        r["epoch"],r["event_time"],r["elapsed_ms"],r["client_ip"],r["decision"],r["result_code"],r["http_status"],
        r["bytes"],r["method"],r["destination"],r["destination_host"],r["destination_ip"],r["destination_port"],
        r["hierarchy"],r["hierarchy_code"],r["upstream_ip"],r["mime_type"],r["network_id"],r["network_name"],r["vlan_id"],
        r["application_ids"],r["application_names"],r["matched_rule_id"],r["matched_rule_destination"],r["access_profile_names"],
        r["traffic_path"],r["raw_line"],r["event_hash"],
    ))


def ingest_access_log(max_events=50000, cleanup=True):
    """Incrementally ingest Squid access.log into the searchable telemetry DB.

    File inode+offset state survives restarts and detects log rotation. A file lock
    prevents concurrent ingestion by Uvicorn workers and the systemd collector.
    """
    try:
        import fcntl
        DATA_ROOT.mkdir(parents=True, exist_ok=True)
        with open(_LOCK_PATH, "a+") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {"inserted": 0, "busy": True}
            return _ingest_locked(max_events=max_events, cleanup=cleanup)
    except Exception as e:
        return {"inserted": 0, "error": str(e)}


def _ingest_locked(max_events=50000, cleanup=True):
    path = SQUID_ACCESS_LOG
    if not path.exists():
        return {"inserted": 0, "error": f"access log missing: {path}"}
    st = path.stat()
    c = connect()
    inserted = 0
    parsed = 0
    try:
        old_inode = _get_state(c, "access_log_inode")
        old_offset = int(_get_state(c, "access_log_offset", "0") or 0)
        bootstrap_bytes = int(_setting(c, "telemetry_bootstrap_bytes", "52428800"))
        if old_inode is None:
            offset = max(0, st.st_size - bootstrap_bytes)
            first_bootstrap = offset > 0
        elif str(st.st_ino) != str(old_inode) or st.st_size < old_offset:
            offset = 0
            first_bootstrap = False
        else:
            offset = old_offset
            first_bootstrap = False
        networks = _networks(c)
        attrs = _attribution_data(c)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            if first_bootstrap:
                f.readline()  # discard a partial first line after byte seek
            while parsed < max_events:
                raw = f.readline()
                if not raw:
                    break
                parsed += 1
                rec = parse_squid_line(raw)
                if not rec:
                    continue
                rec = _enrich(c, rec, networks, attrs)
                before = c.total_changes
                _insert_record(c, rec)
                if c.total_changes > before:
                    inserted += 1
            new_offset = f.tell()
        _set_state(c, "access_log_inode", st.st_ino)
        _set_state(c, "access_log_offset", new_offset)
        _set_state(c, "last_ingest_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        _set_state(c, "last_ingest_inserted", inserted)
        cleanup_result = None
        if cleanup:
            cleanup_result = _cleanup_telemetry_connection(c)
        summary_state=c.execute("SELECT COUNT(*) c,MIN(event_time) first_event,MAX(event_time) last_event,MAX(epoch) last_epoch FROM telemetry_events").fetchone()
        _set_state(c,"telemetry_event_count",summary_state["c"] or 0)
        _set_state(c,"telemetry_first_event",summary_state["first_event"] or "")
        _set_state(c,"telemetry_last_event",summary_state["last_event"] or "")
        _set_state(c,"telemetry_last_event_epoch",summary_state["last_epoch"] or "")
        c.commit()
        # Expensive intelligence/aggregation runs only in this collector path, never in GUI requests.
        candidate_result = refresh_dependency_candidates()
        cache_result = refresh_dashboard_cache((60,1440))
        return {"inserted": inserted, "parsed": parsed, "offset": new_offset, "inode": st.st_ino, "cleanup": cleanup_result, "dependency_candidates": candidate_result, "dashboard_cache": cache_result}
    finally:
        c.close()


def ensure_fresh():
    # Never parse Squid logs inside a web request. The 30-second collector
    # timer owns ingestion so a large/locked access.log cannot stall the GUI or
    # trigger an Nginx 504. UI data can therefore be up to one collector interval old.
    return {"inserted": 0, "deferred": True}


def _range_epochs(range_key="1h", date_from=None, date_to=None):
    now = time.time()
    if date_from:
        try: start = datetime.fromisoformat(date_from).timestamp()
        except Exception: start = None
    else:
        start = None
    if date_to:
        try: end = datetime.fromisoformat(date_to).timestamp()
        except Exception: end = None
    else:
        end = None
    if start is None:
        seconds = {
            "5m":300,"15m":900,"1h":3600,"6h":21600,"24h":86400,
            "today":None,"yesterday":None,"7d":604800,"30d":2592000,"all":None,
        }.get(range_key, 3600)
        if range_key == "today":
            start = datetime.now().replace(hour=0,minute=0,second=0,microsecond=0).timestamp()
        elif range_key == "yesterday":
            today = datetime.now().replace(hour=0,minute=0,second=0,microsecond=0)
            start = (today - timedelta(days=1)).timestamp(); end = today.timestamp()
        elif seconds is not None:
            start = now - seconds
    return start, end


def _filter_sql(filters, alias="t"):
    clauses=[]; params=[]
    include_system = str(filters.get("include_system", "")).strip().lower() in ("1","true","yes","on")
    explicit_client = (filters.get("client_ip") or "").strip()
    if not include_system and not is_system_client(explicit_client):
        clause, values = _system_exclusion_sql(f"{alias}.client_ip")
        clauses.append(clause)
        params.extend(values)
    start,end=_range_epochs(filters.get("range","1h"), filters.get("date_from"), filters.get("date_to"))
    if start is not None: clauses.append(f"{alias}.epoch>=?");params.append(start)
    if end is not None: clauses.append(f"{alias}.epoch<=?");params.append(end)
    def eq(field,key,cast=None):
        v=filters.get(key)
        if v not in (None,""):
            clauses.append(f"{alias}.{field}=?");params.append(cast(v) if cast else v)
    eq("client_ip","client_ip")
    eq("decision","decision")
    eq("method","method")
    eq("network_id","network_id",int)
    eq("destination_port","port",int)
    eq("traffic_path","traffic_path")
    app_id=filters.get("application_id")
    if app_id not in (None,""):
        clauses.append(f"{alias}.application_ids LIKE ?");params.append(f"%,{int(app_id)},%")
    dest=(filters.get("destination") or "").strip().lower()
    if dest:
        clauses.append(f"(LOWER({alias}.destination_host) LIKE ? OR LOWER({alias}.destination) LIKE ?)")
        params.extend([f"%{dest}%",f"%{dest}%"])
    dip=(filters.get("destination_ip") or "").strip()
    if dip:
        clauses.append(f"{alias}.destination_ip LIKE ?");params.append(f"%{dip}%")
    q=(filters.get("q") or "").strip().lower()
    if q:
        like=f"%{q}%"
        clauses.append(f"(LOWER({alias}.client_ip) LIKE ? OR LOWER({alias}.destination_host) LIKE ? OR LOWER({alias}.destination_ip) LIKE ? OR LOWER({alias}.application_names) LIKE ? OR LOWER({alias}.network_name) LIKE ? OR LOWER({alias}.result_code) LIKE ?)")
        params.extend([like]*6)
    return (" WHERE "+" AND ".join(clauses)) if clauses else "",params


def list_events(filters=None, page=1, page_size=100):
    ensure_fresh()
    filters=filters or {}
    page=max(1,int(page));page_size=max(25,min(int(page_size),500))
    where,params=_filter_sql(filters)
    c=connect()
    try:
        total=c.execute("SELECT COUNT(*) c FROM telemetry_events t"+where,params).fetchone()["c"]
        rows=[dict(r) for r in c.execute("SELECT t.* FROM telemetry_events t"+where+" ORDER BY t.epoch DESC LIMIT ? OFFSET ?",params+[page_size,(page-1)*page_size])]
        for row in rows:
            row["is_system"] = is_system_client(row.get("client_ip"))
        pages=max(1,(total+page_size-1)//page_size)
        return {"rows":rows,"total":total,"page":page,"page_size":page_size,"pages":pages}
    finally:c.close()


def traffic_summary(filters=None):
    ensure_fresh();filters=filters or {};where,params=_filter_sql(filters);c=connect()
    try:
        r=c.execute("""SELECT COUNT(*) total,
          SUM(CASE WHEN decision='ALLOW' THEN 1 ELSE 0 END) allowed,
          SUM(CASE WHEN decision='DENY' THEN 1 ELSE 0 END) denied,
          COUNT(DISTINCT client_ip) clients,COALESCE(SUM(bytes),0) bytes,
          COALESCE(AVG(elapsed_ms),0) avg_elapsed_ms
          FROM telemetry_events t"""+where,params).fetchone()
        return {k:(r[k] or 0) for k in r.keys()}
    finally:c.close()


def filter_options():
    c=connect()
    try:
        networks=[dict(r) for r in c.execute("SELECT id,name,vlan_id,cidr FROM networks WHERE enabled=1 AND proxy_enabled=1 ORDER BY name")]
        apps=[dict(r) for r in c.execute("SELECT id,name,provider FROM applications WHERE status='active' ORDER BY name")]
        return {"networks":networks,"applications":apps}
    finally:c.close()


def top_items(filters=None, field="destination_host", limit=10):
    allowed={"destination_host","client_ip","application_names","network_name","destination_ip"}
    if field not in allowed: raise ValueError("invalid field")
    where,params=_filter_sql(filters or {})
    c=connect()
    try:
        rows=c.execute(f"SELECT {field} name,COUNT(*) count,COALESCE(SUM(bytes),0) bytes FROM telemetry_events t"+where+f" AND {field}!='' GROUP BY {field} ORDER BY count DESC LIMIT ?" if where else f"SELECT {field} name,COUNT(*) count,COALESCE(SUM(bytes),0) bytes FROM telemetry_events t WHERE {field}!='' GROUP BY {field} ORDER BY count DESC LIMIT ?",params+[limit]).fetchall()
        return [dict(r) for r in rows]
    finally:c.close()


def timeline(minutes=60,bucket_minutes=5):
    ensure_fresh();minutes=max(15,min(int(minutes),1440));bucket_minutes=max(1,min(int(bucket_minutes),60));start=time.time()-minutes*60;c=connect()
    clause, values = _system_exclusion_sql("client_ip")
    try: rows=[dict(r) for r in c.execute("SELECT epoch,decision,client_ip,bytes FROM telemetry_events WHERE epoch>=? AND "+clause+" ORDER BY epoch",[start]+values)]
    finally:c.close()
    now=datetime.now().replace(second=0,microsecond=0);startdt=now-timedelta(minutes=minutes);buckets=defaultdict(lambda:{"allowed":0,"denied":0,"clients":set(),"bytes":0})
    for r in rows:
        dt=datetime.fromtimestamp(r["epoch"]);key=dt.replace(minute=(dt.minute//bucket_minutes)*bucket_minutes,second=0,microsecond=0);b=buckets[key]
        if r["decision"]=="ALLOW":b["allowed"]+=1
        elif r["decision"]=="DENY":b["denied"]+=1
        b["clients"].add(r["client_ip"]);b["bytes"]+=int(r["bytes"] or 0)
    pts=[];cursor=startdt.replace(minute=(startdt.minute//bucket_minutes)*bucket_minutes,second=0,microsecond=0)
    while cursor<=now:
        b=buckets[cursor];pts.append({"label":cursor.strftime("%H:%M"),"allowed":b["allowed"],"denied":b["denied"],"clients":len(b["clients"]),"bytes":b["bytes"]});cursor+=timedelta(minutes=bucket_minutes)
    return pts


def network_breakdown(minutes=1440):
    ensure_fresh();start=time.time()-max(15,min(int(minutes),43200))*60;c=connect()
    clause, values = _system_exclusion_sql("client_ip")
    try:
        rows=c.execute("""SELECT COALESCE(network_name,'Unmapped') name,vlan_id,
          SUM(CASE WHEN decision='ALLOW' THEN 1 ELSE 0 END) allowed,
          SUM(CASE WHEN decision='DENY' THEN 1 ELSE 0 END) denied,
          COUNT(DISTINCT client_ip) clients,COALESCE(SUM(bytes),0) bytes
          FROM telemetry_events WHERE epoch>=? AND """+clause+""" GROUP BY network_id,network_name,vlan_id ORDER BY allowed+denied DESC""",[start]+values).fetchall()
        return [dict(r) for r in rows]
    finally:c.close()


def _compute_dashboard_payload(minutes=60):
    ensure_fresh();f={"range":"1h" if minutes<=60 else "24h"};s=traffic_summary(f)
    return {"timeline":timeline(minutes,5),"allowed":s["allowed"],"denied":s["denied"],"clients":s["clients"],
            "bytes":s["bytes"],"top_blocked":top_items({**f,"decision":"DENY"},"destination_host",10),
            "top_allowed":top_items({**f,"decision":"ALLOW"},"destination_host",10),
            "top_clients":top_items(f,"client_ip",10),"networks":network_breakdown(minutes)}


def _cache_ttl(c):
    try:
        return max(5, min(300, int(_setting(c, "dashboard_cache_ttl_seconds", "20"))))
    except Exception:
        return 20


def refresh_dashboard_cache(minutes_list=(60, 1440)):
    """Precompute overview/dashboard analytics outside the web request path."""
    out={}
    for minutes in minutes_list:
        payload=_compute_dashboard_payload(int(minutes))
        c=connect()
        try:
            ttl=_cache_ttl(c)
            now=time.time()
            key=f"traffic:{int(minutes)}"
            c.execute(
                "INSERT INTO dashboard_cache(key,payload_json,generated_at,expires_at) VALUES(?,?,CURRENT_TIMESTAMP,?) "
                "ON CONFLICT(key) DO UPDATE SET payload_json=excluded.payload_json,generated_at=CURRENT_TIMESTAMP,expires_at=excluded.expires_at",
                (key,json.dumps(payload,separators=(",",":")),now+ttl),
            )
            c.commit()
            out[key]={"generated":True,"ttl":ttl}
        finally:
            c.close()
    return out


def dashboard_payload(minutes=60):
    """Return precomputed dashboard data; never perform expensive aggregation in a page request."""
    key=f"traffic:{int(minutes)}"
    c=connect()
    try:
        r=c.execute("SELECT payload_json,generated_at,expires_at FROM dashboard_cache WHERE key=?",(key,)).fetchone()
        if r:
            try:
                payload=json.loads(r["payload_json"])
                payload["cache_generated_at"]=r["generated_at"]
                payload["cache_stale"]=float(r["expires_at"]) < time.time()
                return payload
            except Exception:
                pass
    finally:
        c.close()
    return {
        "timeline":[],"allowed":0,"denied":0,"clients":0,"bytes":0,
        "top_blocked":[],"top_allowed":[],"top_clients":[],"networks":[],
        "cache_generated_at":None,"cache_stale":True,"cache_warming":True,
    }


def _confidence_for_classification(classification,recommendation):
    if classification in ("first_party","authentication","api","realtime"):
        return 90,"high"
    if classification in ("cdn","storage"):
        return 72,"medium"
    if recommendation=="ignore":
        return 10,"low"
    return 55,"medium"


def refresh_dependency_candidates(max_denied=2000):
    """Correlate new blocked hosts with the most recently active single application for a client.

    This is intentionally conservative: candidates are evidence only and never change policy.
    """
    from app.services.discovery import _classify_endpoint
    c=connect()
    created=updated=0
    try:
        window=max(30,min(900,int(_setting(c,"dependency_candidate_window_seconds","120"))))
        last=float(_get_state(c,"dependency_candidate_scan_epoch",str(max(0,time.time()-300))) or 0)
        system_clause, system_values = _system_exclusion_sql("client_ip")
        denied=[dict(r) for r in c.execute("""SELECT id,epoch,event_time,client_ip,destination_host,destination_port
            FROM telemetry_events WHERE epoch>? AND decision='DENY' AND destination_host!='' AND """+system_clause+"""
            ORDER BY epoch ASC LIMIT ?""",[last]+system_values+[max(100,min(int(max_denied),10000))])]
        max_epoch=last
        for d in denied:
            max_epoch=max(max_epoch,float(d['epoch']))
            prev=c.execute("""SELECT application_ids,application_names FROM telemetry_events
                WHERE client_ip=? AND decision='ALLOW' AND epoch<=? AND epoch>=?
                  AND application_ids IS NOT NULL AND application_ids!=''
                ORDER BY epoch DESC LIMIT 1""",(d['client_ip'],d['epoch'],d['epoch']-window)).fetchone()
            if not prev: continue
            app_ids=[int(x) for x in (prev['application_ids'] or '').strip(',').split(',') if x.strip().isdigit()]
            app_ids=list(dict.fromkeys(app_ids))
            if len(app_ids)!=1: continue
            aid=app_ids[0]
            host=(d['destination_host'] or '').lower().rstrip('.')
            protocol='HTTPS' if int(d['destination_port'] or 443)==443 else 'HTTP'
            from app.services.dependency_assignment import matches
            correction=next((row for row in c.execute("SELECT destination,target_application_id FROM dependency_corrections WHERE source_application_id=? AND protocol IN (?,'BOTH') ORDER BY length(destination) DESC",(aid,protocol)) if matches(row['destination'],host)),None)
            if correction:aid=correction['target_application_id']
            app=c.execute("SELECT id,name,seed_domain FROM applications WHERE id=? AND status='active'",(aid,)).fetchone()
            if not app: continue
            host=(d['destination_host'] or '').lower().rstrip('.')
            # If this host already belongs to the application, it is not a new dependency candidate.
            already=False
            for rr in c.execute("""SELECT r.destination FROM rules r JOIN application_rules ar ON ar.rule_id=r.id
                WHERE ar.application_id=? AND ar.enabled=1 AND r.rule_type='domain' AND r.status='active'""",(aid,)):
                if _domain_matches(rr['destination'],host): already=True; break
            if already: continue
            cls,rec=_classify_endpoint(host,seed_host=(app['seed_domain'] or '').lower().rstrip('.'))
            if rec=='ignore': continue
            score,confidence=_confidence_for_classification(cls,rec)
            # A nearby request from the same IP cannot prove process/application origin.
            score,confidence,rec=min(score,40),'low','review'
            protocol='HTTPS' if int(d['destination_port'] or 443)==443 else 'HTTP'
            row=c.execute("SELECT id,status FROM application_dependency_candidates WHERE application_id=? AND destination=? AND protocol=?",(aid,host,protocol)).fetchone()
            evidence=json.dumps({"correlated_from_application":app['name'],"window_seconds":window,"event_id":d['id']},separators=(",",":"))
            if row:
                if row['status']=='pending':
                    c.execute("""UPDATE application_dependency_candidates SET request_count=request_count+1,last_seen_at=?,
                        classification=?,confidence_score=?,confidence=?,recommendation=?,evidence_json=? WHERE id=?""",
                        (d['event_time'],cls,score,confidence,rec,evidence,row['id']))
                    cid=row['id'];updated+=1
                else:
                    continue
            else:
                cur=c.execute("""INSERT INTO application_dependency_candidates(application_id,destination,protocol,classification,
                    confidence_score,confidence,recommendation,request_count,client_count,first_seen_at,last_seen_at,
                    first_client_ip,evidence_json,status) VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?, 'pending')""",
                    (aid,host,protocol,cls,score,confidence,rec,1,d['event_time'],d['event_time'],d['client_ip'],evidence))
                cid=cur.lastrowid;created+=1
            c.execute("""INSERT INTO application_dependency_candidate_clients(candidate_id,client_ip,first_seen_at,last_seen_at)
                VALUES(?,?,?,?) ON CONFLICT(candidate_id,client_ip) DO UPDATE SET last_seen_at=excluded.last_seen_at""",
                (cid,d['client_ip'],d['event_time'],d['event_time']))
            cc=c.execute("SELECT COUNT(*) c FROM application_dependency_candidate_clients WHERE candidate_id=?",(cid,)).fetchone()['c']
            c.execute("UPDATE application_dependency_candidates SET client_count=? WHERE id=?",(cc,cid))
        if denied:
            _set_state(c,"dependency_candidate_scan_epoch",max_epoch)
        c.commit()
        return {"created":created,"updated":updated,"scanned":len(denied),"window_seconds":window}
    finally:
        c.close()


def _cached_hostnames(c, ips):
    keys=['client-ptr:'+str(ip) for ip in ips]
    if not keys:return {}
    found={}
    for row in c.execute('SELECT key,payload_json FROM dashboard_cache WHERE key IN ('+','.join('?' for _ in keys)+') AND expires_at>?',keys+[time.time()]):
        try:found[row['key'].removeprefix('client-ptr:')]=json.loads(row['payload_json']).get('hostname','')
        except (ValueError,TypeError):pass
    return found


def _ptr(ip):
    c=connect()
    try:return _cached_hostnames(c,[ip]).get(ip,'')
    finally:c.close()


def refresh_client_hostnames(limit=8):
    # Worker only: bounded recent-event scan, no DNS while holding a DB write lock.
    limit=max(1,min(int(limit),8));now=time.time();c=connect()
    try:
        rows=c.execute("""SELECT DISTINCT recent.client_ip FROM
            (SELECT client_ip FROM telemetry_events ORDER BY epoch DESC LIMIT 2000) recent
            LEFT JOIN dashboard_cache cache ON cache.key='client-ptr:'||recent.client_ip
            WHERE cache.key IS NULL OR cache.expires_at<=? LIMIT ?""",(now,limit)).fetchall()
    finally:c.close()
    updates=[]
    for row in rows:
        try:ip=str(ipaddress.IPv4Address(row['client_ip']))
        except ValueError:continue
        name=''
        try:
            result=subprocess.run(['/usr/bin/getent','hosts',ip],capture_output=True,text=True,timeout=.5,check=False)
            fields=result.stdout[:1024].split()
            if result.returncode==0 and len(fields)>1 and len(fields[1])<=253 and re.fullmatch(r'[A-Za-z0-9_.-]+',fields[1]):name=fields[1]
        except (OSError,subprocess.TimeoutExpired):pass
        updates.append(('client-ptr:'+ip,json.dumps({'hostname':name}),now+(3600 if name else 600)))
    c=connect()
    try:
        c.executemany("INSERT INTO dashboard_cache(key,payload_json,expires_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET payload_json=excluded.payload_json,expires_at=excluded.expires_at,generated_at=CURRENT_TIMESTAMP",updates)
        c.execute("DELETE FROM dashboard_cache WHERE key LIKE 'client-ptr:%' AND expires_at<?",(now-86400,));c.commit()
    finally:c.close()
    return {'checked':len(updates),'resolved':sum(bool(json.loads(row[1])['hostname']) for row in updates)}


def client_inventory(filters=None, page=1, page_size=50, search=''):
    ensure_fresh();filters=filters or {'range':'24h'}
    where,params=_filter_sql(filters);page_size=max(25,min(500,int(page_size)));page=max(1,int(page))
    search=str(search).strip()[:200].lower();c=connect()
    try:
        base="""WITH devices AS (
            SELECT client_ip ip,MAX(event_time) last_seen,
            SUM(CASE WHEN decision='ALLOW' THEN 1 ELSE 0 END) allowed,
            SUM(CASE WHEN decision='DENY' THEN 1 ELSE 0 END) denied,COUNT(*) requests,
            COUNT(DISTINCT NULLIF(destination_host,'')) destinations,COALESCE(SUM(bytes),0) bytes,
            GROUP_CONCAT(DISTINCT network_name) network,GROUP_CONCAT(DISTINCT vlan_id) vlan_id
            FROM telemetry_events t"""+where+""" GROUP BY client_ip), named AS (
            SELECT devices.*,COALESCE(CASE WHEN json_valid(cache.payload_json) THEN json_extract(cache.payload_json,'$.hostname') END,'') hostname,COALESCE(labels.name,'') label
            FROM devices LEFT JOIN dashboard_cache cache ON cache.key='client-ptr:'||devices.ip AND cache.expires_at>?
            LEFT JOIN client_labels labels ON labels.ip=devices.ip)
            """
        values=params+[time.time()]
        condition=''
        if search:
            condition=" WHERE instr(lower(ip),?)>0 OR instr(lower(hostname),?)>0 OR instr(lower(label),?)>0 OR instr(lower(COALESCE(network,'')),?)>0 OR instr(COALESCE(vlan_id,''),?)>0"
            values.extend([search]*5)
        total=c.execute(base+'SELECT COUNT(*) FROM named'+condition,values).fetchone()[0]
        pages=max(1,(total+page_size-1)//page_size);page=min(page,pages)
        rows=[dict(row) for row in c.execute(base+'SELECT * FROM named'+condition+' ORDER BY requests DESC,ip LIMIT ? OFFSET ?',values+[page_size,(page-1)*page_size])]
        for row in rows:
            row['display_name']=row['label'] or row['hostname'] or row['ip']
            row['identity_source']='manual' if row['label'] else ('DNS/PTR' if row['hostname'] else 'IP only')
        return {'rows':rows,'total':total,'page':page,'pages':pages,'page_size':page_size}
    finally:c.close()


def clients(filters=None, limit=500):
    return client_inventory(filters,1,limit)['rows'][:max(0,min(500,int(limit)))]


def client_detail(ip, range_key="24h", filters=None, page=1, page_size=100):
    ip=str(ipaddress.ip_address(ip))
    # The path IP is authoritative; query filters must never widen this scope.
    f={**(filters or {}),'range':range_key,'client_ip':ip}
    summary=traffic_summary(f);events=list_events(f,page,page_size)
    apps=top_items(f,'application_names',10);dest=top_items(f,'destination_host',15);dips=top_items(f,'destination_ip',10)
    where,params=_filter_sql(f);c=connect()
    try:
        span=c.execute('SELECT MIN(event_time) first_seen,MAX(event_time) last_seen FROM telemetry_events t'+where,params).fetchone()
        latest=c.execute('SELECT network_name,vlan_id FROM telemetry_events t'+where+' ORDER BY epoch DESC,id DESC LIMIT 1',params).fetchone()
        meta={**dict(span),**(dict(latest) if latest else {}),'hostname':_cached_hostnames(c,[ip]).get(ip,''),'ip':ip}
        from app.services.client_identity import label
        meta['label']=label(c,ip);meta['display_name']=meta['label'] or meta['hostname'] or ip
        meta['identity_source']='manual' if meta['label'] else ('DNS/PTR' if meta['hostname'] else 'IP only')
    finally:c.close()
    return {'meta':meta,'summary':summary,'events':events,'applications':apps,'destinations':dest,'destination_ips':dips}



def _db_space_stats(c):
    page_size = int(c.execute("PRAGMA page_size").fetchone()[0])
    page_count = int(c.execute("PRAGMA page_count").fetchone()[0])
    freelist = int(c.execute("PRAGMA freelist_count").fetchone()[0])
    logical_used = max(0, page_count - freelist) * page_size
    file_bytes = DB_PATH.stat().st_size if DB_PATH.exists() else page_count * page_size
    free_bytes = shutil.disk_usage(DB_PATH.parent if DB_PATH.parent.exists() else DATA_ROOT).free
    return {
        "page_size": page_size, "page_count": page_count, "freelist_pages": freelist,
        "logical_used_bytes": logical_used, "db_file_bytes": file_bytes, "disk_free_bytes": free_bytes,
    }


def _cleanup_telemetry_connection(c):
    retention = max(1, min(365, int(_setting(c, "telemetry_retention_days", "30"))))
    hard_cap = max(256 * 1024 * 1024, int(_setting(c, "telemetry_max_used_bytes", str(8 * 1024**3))))
    target = max(128 * 1024 * 1024, int(_setting(c, "telemetry_cleanup_target_bytes", str(int(6.5 * 1024**3)))))
    target = min(target, hard_cap)
    min_free = max(1024 * 1024 * 1024, int(_setting(c, "telemetry_min_free_bytes", str(10 * 1024**3))))

    before_count = c.execute("SELECT COUNT(*) c FROM telemetry_events").fetchone()["c"]
    cutoff = time.time() - retention * 86400
    age_deleted = c.execute("DELETE FROM telemetry_events WHERE epoch < ?", (cutoff,)).rowcount
    deleted = max(age_deleted, 0)

    stats = _db_space_stats(c)
    # logical_used_bytes excludes reusable free pages inside SQLite. This avoids
    # repeatedly purging events merely because the physical file has not shrunk.
    pressure = stats["logical_used_bytes"] > hard_cap or stats["disk_free_bytes"] < min_free
    batches = 0
    while pressure and batches < 200:
        ids = [r["id"] for r in c.execute("SELECT id FROM telemetry_events ORDER BY epoch ASC,id ASC LIMIT 10000")]
        if not ids:
            break
        c.executemany("DELETE FROM telemetry_events WHERE id=?", ((x,) for x in ids))
        deleted += len(ids)
        batches += 1
        stats = _db_space_stats(c)
        if stats["logical_used_bytes"] <= target and stats["disk_free_bytes"] >= min_free:
            break
        pressure = stats["logical_used_bytes"] > hard_cap or stats["disk_free_bytes"] < min_free

    c.execute("PRAGMA optimize")
    try:
        c.execute("PRAGMA incremental_vacuum(2000)")
    except Exception:
        pass
    after_count = int(c.execute("SELECT COUNT(*) c FROM telemetry_events").fetchone()["c"] or 0)
    _set_state(c, "last_cleanup_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    _set_state(c, "last_cleanup_deleted", deleted)
    _set_state(c, "telemetry_event_count", after_count)
    edge=c.execute("SELECT MIN(event_time) first_event,MAX(event_time) last_event,MAX(epoch) last_epoch FROM telemetry_events").fetchone()
    _set_state(c,"telemetry_first_event",edge["first_event"] or "")
    _set_state(c,"telemetry_last_event",edge["last_event"] or "")
    _set_state(c,"telemetry_last_event_epoch",edge["last_epoch"] or "")
    _set_state(c, "last_cleanup_reason", "age+storage" if batches else "age")
    return {"deleted": deleted, "events_before": before_count, "events_after": after_count, **stats}


def cleanup_telemetry():
    c = connect()
    try:
        result = _cleanup_telemetry_connection(c)
        c.commit()
        try:
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:
            pass
        return result
    finally:
        c.close()


def cleanup_rotated_squid_logs():
    c = connect()
    try:
        days = max(1, min(90, int(_setting(c, "squid_raw_log_retention_days", "14"))))
        max_bytes = max(256 * 1024 * 1024, int(_setting(c, "squid_raw_log_max_bytes", str(4 * 1024**3))))
    finally:
        c.close()
    now = time.time()
    files = []
    if SQUID_LOG_DIR.exists():
        for p in SQUID_LOG_DIR.iterdir():
            if not p.is_file() or p.name == "access.log" or not p.name.startswith("access.log"):
                continue
            try:
                st = p.stat(); files.append((st.st_mtime, st.st_size, p))
            except OSError:
                pass
    removed = 0; freed = 0
    for mtime, size, p in list(files):
        if now - mtime > days * 86400:
            try: p.unlink(); removed += 1; freed += size
            except OSError: pass
    files = [(m,s,p) for m,s,p in files if p.exists()]
    total = sum(s for _,s,_ in files)
    for mtime,size,p in sorted(files):
        if total <= max_bytes: break
        try: p.unlink(); total -= size; removed += 1; freed += size
        except OSError: pass
    return {"removed_files": removed, "freed_bytes": freed, "remaining_rotated_bytes": total, "retention_days": days, "max_bytes": max_bytes}


def update_storage_settings(retention_days, max_gb, target_gb, min_free_gb, raw_days, raw_max_gb):
    retention_days=max(1,min(int(retention_days),365)); max_gb=max(1,min(float(max_gb),1000));
    target_gb=max(0.5,min(float(target_gb),max_gb)); min_free_gb=max(1,min(float(min_free_gb),1000));
    raw_days=max(1,min(int(raw_days),90)); raw_max_gb=max(0.25,min(float(raw_max_gb),1000))
    vals={
      "telemetry_retention_days":str(retention_days),
      "telemetry_max_used_bytes":str(int(max_gb*1024**3)),
      "telemetry_cleanup_target_bytes":str(int(target_gb*1024**3)),
      "telemetry_min_free_bytes":str(int(min_free_gb*1024**3)),
      "squid_raw_log_retention_days":str(raw_days),
      "squid_raw_log_max_bytes":str(int(raw_max_gb*1024**3)),
    }
    c=connect()
    try:
        for k,v in vals.items():
            c.execute("INSERT INTO settings(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP",(k,v))
        c.commit()
    finally:c.close()
    return vals


def telemetry_health():
    c=connect()
    try:
        count=int(_get_state(c,"telemetry_event_count","0") or 0)
        first=_get_state(c,"telemetry_first_event","") or None
        last=_get_state(c,"telemetry_last_event","") or None
        stats=_db_space_stats(c)
        return {
            "events":count,"first_event":first,"last_event":last,"last_ingest_at":_get_state(c,"last_ingest_at"),
            "last_ingest_inserted":_get_state(c,"last_ingest_inserted","0"),"retention_days":int(_setting(c,"telemetry_retention_days","30")),
            "max_used_bytes":int(_setting(c,"telemetry_max_used_bytes",str(8*1024**3))),
            "cleanup_target_bytes":int(_setting(c,"telemetry_cleanup_target_bytes",str(int(6.5*1024**3)))),
            "min_free_bytes":int(_setting(c,"telemetry_min_free_bytes",str(10*1024**3))),
            "raw_log_retention_days":int(_setting(c,"squid_raw_log_retention_days","14")),
            "raw_log_max_bytes":int(_setting(c,"squid_raw_log_max_bytes",str(4*1024**3))),
            "last_cleanup_at":_get_state(c,"last_cleanup_at"),"last_cleanup_deleted":_get_state(c,"last_cleanup_deleted","0"),
            "source":"Squid access.log","direct_visibility":False,**stats,
        }
    finally:c.close()


def update_retention(days):
    days=max(1,min(int(days),365));c=connect()
    try:
        c.execute("INSERT INTO settings(key,value,updated_at) VALUES('telemetry_retention_days',?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP",(str(days),));c.commit()
    finally:c.close()
    return days


def _export_rows(filters):
    where,params=_filter_sql(filters);c=connect()
    try:
        return [dict(r) for r in c.execute("""SELECT event_time,client_ip,network_name,vlan_id,decision,application_names,
            access_profile_names,method,destination_host,destination_ip,destination_port,result_code,http_status,bytes,
            elapsed_ms,hierarchy_code,upstream_ip,traffic_path,matched_rule_destination
            FROM telemetry_events t"""+where+" ORDER BY epoch DESC LIMIT 250000",params)]
    finally:c.close()


_EXPORT_HEADERS=["Time","Client IP","Network","VLAN","Decision","Application","Access Profile","Method","Destination Host","Destination IP","Port","Squid Result","HTTP Status","Bytes","Duration ms","Hierarchy","Upstream IP","Path","Matched Rule"]
_EXPORT_KEYS=["event_time","client_ip","network_name","vlan_id","decision","application_names","access_profile_names","method","destination_host","destination_ip","destination_port","result_code","http_status","bytes","elapsed_ms","hierarchy_code","upstream_ip","traffic_path","matched_rule_destination"]


def export_csv(filters):
    ensure_fresh();rows=_export_rows(filters);buf=io.StringIO();w=csv.writer(buf,quoting=csv.QUOTE_ALL);w.writerow(_EXPORT_HEADERS)
    for r in rows:w.writerow([csv_cell(r.get(k,"")) for k in _EXPORT_KEYS])
    return buf.getvalue().encode("utf-8-sig")


def _xlsx_col(n):
    s=""
    while n:
        n,rem=divmod(n-1,26);s=chr(65+rem)+s
    return s


def export_xlsx(filters):
    """Generate a standards-compliant, dependency-free XLSX export."""
    ensure_fresh();rows=_export_rows(filters);all_rows=[_EXPORT_HEADERS]+[[r.get(k,"") for k in _EXPORT_KEYS] for r in rows]
    sheet=[]
    for ri,row in enumerate(all_rows,1):
        cells=[]
        for ci,val in enumerate(row,1):
            ref=f"{_xlsx_col(ci)}{ri}"
            if isinstance(val,(int,float)) and val is not None:
                cells.append(f'<c r="{ref}" t="n"><v>{val}</v></c>')
            else:
                text=escape("" if val is None else "".join(ch for ch in str(val) if ch in "\t\n\r" or 0x20<=ord(ch)<=0xD7FF or 0xE000<=ord(ch)<=0xFFFD or 0x10000<=ord(ch)<=0x10FFFF))
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{text}</t></is></c>')
        sheet.append(f'<row r="{ri}">'+"".join(cells)+"</row>")
    sheet_xml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetData>'+"".join(sheet)+'</sheetData><autoFilter ref="A1:S%d"/></worksheet>'%len(all_rows)
    out=io.BytesIO()
    with zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>')
        z.writestr("_rels/.rels",'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr("xl/workbook.xml",'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Traffic Explorer" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels",'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
        z.writestr("xl/worksheets/sheet1.xml",sheet_xml)
    return out.getvalue()
