import json
import os
import shutil
import socket
import subprocess
import time

from app.config import PROXY_IP, PROXY_PORT, DEFAULT_DNS_SERVERS, LOCAL_DNS_CACHE, LOCAL_DNS_IP
from app.db import connect


def run(cmd, timeout=5):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return {"ok": p.returncode == 0, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except Exception as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc)}


def service_status(name):
    r = run(["systemctl", "is-active", name], timeout=3)
    return r["stdout"] or "unknown"


def disk_usage():
    u = shutil.disk_usage("/")
    return {
        "total_gb": round(u.total / 1024**3, 1),
        "used_gb": round(u.used / 1024**3, 1),
        "free_gb": round(u.free / 1024**3, 1),
        "percent": round(u.used / u.total * 100, 1),
    }


def memory_usage():
    vals = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                vals[k] = int(v.strip().split()[0])
        total = vals.get("MemTotal", 0)
        avail = vals.get("MemAvailable", 0)
        used = total - avail
        return {
            "total_mb": round(total / 1024),
            "used_mb": round(used / 1024),
            "percent": round(used / total * 100, 1) if total else 0,
        }
    except Exception:
        return {"total_mb": 0, "used_mb": 0, "percent": 0}


def load_average():
    try:
        one, five, fifteen = os.getloadavg()
        return {"one": round(one, 2), "five": round(five, 2), "fifteen": round(fifteen, 2)}
    except Exception:
        return {"one": 0, "five": 0, "fifteen": 0}


def port_open(host=PROXY_IP, port=PROXY_PORT):
    """Passively verify that a TCP listener exists without connecting to Squid.

    An active self-connect pollutes Squid access.log with
    transaction-end-before-headers events and makes the appliance appear as a
    client. Listener state is enough here because service_status('squid') is
    collected separately in the same health payload.
    """
    wanted = f"{int(port):04X}"
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(table, "r", encoding="utf-8") as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) < 4 or parts[3] != "0A":
                        continue
                    local = parts[1]
                    if ":" not in local:
                        continue
                    _, hex_port = local.rsplit(":", 1)
                    if hex_port.upper() == wanted:
                        return True
        except OSError:
            continue
    return False


def _dig(server):
    started=time.perf_counter()
    r = run(["/usr/bin/dig", f"@{server}", "google.com", "A", "+time=1", "+tries=1", "+short"], 2)
    return {"server":server,"ok":bool(r["ok"] and r["stdout"]),"latency_ms":round((time.perf_counter()-started)*1000,1)}


def dns_health():
    out=[]
    if LOCAL_DNS_CACHE:
        x=_dig(LOCAL_DNS_IP);x["role"]="local-cache";out.append(x)
    for s in DEFAULT_DNS_SERVERS:
        x=_dig(s);x["role"]="upstream";out.append(x)
    return out


def live_system_health():
    from app.config import SERVICE_NAME
    return {
        "generated_at": time.time(),
        "squid_status": service_status("squid"),
        "nginx_status": service_status("nginx"),
        "app_status": service_status(SERVICE_NAME),
        "port_ok": port_open(),
        "dns": dns_health(),
        "disk": disk_usage(),
        "memory": memory_usage(),
        "load": load_average(),
        "local_dns_cache": bool(LOCAL_DNS_CACHE),
    }


def cache_system_health(ttl=30):
    payload=live_system_health();now=time.time();c=connect()
    try:
        c.execute(
            "INSERT INTO dashboard_cache(key,payload_json,generated_at,expires_at) VALUES('system:health',?,CURRENT_TIMESTAMP,?) "
            "ON CONFLICT(key) DO UPDATE SET payload_json=excluded.payload_json,generated_at=CURRENT_TIMESTAMP,expires_at=excluded.expires_at",
            (json.dumps(payload,separators=(",",":")),now+max(5,min(int(ttl),300))),
        );c.commit();return payload
    finally:c.close()


def cached_system_health():
    c=connect()
    try:r=c.execute("SELECT payload_json,generated_at,expires_at FROM dashboard_cache WHERE key='system:health'").fetchone()
    finally:c.close()
    if r:
        try:
            d=json.loads(r['payload_json']);d['cache_generated_at']=r['generated_at'];d['cache_stale']=float(r['expires_at'])<time.time();return d
        except Exception:pass
    return {
        "generated_at":None,"cache_generated_at":None,"cache_stale":True,
        "squid_status":"warming","nginx_status":"warming","app_status":"warming","port_ok":False,
        "dns":[],"disk":disk_usage(),"memory":memory_usage(),"load":load_average(),"local_dns_cache":bool(LOCAL_DNS_CACHE),
    }
