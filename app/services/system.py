import os
import shutil
import socket
import subprocess
from app.config import PROXY_IP, PROXY_PORT, DEFAULT_DNS_SERVERS


def run(cmd, timeout=5):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return {"ok": p.returncode == 0, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except Exception as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc)}


def service_status(name):
    r = run(["systemctl", "is-active", name])
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
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except Exception:
        return False


def dns_health():
    out = []
    for s in DEFAULT_DNS_SERVERS:
        r = run(["/usr/bin/dig", f"@{s}", "google.com", "A", "+time=2", "+tries=1", "+short"], 4)
        out.append({"server": s, "ok": bool(r["ok"] and r["stdout"])})
    return out
