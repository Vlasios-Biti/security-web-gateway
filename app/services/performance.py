from __future__ import annotations

import math
import os
import shutil
import socket
import subprocess
import time
from datetime import datetime

from app.config import DB_PATH, PROXY_IP, PROXY_PORT
from app.db import connect


def _read_cpu():
    with open('/proc/stat', 'r', encoding='utf-8') as f:
        parts = f.readline().split()[1:]
    vals = [int(x) for x in parts]
    while len(vals) < 8:
        vals.append(0)
    user,nice,system,idle,iowait,irq,softirq,steal = vals[:8]
    total = sum(vals[:8])
    busy = total - idle - iowait
    return {'total': total, 'busy': busy, 'iowait': iowait, 'steal': steal}


def _state(c, key, default=None):
    r = c.execute('SELECT value FROM telemetry_state WHERE key=?', (key,)).fetchone()
    return r['value'] if r else default


def _set_state(c, key, value):
    c.execute(
        "INSERT INTO telemetry_state(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP",
        (key, str(value)),
    )


def _cpu_percent(c):
    now = _read_cpu()
    old_raw = _state(c, 'perf_cpu_snapshot')
    cpu = iowait = 0.0
    if old_raw:
        try:
            ot, ob, oi = (int(x) for x in old_raw.split(':'))
            dt = max(1, now['total'] - ot)
            cpu = max(0.0, min(100.0, (now['busy'] - ob) * 100.0 / dt))
            iowait = max(0.0, min(100.0, (now['iowait'] - oi) * 100.0 / dt))
        except Exception:
            pass
    _set_state(c, 'perf_cpu_snapshot', f"{now['total']}:{now['busy']}:{now['iowait']}")
    return round(cpu, 2), round(iowait, 2)


def _memory_percent():
    vals = {}
    try:
        with open('/proc/meminfo', 'r', encoding='utf-8') as f:
            for line in f:
                k, v = line.split(':', 1)
                vals[k] = int(v.strip().split()[0])
        total = vals.get('MemTotal', 0)
        avail = vals.get('MemAvailable', 0)
        return round((total - avail) * 100.0 / total, 2) if total else 0.0
    except Exception:
        return 0.0


def _percentile(values, q):
    if not values:
        return None
    xs = sorted(float(v) for v in values)
    pos = (len(xs) - 1) * q
    lo = int(math.floor(pos)); hi = int(math.ceil(pos))
    if lo == hi:
        return round(xs[lo], 2)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (pos - lo), 2)


def _proxy_connections():
    try:
        p = subprocess.run(
            ['/usr/bin/ss', '-Htan', 'state', 'established'],
            capture_output=True, text=True, timeout=3, check=False,
        )
        needle = f':{PROXY_PORT}'
        return sum(1 for line in p.stdout.splitlines() if needle in line)
    except Exception:
        return 0


def collect_performance_sample():
    c = connect()
    try:
        cpu, iowait = _cpu_percent(c)
        try:
            load1, load5, _ = os.getloadavg()
        except Exception:
            load1 = load5 = 0.0
        mem = _memory_percent()
        disk = shutil.disk_usage('/')
        disk_pct = round(disk.used * 100.0 / disk.total, 2) if disk.total else 0.0
        db_bytes = DB_PATH.stat().st_size if DB_PATH.exists() else 0
        r=c.execute("SELECT value FROM telemetry_state WHERE key='telemetry_last_event_epoch'").fetchone()
        last=r['value'] if r else None
        lag = max(0.0, time.time() - float(last)) if last else None
        values = [r['elapsed_ms'] for r in c.execute(
            "SELECT elapsed_ms FROM telemetry_events WHERE epoch>=? AND decision='ALLOW' "
            "AND elapsed_ms IS NOT NULL ORDER BY epoch DESC LIMIT 5000",
            (time.time() - 300,),
        )]
        p50 = _percentile(values, .50)
        p95 = _percentile(values, .95)
        p99 = _percentile(values, .99)
        conns = _proxy_connections()
        epoch = time.time()
        c.execute(
            """INSERT INTO performance_samples(epoch,cpu_percent,iowait_percent,load1,load5,memory_percent,
               disk_percent,disk_free_bytes,db_file_bytes,telemetry_lag_seconds,proxy_p50_ms,proxy_p95_ms,
               proxy_p99_ms,proxy_connections) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (epoch,cpu,iowait,load1,load5,mem,disk_pct,disk.free,db_bytes,lag,p50,p95,p99,conns),
        )
        days = int((c.execute("SELECT value FROM settings WHERE key='performance_retention_days'").fetchone() or {'value':'7'})['value'])
        c.execute('DELETE FROM performance_samples WHERE epoch < ?', (epoch - max(1,min(days,90))*86400,))
        c.commit()
        return latest_performance(c)
    finally:
        c.close()


def latest_performance(c=None):
    own = c is None
    c = c or connect()
    try:
        r = c.execute('SELECT * FROM performance_samples ORDER BY epoch DESC LIMIT 1').fetchone()
        return dict(r) if r else None
    finally:
        if own:
            c.close()


def performance_history(hours=6, limit=360):
    hours = max(1, min(int(hours), 168))
    c = connect()
    try:
        rows = c.execute(
            'SELECT * FROM performance_samples WHERE epoch>=? ORDER BY epoch DESC LIMIT ?',
            (time.time()-hours*3600, max(10,min(int(limit),2000))),
        ).fetchall()
        return [dict(r) for r in reversed(rows)]
    finally:
        c.close()
