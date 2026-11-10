import json
import sqlite3
from pathlib import Path
from app.config import DB_PATH

EXPECTED_MIGRATION = "017"


def connect(path=None):
    p = Path(path or DB_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=10000")
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("PRAGMA temp_store=MEMORY")
    c.execute("PRAGMA cache_size=-32768")
    try:
        c.execute("PRAGMA mmap_size=268435456")
    except sqlite3.DatabaseError:
        pass
    return c


def schema_version(path=None):
    c = connect(path)
    try:
        if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").fetchone():
            return None
        r = c.execute("SELECT MAX(version) v FROM schema_migrations").fetchone()
        return r["v"] if r else None
    finally:
        c.close()


def verify_schema():
    v = schema_version()
    if v != EXPECTED_MIGRATION:
        raise RuntimeError(
            f"Database migration level {v!r}; expected {EXPECTED_MIGRATION!r}. "
            "Run tools/migrate.py before starting the service. Runtime startup never mutates schema."
        )


def audit(actor, action, result, object_type=None, object_id=None, source_ip=None, details_json=None):
    c = connect()
    try:
        c.execute(
            "INSERT INTO audit_events(actor,action,object_type,object_id,source_ip,result,details_json) VALUES(?,?,?,?,?,?,?)",
            (actor, action, object_type, str(object_id) if object_id is not None else None, source_ip, result, details_json),
        )
        c.commit()
    finally:
        c.close()
