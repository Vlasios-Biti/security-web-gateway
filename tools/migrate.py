#!/usr/bin/env python3
import argparse,sqlite3
from pathlib import Path

def main(db,root):
    db=Path(db);db.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(db,timeout=30)
    try:
        c.execute("PRAGMA foreign_keys=ON");c.execute("PRAGMA busy_timeout=30000");c.execute("PRAGMA journal_mode=WAL");c.execute("PRAGMA synchronous=FULL")
        c.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY,applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)");c.commit()
        applied={r[0] for r in c.execute("SELECT version FROM schema_migrations")}
        for f in sorted((Path(root)/"migrations").glob("*.sql")):
            v=f.name.split("_",1)[0]
            if v in applied:continue
            if not v.isdigit():raise RuntimeError(f"Unsafe migration version: {v}")
            script=f.read_text()
            try:
                c.executescript("BEGIN IMMEDIATE;\n"+script+f"\nINSERT INTO schema_migrations(version) VALUES('{v}');\nCOMMIT;\n")
            except Exception:
                try:c.execute("ROLLBACK")
                except Exception:pass
                raise
        integ=c.execute("PRAGMA integrity_check").fetchone()[0]
        if integ!="ok":raise RuntimeError("integrity_check: "+integ)
        fk=list(c.execute("PRAGMA foreign_key_check"))
        if fk:raise RuntimeError("foreign_key_check failed: "+repr(fk[:3]))
        print(c.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0])
    finally:c.close()
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--db",required=True);p.add_argument("--root",required=True);a=p.parse_args();main(a.db,a.root)
