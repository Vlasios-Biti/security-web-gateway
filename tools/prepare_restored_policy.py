#!/usr/bin/env python3
"""Prepare an imported policy DB while retaining target-local connection state."""
import sqlite3

LOCAL_SETTINGS=('connection_policy','pac_endpoint')


def prepare_restored_policy(target_path,backup_path,staged_path):
    source=sqlite3.connect(target_path)
    try:
        with sqlite3.connect(backup_path) as backup:source.backup(backup)
        local={key:source.execute('SELECT value FROM settings WHERE key=?',(key,)).fetchone() for key in LOCAL_SETTINGS}
    finally:source.close()
    c=sqlite3.connect(staged_path)
    try:
        c.execute('DELETE FROM sessions')
        c.execute("UPDATE application_learning_sessions SET status='stopped' WHERE status='active'")
        c.execute("UPDATE discovery_runs SET status='discarded',error_text='Cancelled by state restore' WHERE status='running'")
        for table in ('health_test_queue','health_delivery_state','health_incidents'):c.execute('DELETE FROM '+table)
        for key,row in local.items():
            c.execute('DELETE FROM settings WHERE key=?',(key,))
            if row:c.execute('INSERT INTO settings(key,value) VALUES(?,?)',(key,row[0]))
        c.commit();c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    except Exception:c.rollback();raise
    finally:c.close()


if __name__=='__main__':
    import sys
    prepare_restored_policy(*sys.argv[1:])
