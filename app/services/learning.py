"""Legacy IP-based sessions are retired: correlation cannot establish ownership."""
from app.db import connect, audit

RETIRED_REASON = "IP-based automatic learning is disabled. Import a selected-tab capture or HAR workflow instead."


def latest_session(application_id):
    c = connect()
    try:
        row = c.execute("SELECT * FROM application_learning_sessions WHERE application_id=? ORDER BY id DESC LIMIT 1", (application_id,)).fetchone()
        return dict(row) if row else None
    finally:
        c.close()


def start_session(application_id, client_ip, actor):
    raise ValueError(RETIRED_REASON)


def stop_session(application_id, actor):
    c = connect()
    try:
        c.execute("UPDATE application_learning_sessions SET status='stopped' WHERE application_id=? AND status='active'", (application_id,))
        c.commit()
    finally:
        c.close()
    audit(actor, "LEARNING_STOP", "SUCCESS", "application", application_id)


def process_learning_sessions():
    # A deployed earlier review build may still have active sessions. Revoke
    # them before processing any traffic; never turn correlation into ALLOW.
    c = connect()
    try:
        rows = list(c.execute("SELECT id,started_by,client_ip FROM application_learning_sessions WHERE status='active'"))
        c.execute("UPDATE application_learning_sessions SET status='stopped',error_text=? WHERE status='active'", (RETIRED_REASON,))
        c.commit()
    finally:
        c.close()
    for row in rows:
        audit(row['started_by'], "LEARNING_RETIRED", "STOPPED", "learning_session", row['id'], row['client_ip'])
    return [{"session": row['id'], "status": "stopped", "reason": RETIRED_REASON} for row in rows]
