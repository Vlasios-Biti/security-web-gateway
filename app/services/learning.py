"""Finite, administrator-started learning from one client's correlated proxy traffic."""
import json
import ipaddress
import time
from app.db import connect, audit


def latest_session(application_id):
    c = connect()
    try:
        row = c.execute("SELECT * FROM application_learning_sessions WHERE application_id=? ORDER BY id DESC LIMIT 1", (application_id,)).fetchone()
        session = dict(row) if row else None
        if session and session['status']=='active' and session['expires_epoch']<=time.time():
            session['status']='completed'
        return session
    finally:
        c.close()


def start_session(application_id, client_ip, actor):
    from app.services.apply import save_apply_state
    address = str(ipaddress.IPv4Address(client_ip.strip()))
    if save_apply_state()["dirty"]:
        raise ValueError("Apply or review pending policy changes before starting learning.")
    now = time.time()
    c = connect()
    try:
        c.execute("BEGIN IMMEDIATE")
        user = c.execute("SELECT role FROM users WHERE username=? AND enabled=1", (actor,)).fetchone()
        if not user or user["role"] != "admin":
            raise ValueError("An Administrator must start a learning session.")
        app = c.execute("SELECT id FROM applications WHERE id=? AND status='active'", (application_id,)).fetchone()
        if not app:
            raise ValueError("Activate the application before learning.")
        c.execute("UPDATE application_learning_sessions SET status='completed' WHERE status='active' AND expires_epoch<=?", (now,))
        if c.execute("SELECT 1 FROM application_learning_sessions WHERE client_ip=? AND status='active'", (address,)).fetchone():
            raise ValueError("This device already has an active learning session. Stop it first.")
        cur = c.execute("INSERT INTO application_learning_sessions(application_id,client_ip,started_by,started_epoch,expires_epoch) VALUES(?,?,?,?,?)", (application_id, address, actor, now, now + 600))
        c.commit()
        session_id = cur.lastrowid
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()
    audit(actor, "LEARNING_START", "SUCCESS", "learning_session", session_id, address)
    return session_id


def stop_session(application_id, actor):
    c = connect()
    try:
        c.execute("UPDATE application_learning_sessions SET status='stopped' WHERE application_id=? AND status='active'", (application_id,))
        c.commit()
    finally:
        c.close()
    audit(actor, "LEARNING_STOP", "SUCCESS", "application", application_id)


def process_learning_sessions():
    from app.security import normalize_domain
    from app.services.discovery import _classify_endpoint, _public_addresses
    from app.services.access_model import create_application_dependency
    from app.services.apply import save_apply_state, apply_saved_change
    now = time.time()
    c = connect()
    try:
        c.execute("UPDATE application_learning_sessions SET status='completed' WHERE status='active' AND expires_epoch<=?", (now,))
        c.commit()
        sessions = [dict(r) for r in c.execute("SELECT s.*,a.seed_domain,a.status app_status,u.role,u.enabled FROM application_learning_sessions s JOIN applications a ON a.id=s.application_id LEFT JOIN users u ON u.username=s.started_by WHERE s.status='active' ORDER BY s.id LIMIT 10")]
    finally:
        c.close()
    results = []
    for session in sessions:
        sid, aid = session["id"], session["application_id"]
        try:
            if session["role"] != "admin" or not session["enabled"] or session["app_status"] != "active":
                raise ValueError("Learning stopped because the administrator or application is no longer active.")
            if save_apply_state()["dirty"]:
                raise ValueError("Learning paused: pending policy changes require administrator review.")
            c = connect()
            try:
                events = [dict(r) for r in c.execute("SELECT id,epoch,destination_host,destination_port FROM telemetry_events WHERE client_ip=? AND id>? AND epoch>=? AND epoch<=? AND decision='DENY' ORDER BY id LIMIT 1000", (session["client_ip"], session["last_event_id"], session["started_epoch"], min(now, session["expires_epoch"])))]
                selected = []
                for event in events:
                    # Require recent activity belonging to this application alone.
                    anchor = c.execute("SELECT application_ids FROM telemetry_events WHERE client_ip=? AND decision='ALLOW' AND epoch BETWEEN ? AND ? AND application_ids IS NOT NULL AND application_ids!='' ORDER BY epoch DESC,id DESC LIMIT 1", (session["client_ip"], max(session["started_epoch"], event["epoch"] - 60), event["epoch"])).fetchone()
                    ids = {int(x) for x in (anchor["application_ids"] or "").strip(",").split(",") if x.strip().isdigit()} if anchor else set()
                    if ids != {aid} or event["destination_port"] not in (80, 443):
                        continue
                    try:
                        host = normalize_domain(event["destination_host"], allow_wildcard=False)
                    except ValueError:
                        continue
                    classification, recommendation = _classify_endpoint(host, seed_host=session["seed_domain"])
                    if recommendation == "ignore":
                        continue
                    protocol = "HTTPS" if event["destination_port"] == 443 else "HTTP"
                    if c.execute("SELECT 1 FROM application_learning_destinations WHERE session_id=? AND destination=? AND protocol=?", (sid, host, protocol)).fetchone():
                        continue
                    if (host, protocol) not in {(x[0], x[1]) for x in selected}:
                        selected.append((host, protocol, event["id"]))
                if session["learned_count"] + len(selected) > 50:
                    raise ValueError("Learning reached the 50-destination limit. Review the session before continuing.")
            finally:
                c.close()
            added = 0
            for host, protocol, event_id in selected:
                # DNS validates public destinations before granting access; private
                # services and reserved addresses do not enter public-app policy.
                try:
                    _public_addresses(host, 443 if protocol == "HTTPS" else 80)
                except ValueError:
                    continue
                c = connect()
                try:
                    active = c.execute("SELECT status,expires_epoch FROM application_learning_sessions WHERE id=?", (sid,)).fetchone()
                    if active["status"] != "active" or active["expires_epoch"] <= time.time():
                        break
                finally:
                    c.close()
                rid = create_application_dependency(aid, "domain", host, protocol, session["started_by"], f"Learning session {sid}; correlated event {event_id}")
                c = connect()
                try:
                    c.execute("INSERT INTO application_learning_destinations VALUES(?,?,?,?,?)", (sid, host, protocol, event_id, rid))
                    c.execute("UPDATE application_rules SET source='live-learning',confidence='medium',metadata_json=? WHERE application_id=? AND rule_id=?", (json.dumps({"session_id":sid,"event_id":event_id}), aid, rid))
                    c.execute("UPDATE application_learning_sessions SET learned_count=learned_count+1 WHERE id=?", (sid,))
                    c.commit()
                finally:
                    c.close()
                audit(session["started_by"], "LEARNING_DEPENDENCY", "SAVED", "learning_session", sid, session["client_ip"], json.dumps({"destination":host}))
                added += 1
            if added:
                # One validation/reload per batch, never one reload per domain.
                applied = apply_saved_change(session["started_by"], session["client_ip"], f"Learn {added} dependencies for application {aid}")
                if not applied.get("ok") or applied.get("pending_approval"):
                    raise ValueError(applied.get("error") or "Learned destinations require administrator review.")
            c = connect()
            try:
                if events:
                    c.execute("UPDATE application_learning_sessions SET last_event_id=? WHERE id=?", (events[-1]["id"], sid))
                c.commit()
            finally:
                c.close()
            results.append({"session": sid, "learned": added})
        except Exception as exc:
            c = connect()
            try:
                c.execute("UPDATE application_learning_sessions SET status='failed',error_text=? WHERE id=?", (str(exc), sid))
                c.commit()
            finally:
                c.close()
            audit(session["started_by"], "LEARNING_SESSION", "FAILED", "learning_session", sid, session["client_ip"], json.dumps({"error":str(exc)}))
            results.append({"session": sid, "error": str(exc)})
    return results
