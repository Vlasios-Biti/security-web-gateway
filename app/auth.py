import hashlib
import secrets
import time
from datetime import datetime, timezone, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

from app.config import (
    SESSION_COOKIE,
    SESSION_HOURS,
    LOGIN_MAX_ATTEMPTS,
    LOGIN_LOCK_MINUTES,
    SESSION_TOUCH_INTERVAL_SECONDS,
)
from app.db import connect, audit

PH = PasswordHasher()
# Constant-work dummy hash reduces username enumeration timing differences.
_DUMMY_HASH = PH.hash("security-web-gateway-dummy-password-not-a-real-account")
_SESSION_TOUCH_CACHE = {}


def utcnow():
    return datetime.now(timezone.utc)


def client_ip(request):
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")


def user_from_request(request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    c = connect()
    try:
        r = c.execute(
            """SELECT s.id session_id,s.csrf_token,s.expires_at,s.revoked_at,s.last_seen_at,
                      u.id,u.username,u.role,u.enabled FROM sessions s
               JOIN users u ON u.id=s.user_id WHERE s.token_hash=?""",
            (digest,),
        ).fetchone()
        if not r or r["revoked_at"] or not r["enabled"]:
            return None
        exp = datetime.fromisoformat(r["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if utcnow() >= exp:
            return None

        # Avoid a SQLite write on every request. Touch a session at most once per
        # configured interval in each worker process. Authentication remains a
        # fast indexed read for normal page loads.
        now = time.time()
        last = _SESSION_TOUCH_CACHE.get(r["session_id"], 0)
        if now - last >= max(30, SESSION_TOUCH_INTERVAL_SECONDS):
            try:
                c.execute(
                    "UPDATE sessions SET last_seen_at=? WHERE id=?",
                    (utcnow().isoformat(), r["session_id"]),
                )
                c.commit()
                _SESSION_TOUCH_CACHE[r["session_id"]] = now
            except Exception:
                c.rollback()
        return dict(r)
    finally:
        c.close()


def authenticate(username, password, request):
    username = username.strip().lower()
    c = connect()
    try:
        r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not r or not r["enabled"]:
            try:
                PH.verify(_DUMMY_HASH, password)
            except Exception:
                pass
            audit(
                username or "<empty>",
                "LOGIN",
                "FAILED",
                source_ip=client_ip(request),
                details_json='{"reason":"invalid_credentials"}',
            )
            return None

        if r["locked_until"]:
            locked = datetime.fromisoformat(r["locked_until"])
            if locked.tzinfo is None:
                locked = locked.replace(tzinfo=timezone.utc)
            if utcnow() < locked:
                audit(
                    username,
                    "LOGIN",
                    "FAILED",
                    source_ip=client_ip(request),
                    details_json='{"reason":"account_locked"}',
                )
                return None

        try:
            PH.verify(r["password_hash"], password)
        except (VerifyMismatchError, VerificationError):
            attempts = int(r["failed_attempts"] or 0) + 1
            lock = (
                (utcnow() + timedelta(minutes=LOGIN_LOCK_MINUTES)).isoformat()
                if attempts >= LOGIN_MAX_ATTEMPTS
                else None
            )
            c.execute(
                "UPDATE users SET failed_attempts=?,locked_until=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (attempts, lock, r["id"]),
            )
            c.commit()
            audit(
                username,
                "LOGIN",
                "FAILED",
                source_ip=client_ip(request),
                details_json=f'{{"reason":"invalid_credentials","failed_attempts":{attempts}}}',
            )
            return None

        h = r["password_hash"]
        if PH.check_needs_rehash(h):
            h = PH.hash(password)
        c.execute(
            """UPDATE users SET failed_attempts=0,locked_until=NULL,last_login_at=?,password_hash=?,
               updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (utcnow().isoformat(), h, r["id"]),
        )
        c.commit()
        audit(username, "LOGIN", "SUCCESS", source_ip=client_ip(request))
        return dict(r)
    finally:
        c.close()


def create_session(user_id, request):
    token = secrets.token_urlsafe(48)
    digest = hashlib.sha256(token.encode()).hexdigest()
    csrf = secrets.token_urlsafe(32)
    now = utcnow()
    exp = now + timedelta(hours=SESSION_HOURS)
    c = connect()
    try:
        c.execute(
            """INSERT INTO sessions(user_id,token_hash,csrf_token,source_ip,user_agent,created_at,expires_at,last_seen_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (
                user_id,
                digest,
                csrf,
                client_ip(request),
                request.headers.get("user-agent", "")[:300],
                now.isoformat(),
                exp.isoformat(),
                now.isoformat(),
            ),
        )
        c.commit()
    finally:
        c.close()
    return token


def check_csrf(user, supplied):
    return bool(user and supplied and secrets.compare_digest(user["csrf_token"], supplied))


def revoke_current_session(request, user):
    if not user:
        return
    c = connect()
    try:
        c.execute(
            "UPDATE sessions SET revoked_at=? WHERE id=?",
            (utcnow().isoformat(), user["session_id"]),
        )
        c.commit()
    finally:
        c.close()
    audit(user["username"], "LOGOUT", "SUCCESS", source_ip=client_ip(request))
