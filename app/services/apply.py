import fcntl
from contextlib import contextmanager
from app.config import DATA_ROOT, MODE
from app.db import audit,connect
from app.services.deployment import deploy,effective_policy_changed,reconcile_pending_if_no_diff

LOCK_PATH=DATA_ROOT/"policy-apply.lock"

def _role_for_actor(actor):
    c=connect()
    try:
        row=c.execute("SELECT role FROM users WHERE username=? AND enabled=1",(actor,)).fetchone()
        return row["role"] if row else None
    finally:
        c.close()

@contextmanager
def _apply_lock():
    LOCK_PATH.parent.mkdir(parents=True,exist_ok=True)
    with open(LOCK_PATH,"a+",encoding="utf-8") as f:
        fcntl.flock(f.fileno(),fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f.fileno(),fcntl.LOCK_UN)

def save_apply_state():
    return {"dirty":effective_policy_changed()}

def apply_saved_change(actor,source_ip=None,description="Saved policy change",preexisting_dirty=False,role=None):
    """Apply one saved desired-state change immediately when safe.

    Admin saves are validated and applied atomically. Operator saves remain
    pending for Admin approval. If an unrelated effective diff already existed
    before this save, auto-apply is deliberately blocked so one Save can never
    silently publish another person's earlier pending work.
    """
    role=role or _role_for_actor(actor)
    if role!="admin":
        audit(actor,"SAVE_APPLY","PENDING_APPROVAL","policy",None,source_ip)
        return {"ok":True,"applied":False,"pending_approval":True,"reason":"administrator approval required"}

    if MODE!="production":
        audit(actor,"SAVE_APPLY","CANDIDATE_ONLY","policy",None,source_ip)
        return {"ok":True,"applied":False,"candidate_only":True,"reason":"candidate preview"}

    if preexisting_dirty:
        audit(actor,"SAVE_APPLY","BLOCKED_EXISTING_PENDING","policy",None,source_ip)
        return {"ok":True,"applied":False,"pending_approval":True,"reason":"existing unapplied policy changes"}

    with _apply_lock():
        # Another request may have applied the same effective desired state
        # while this request was waiting for the lock.
        reconciled=reconcile_pending_if_no_diff()
        if reconciled.get("cleared"):
            audit(actor,"SAVE_APPLY","NO_EFFECTIVE_CHANGE","policy",None,source_ip)
            return {"ok":True,"applied":False,"no_effective_change":True}

        try:
            result=deploy(actor,source_ip,description)
        except Exception as exc:
            audit(actor,"SAVE_APPLY","FAILED","policy",None,source_ip)
            return {"ok":False,"applied":False,"error":str(exc) or "Apply failed"}

        if result.get("ok"):
            audit(actor,"SAVE_APPLY","SUCCESS","policy",None,source_ip)
            return {"ok":True,"applied":True,"result":result}

        audit(actor,"SAVE_APPLY","FAILED","policy",None,source_ip)
        return {"ok":False,"applied":False,"error":result.get("message") or "Apply failed","result":result}

def apply_message(result):
    if result.get("applied"):
        return "Saved and applied to production"
    if result.get("no_effective_change"):
        return "Saved"
    if result.get("candidate_only"):
        return "Saved in candidate preview"
    if result.get("pending_approval"):
        if result.get("reason")=="existing unapplied policy changes":
            return "Saved. Existing unapplied changes require one-time Admin review before direct Save can resume"
        return "Saved. Administrator approval required"
    if not result.get("ok"):
        return "Saved, but production apply failed; previous policy remains active"
    return "Saved"
