"""Revocable, expiring read-only integration credentials. Raw keys are never stored."""
import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from app.db import connect, audit

SCOPES={'clients:read','traffic:read'}


def create_token(name, scopes, days, actor):
    name=name.strip();scopes=sorted(set(scopes))
    if not name or len(name)>80 or not scopes or not set(scopes)<=SCOPES or not 1<=days<=365:
        raise ValueError('Enter a name, at least one read permission and an expiry of 1–365 days.')
    raw='swg_'+secrets.token_urlsafe(32)
    expires=(datetime.now(timezone.utc)+timedelta(days=days)).isoformat()
    c=connect()
    try:
        owner=c.execute("SELECT id FROM users WHERE username=? AND enabled=1 AND role='admin'",(actor,)).fetchone()
        if not owner:raise ValueError('Administrator required.')
        cid=c.execute('INSERT INTO api_tokens(name,token_hash,token_prefix,scopes_json,owner_id,expires_at) VALUES(?,?,?,?,?,?)',
            (name,hashlib.sha256(raw.encode()).hexdigest(),raw[:12],json.dumps(scopes),owner['id'],expires)).lastrowid;c.commit()
    finally:c.close()
    audit(actor,'API_TOKEN_CREATE','SUCCESS','api_token',cid)
    return raw


def tokens():
    c=connect()
    try:return [dict(r) for r in c.execute('SELECT id,name,token_prefix,scopes_json,created_at,expires_at,revoked_at,last_used_at FROM api_tokens ORDER BY id DESC')]
    finally:c.close()


def revoke_token(token_id, actor):
    c=connect()
    try:c.execute('UPDATE api_tokens SET revoked_at=CURRENT_TIMESTAMP WHERE id=?',(token_id,));c.commit()
    finally:c.close()
    audit(actor,'API_TOKEN_REVOKE','SUCCESS','api_token',token_id)


def authenticate(request):
    # Cookie sessions never authorize this integration interface.
    if request.url.scheme!='https':raise HTTPException(400,'Use HTTPS for the integration API.')
    header=request.headers.get('authorization','')
    if not header.startswith('Bearer ') or len(header)>200:raise HTTPException(401,'Bearer token required.')
    raw=header[7:]
    digest=hashlib.sha256(raw.encode()).hexdigest();now=int(time.time())
    c=connect()
    try:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute("""SELECT t.* FROM api_tokens t JOIN users u ON u.id=t.owner_id
            WHERE t.token_hash=? AND t.revoked_at IS NULL AND julianday(t.expires_at)>julianday('now') AND u.enabled=1 AND u.role='admin'""",(digest,)).fetchone()
        if not row:raise HTTPException(401,'Invalid, expired or revoked token.')
        window=now//60
        count=row['request_count']+1 if row['window_start']==window else 1
        if count>120:raise HTTPException(429,'Rate limit exceeded; retry next minute.',headers={'Retry-After':'60'})
        c.execute('UPDATE api_tokens SET window_start=?,request_count=?,last_used_at=CURRENT_TIMESTAMP WHERE id=?',(window,count,row['id']));c.commit()
        return {'id':row['id'],'scopes':json.loads(row['scopes_json'])}
    finally:c.close()


def require_scope(request, scope):
    identity=getattr(request.state,'api_identity',None)
    if not identity or scope not in identity['scopes']:raise HTTPException(403,'Token permission required: '+scope)
