from datetime import datetime,timezone
from argon2 import PasswordHasher
from fastapi import APIRouter,Request,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.db import connect,audit
PH=PasswordHasher();router=APIRouter(prefix="/security")
def admin(request):return request.state.user and request.state.user["role"]=="admin"
@router.get("/users",response_class=HTMLResponse)
def page(request:Request):
    if not admin(request):return HTMLResponse("Forbidden",403)
    c=connect()
    try:
        rows=[dict(x) for x in c.execute("SELECT id,username,role,enabled,failed_attempts,locked_until,last_login_at,created_at FROM users ORDER BY username")]
        sessions=[dict(x) for x in c.execute("""SELECT s.id,u.username,s.source_ip,s.user_agent,s.created_at,s.expires_at,s.last_seen_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.revoked_at IS NULL AND s.expires_at>? ORDER BY s.last_seen_at DESC""",(datetime.now(timezone.utc).isoformat(),))]
    finally:c.close()
    return request.app.state.templates.TemplateResponse(request=request,name="users/list.html",context={"request":request,"page_title":"Users & Sessions","rows":rows,"sessions":sessions})
@router.get("/users/add",response_class=HTMLResponse)
def add_page(request:Request):
    if not admin(request):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="users/add.html",context={"request":request,"page_title":"Add Local User","error":None})
@router.post("/users/add")
def add(request:Request,username:str=Form(...),password:str=Form(...),role:str=Form(...),csrf_token:str=Form(...)):
    u=request.state.user
    if not admin(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    username=username.strip().lower();err=None
    if len(username)<3 or not all(ch.isalnum() or ch in "._-" for ch in username):err="Invalid username."
    elif len(password)<14:err="Password must contain at least 14 characters."
    elif role not in("viewer","auditor","operator","admin"):err="Invalid role."
    if not err:
        c=connect()
        try:
            if c.execute("SELECT 1 FROM users WHERE username=?",(username,)).fetchone():err="Username already exists."
            else:c.execute("INSERT INTO users(username,password_hash,role,enabled) VALUES(?,?,?,1)",(username,PH.hash(password),role));c.commit()
        finally:c.close()
        if not err:audit(u["username"],"USER_CREATE","SUCCESS","user",username,auth.client_ip(request));return RedirectResponse("/security/users?msg=User+created",303)
    return request.app.state.templates.TemplateResponse(request=request,name="users/add.html",context={"request":request,"page_title":"Add Local User","error":err},status_code=400)
@router.get("/users/{user_id}/edit",response_class=HTMLResponse)
def edit_page(user_id:int,request:Request):
    if not admin(request):return HTMLResponse("Forbidden",403)
    c=connect()
    try:row=c.execute("SELECT id,username,role,enabled,failed_attempts,locked_until,last_login_at FROM users WHERE id=?",(user_id,)).fetchone()
    finally:c.close()
    if not row:return HTMLResponse("Not found",404)
    return request.app.state.templates.TemplateResponse(request=request,name="users/edit.html",context={"request":request,"page_title":"Manage User","target":dict(row),"error":None})
@router.post("/users/{user_id}/edit")
def edit_user(user_id:int,request:Request,role:str=Form(...),enabled:bool=Form(False),new_password:str=Form(""),unlock:bool=Form(False),csrf_token:str=Form(...)):
    u=request.state.user
    if not admin(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    if role not in("viewer","auditor","operator","admin"):return HTMLResponse("Invalid role",400)
    if new_password and len(new_password)<14:return HTMLResponse("New password must contain at least 14 characters.",400)
    c=connect();err=None;target=None
    try:
        target=c.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
        if not target:err="User not found."
        elif target["id"]==u["id"] and (not enabled or role!="admin"):err="You cannot disable or demote your own active administrator account."
        else:
            enabled_admins=c.execute("SELECT COUNT(*) c FROM users WHERE role='admin' AND enabled=1").fetchone()["c"]
            if target["role"]=="admin" and target["enabled"] and (not enabled or role!="admin") and enabled_admins<=1:err="Refused: at least one enabled administrator must remain."
        if not err:
            fields=[role,1 if enabled else 0];sql="UPDATE users SET role=?,enabled=?"
            if new_password:sql+=",password_hash=?";fields.append(PH.hash(new_password))
            if unlock:sql+=",failed_attempts=0,locked_until=NULL"
            sql+=",updated_at=CURRENT_TIMESTAMP WHERE id=?";fields.append(user_id);c.execute(sql,fields)
            if new_password or not enabled:c.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",(datetime.now(timezone.utc).isoformat(),user_id))
            c.commit()
    finally:c.close()
    if err:return request.app.state.templates.TemplateResponse(request=request,name="users/edit.html",context={"request":request,"page_title":"Manage User","target":dict(target) if target else {"id":user_id,"username":"?","role":role,"enabled":enabled},"error":err},status_code=400)
    audit(u["username"],"USER_UPDATE","SUCCESS","user",user_id,auth.client_ip(request));return RedirectResponse("/security/users?msg=User+updated",303)
@router.post("/sessions/{session_id}/revoke")
def revoke(session_id:int,request:Request,csrf_token:str=Form(...)):
    u=request.state.user
    if not admin(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    c=connect()
    try:c.execute("UPDATE sessions SET revoked_at=? WHERE id=?",(datetime.now(timezone.utc).isoformat(),session_id));c.commit()
    finally:c.close()
    audit(u["username"],"SESSION_REVOKE","SUCCESS","session",session_id,auth.client_ip(request));return RedirectResponse("/security/users?msg=Session+revoked",303)
