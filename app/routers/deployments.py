from fastapi import APIRouter,Request,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.db import connect
from app.services.rules import pending_count
from app.services.deployment import preview_diff,rollback_to,drift_status,current_live,reconcile_pending_if_no_diff
from app.services.apply import apply_saved_change,apply_message
from app.config import MODE
router=APIRouter(prefix="/changes")
@router.get("/deployments",response_class=HTMLResponse)
def index(request:Request):
    c=connect()
    try:rows=[dict(x) for x in c.execute("SELECT * FROM deployments ORDER BY id DESC LIMIT 50")]
    finally:c.close()
    return request.app.state.templates.TemplateResponse(request=request,name="deployments/list.html",
        context={"request":request,"page_title":"Apply History","rows":rows,"pending_count":pending_count()})
@router.get("/review",response_class=HTMLResponse)
def review(request:Request):
    if request.state.user["role"] not in("admin","operator"):return HTMLResponse("Forbidden",403)
    reconcile_pending_if_no_diff()
    c=connect()
    try:
        rows=[dict(x) for x in c.execute("SELECT * FROM deployments ORDER BY id DESC LIMIT 12")]
        audits=[dict(x) for x in c.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 30")]
        failed_applies=c.execute("SELECT COUNT(*) c FROM audit_events WHERE action='SAVE_APPLY' AND result='FAILED'").fetchone()["c"]
        backup_count=c.execute("SELECT COUNT(*) c FROM audit_events WHERE action='SYSTEM_BACKUP' AND result='SUCCESS'").fetchone()["c"]
        last_backup=c.execute("SELECT timestamp,result FROM audit_events WHERE action='SYSTEM_BACKUP' ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        c.close()
    drift=drift_status();pc=pending_count()
    return request.app.state.templates.TemplateResponse(request=request,name="deployments/review.html",
        context={"request":request,"page_title":"Activity","pending_count":pc,"diff":preview_diff(),"rows":rows,"drift":drift,
        "audit_rows":audits,"failed_applies":failed_applies,"backup_count":backup_count,"last_backup":dict(last_backup) if last_backup else None})

@router.get("/drift",response_class=HTMLResponse)
def drift(request:Request):
    import difflib
    c=connect()
    try: dep=c.execute("SELECT version,config_sha256,config_content,deployed_at FROM deployments WHERE status='deployed' ORDER BY id DESC LIMIT 1").fetchone()
    finally:c.close()
    live=current_live();diff=""
    if dep: diff="".join(difflib.unified_diff((dep["config_content"] or "").splitlines(True),live.splitlines(True),fromfile=f"expected-{dep['version']}",tofile="live"))
    return request.app.state.templates.TemplateResponse(request=request,name="deployments/drift.html",context={"request":request,"page_title":"Config Drift","drift":drift_status(),"diff":diff})

@router.post("/deploy")
def deploy_now(request:Request,description:str=Form(""),csrf_token:str=Form(...)):
    if MODE != "production": return RedirectResponse("/changes/review?error=Deploy+is+disabled+in+candidate+preview",303)
    u=request.state.user
    if u["role"]!="admin":return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    result=apply_saved_change(u["username"],auth.client_ip(request),description or "Approve existing pending policy",preexisting_dirty=False,role=u["role"])
    msg=apply_message(result)
    return RedirectResponse("/changes/review?msg="+msg.replace(" ","+") if result.get("ok") else "/changes/review?error="+msg.replace(" ","+"),303)
@router.post("/rollback/{deployment_id}")
def rollback(deployment_id:int,request:Request,csrf_token:str=Form(...)):
    if MODE != "production": return RedirectResponse("/changes/deployments?error=Rollback+is+disabled+in+candidate+preview",303)
    u=request.state.user
    if u["role"]!="admin":return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:result=rollback_to(deployment_id,u["username"],auth.client_ip(request))
    except Exception:return RedirectResponse("/changes/deployments?error=Rollback+failed",303)
    return RedirectResponse("/changes/deployments?msg=Rollback+completed" if result.get("ok") else "/changes/deployments?error=Rollback+failed",303)
