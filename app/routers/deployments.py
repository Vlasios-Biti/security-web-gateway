from fastapi import APIRouter,Request,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.db import connect
from app.services.rules import pending_count
from app.services.deployment import preview_diff,deploy,rollback_to,drift_status,current_live,reconcile_pending_if_no_diff
from app.config import MODE
router=APIRouter(prefix="/changes")
@router.get("/deployments",response_class=HTMLResponse)
def index(request:Request):
    c=connect()
    try:rows=[dict(x) for x in c.execute("SELECT * FROM deployments ORDER BY id DESC LIMIT 50")]
    finally:c.close()
    return request.app.state.templates.TemplateResponse(request=request,name="deployments/list.html",
        context={"request":request,"page_title":"Deployments","rows":rows,"pending_count":pending_count()})
@router.get("/review",response_class=HTMLResponse)
def review(request:Request):
    if request.state.user["role"] not in("admin","operator"):return HTMLResponse("Forbidden",403)
    reconcile_pending_if_no_diff()
    c=connect()
    try:
        rows=[dict(x) for x in c.execute("SELECT * FROM deployments ORDER BY id DESC LIMIT 8")]
    finally:
        c.close()
    return request.app.state.templates.TemplateResponse(request=request,name="deployments/review.html",
        context={"request":request,"page_title":"Activity","pending_count":pending_count(),"diff":preview_diff(),"rows":rows,"drift":drift_status()})

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
    result=deploy(u["username"],auth.client_ip(request),description)
    return RedirectResponse("/changes/review?msg=Deployment+successful" if result.get("ok") else "/changes/review?error=Deployment+failed",303)
@router.post("/rollback/{deployment_id}")
def rollback(deployment_id:int,request:Request,csrf_token:str=Form(...)):
    if MODE != "production": return RedirectResponse("/changes/deployments?error=Rollback+is+disabled+in+candidate+preview",303)
    u=request.state.user
    if u["role"]!="admin":return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:result=rollback_to(deployment_id,u["username"],auth.client_ip(request))
    except Exception:return RedirectResponse("/changes/deployments?error=Rollback+failed",303)
    return RedirectResponse("/changes/deployments?msg=Rollback+completed" if result.get("ok") else "/changes/deployments?error=Rollback+failed",303)
