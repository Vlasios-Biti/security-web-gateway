import json
from fastapi import APIRouter,Request,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.db import audit
from app.services.system import service_status,disk_usage,memory_usage,port_open,dns_health,cached_system_health
from app.services.deployment import drift_status
from app.services.traffic import telemetry_health,update_storage_settings,cleanup_telemetry,cleanup_rotated_squid_logs
from app.services.operations import validate_squid,reload_squid,create_backup
from app.config import MODE
from app.services.performance import latest_performance,performance_history
from app.db import connect
router=APIRouter(prefix="/system")
@router.get("/health",response_class=HTMLResponse)
def page(request:Request):
    h=cached_system_health();perf=latest_performance();telemetry=telemetry_health();drift=drift_status()
    c=connect()
    try:
        last_apply=c.execute("SELECT id,version,status,created_by,deployed_at,description FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
        backup_count=c.execute("SELECT COUNT(*) c FROM audit_events WHERE action='SYSTEM_BACKUP' AND result='SUCCESS'").fetchone()["c"]
        last_backup=c.execute("SELECT timestamp,actor,result FROM audit_events WHERE action='SYSTEM_BACKUP' ORDER BY id DESC LIMIT 1").fetchone()
        apply_count=c.execute("SELECT COUNT(*) c FROM deployments WHERE status='deployed'").fetchone()["c"]
    finally:c.close()
    recovery={
      "last_apply":dict(last_apply) if last_apply else None,
      "backup_count":backup_count,
      "last_backup":dict(last_backup) if last_backup else None,
      "rollback_available":bool(apply_count),
    }
    alerts=[]
    if h["squid_status"]!="active":alerts.append({"severity":"critical","title":"Squid data plane is not active","detail":"Proxy enforcement requires immediate attention."})
    if h["nginx_status"]!="active" or h["app_status"]!="active":alerts.append({"severity":"critical","title":"Management plane service unavailable","detail":"Nginx or SWG Manager is not active."})
    if not h["port_ok"]:alerts.append({"severity":"critical","title":"Proxy listener TCP/3128 is down","detail":"Clients cannot use the explicit proxy endpoint."})
    if h["disk"].get("percent",0)>=85:alerts.append({"severity":"warning","title":"Disk utilization is high","detail":f"{h['disk']['percent']}% used; {h['disk']['free_gb']} GB free."})
    if h["memory"].get("percent",0)>=85:alerts.append({"severity":"warning","title":"Memory pressure is high","detail":f"{h['memory']['percent']}% memory used."})
    cert=h.get("certificate") or {}
    if cert.get("days_remaining") is not None and cert["days_remaining"]<=30:alerts.append({"severity":"warning" if cert["days_remaining"]>14 else "critical","title":"Management TLS certificate expires soon","detail":f"{cert['days_remaining']} days remaining."})
    if not (h.get("ntp") or {}).get("ok"):alerts.append({"severity":"warning","title":"NTP synchronization needs attention","detail":(h.get("ntp") or {}).get("state","unknown")})
    for d in h.get("dns",[]):
        if not d.get("ok"):alerts.append({"severity":"warning","title":"DNS resolver unavailable","detail":str(d.get("server","unknown"))})
    if drift.get("state")=="drift":alerts.append({"severity":"critical","title":"Managed Squid configuration drift detected","detail":drift.get("message","Expected and live policy differ.")})
    return request.app.state.templates.TemplateResponse(
      request=request,name="system/health.html",
      context={"request":request,"page_title":"System","health":h,"squid":h["squid_status"],"nginx":h["nginx_status"],"app":h["app_status"],
      "disk":h["disk"],"memory":h["memory"],"swap":h.get("swap",{}),"port_ok":h["port_ok"],"dns":h["dns"],"drift":drift,
      "telemetry":telemetry,"perf":perf,"history":performance_history(6,360),"recovery":recovery,"alerts":alerts,"mode":MODE})

@router.get("/performance",response_class=HTMLResponse)
def performance_page(request:Request):
    return request.app.state.templates.TemplateResponse(request=request,name="system/performance.html",context={"request":request,"page_title":"System Performance","perf":latest_performance(),"history":performance_history(6,360)})

def _admin(request):return request.state.user and request.state.user["role"]=="admin"

@router.get("/backups",response_class=HTMLResponse)
def backups(request:Request):
    if not _admin(request):return HTMLResponse("Forbidden",403)
    from app.db import connect
    c=connect()
    try:rows=[dict(x) for x in c.execute("SELECT * FROM audit_events WHERE action='SYSTEM_BACKUP' ORDER BY id DESC LIMIT 50")]
    finally:c.close()
    return request.app.state.templates.TemplateResponse(request=request,name="system/backups.html",context={"request":request,"page_title":"Configuration Backups","rows":rows,"mode":MODE})

@router.post("/actions/{action}")
def action(action:str,request:Request,csrf_token:str=Form(...)):
    u=request.state.user
    if not _admin(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    funcs={"validate-squid":validate_squid,"reload-squid":reload_squid,"backup":create_backup}
    if action not in funcs:return HTMLResponse("Unsupported action",400)
    try:r=funcs[action]();audit(u["username"],"SYSTEM_"+action.upper().replace("-","_"),"SUCCESS" if r.get("ok") else "FAILED","system",action,auth.client_ip(request),json.dumps(r))
    except Exception as exc:r={"ok":False,"message":str(exc)}
    key="msg" if r.get("ok") else "error";return RedirectResponse("/system/health?"+key+"="+str(r.get("message","Done")).replace(" ","+"),303)


@router.get("/storage",response_class=HTMLResponse)
def storage_page(request:Request):
    if not _admin(request):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="system/storage.html",context={"request":request,"page_title":"Storage / Telemetry","telemetry":telemetry_health()})

@router.post("/storage/settings")
def storage_settings(request:Request,retention_days:int=Form(...),max_gb:float=Form(...),target_gb:float=Form(...),min_free_gb:float=Form(...),raw_days:int=Form(...),raw_max_gb:float=Form(...),csrf_token:str=Form(...)):
    u=request.state.user
    if not _admin(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        vals=update_storage_settings(retention_days,max_gb,target_gb,min_free_gb,raw_days,raw_max_gb)
        audit(u["username"],"STORAGE_SETTINGS","SUCCESS","settings","storage",auth.client_ip(request),json.dumps(vals))
        return RedirectResponse("/system/storage?msg=Storage+guardrails+updated",303)
    except Exception as exc:return RedirectResponse("/system/storage?error="+str(exc).replace(" ","+"),303)

@router.post("/storage/cleanup")
def storage_cleanup(request:Request,csrf_token:str=Form(...)):
    u=request.state.user
    if not _admin(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    result={"telemetry":cleanup_telemetry(),"squid_logs":cleanup_rotated_squid_logs()}
    audit(u["username"],"STORAGE_CLEANUP","SUCCESS","system","storage",auth.client_ip(request),json.dumps(result))
    return RedirectResponse("/system/storage?msg=Storage+cleanup+completed",303)
