import json
from urllib.parse import urlparse
from fastapi import APIRouter,Request,Form,File,UploadFile
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.db import audit,connect
from app.services.access_model import list_applications,get_application,create_application,update_application,set_application_status,delete_application,list_policy_groups,create_application_dependency,set_application_dependency_status
from app.services.discovery import catalog_search,create_run,create_har_run,get_run,list_runs,approve_run
from app.services.rules import list_networks
router=APIRouter(prefix="/applications")

def can_manage(r):return r.state.user and r.state.user["role"] in("admin","operator")

def admin(r):return r.state.user and r.state.user["role"]=="admin"

def can_modify_application(r,app):
    if not can_manage(r):return False
    return admin(r) if app and app.get("system_managed") else True

@router.get("",response_class=HTMLResponse)
def index(request:Request):
    return request.app.state.templates.TemplateResponse(request=request,name="applications/list.html",context={"request":request,"page_title":"Application Policies","applications":list_applications(),"runs":list_runs(10)})

@router.get("/add",response_class=HTMLResponse)
def add_page(request:Request):
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="applications/form.html",context={"request":request,"page_title":"Add Application Policy","application":None,"networks":list_networks(),"groups":list_policy_groups(),"error":None})

@router.post("/add")
def add_submit(request:Request,name:str=Form(...),provider:str=Form(""),description:str=Form(""),seed_domain:str=Form(""),source_kind:str=Form("manual"),source_ref:str=Form(""),auto_monitor:int=Form(0),network_ids:list[int]=Form(default=[]),policy_group_ids:list[int]=Form(default=[]),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        aid=create_application(name,provider,description,seed_domain,source_kind,source_ref,bool(auto_monitor),u["username"]);update_application(aid,name,provider,description,seed_domain,source_kind,source_ref,bool(auto_monitor),network_ids,u["username"],policy_group_ids);audit(u["username"],"APPLICATION_CREATE","SUCCESS","application",aid,auth.client_ip(request));return RedirectResponse(f"/applications/{aid}?msg=Application+created.+Add+or+discover+dependencies",303)
    except Exception as exc:return request.app.state.templates.TemplateResponse(request=request,name="applications/form.html",context={"request":request,"page_title":"Add Application Policy","application":None,"networks":list_networks(),"groups":list_policy_groups(),"error":str(exc)},status_code=400)

@router.get("/discover",response_class=HTMLResponse)
def discover_page(request:Request,query:str=""):
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="applications/discover.html",context={"request":request,"page_title":"Discover Application","query":query,"catalog":catalog_search(query) if query else [],"groups":list_policy_groups(),"error":None})

@router.post("/discover/catalog")
def discover_catalog(request:Request,catalog_key:str=Form(...),policy_group_ids:list[int]=Form(default=[]),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    item=next((x for x in catalog_search("") if x["key"]==catalog_key),None)
    if not item:return RedirectResponse("/applications/discover?error=Unknown+catalog+application",303)
    try:
        c=connect();existing=c.execute("SELECT id FROM applications WHERE name=? AND status!='deleted'",(item["name"],)).fetchone();c.close()
        aid=existing["id"] if existing else create_application(item["name"],item["provider"],item["description"],item["seed_domain"],item.get("source_kind",item["method"]),item.get("source_ref",catalog_key),bool(item.get("auto_monitor")),u["username"],system_managed=False)
        if policy_group_ids:
            c=connect()
            try:
                for gid in {int(x) for x in policy_group_ids}:c.execute("INSERT OR IGNORE INTO policy_group_applications(group_id,application_id) VALUES(?,?)",(gid,aid));c.execute("UPDATE policy_groups SET pending=1 WHERE id=?",(gid,))
                c.commit()
            finally:c.close()
        method=item["method"]
        rid=create_run(aid,item.get("seed_domain") or item["name"],method,u["username"],source_ref=item.get("source_ref"),catalog_key=catalog_key);audit(u["username"],"DISCOVERY_START","SUCCESS","discovery_run",rid,auth.client_ip(request),json.dumps({"catalog":catalog_key,"method":method}));return RedirectResponse(f"/applications/discovery/{rid}",303)
    except Exception as exc:return RedirectResponse("/applications/discover?error="+str(exc).replace(" ","+"),303)

@router.post("/discover/custom")
def discover_custom(request:Request,name:str=Form(...),seed_domain:str=Form(""),method:str=Form(...),source_ref:str=Form(""),client_ip:str=Form(""),window_minutes:int=Form(10),auto_approve:int=Form(0),policy_group_ids:list[int]=Form(default=[]),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        if method=="browser_auto" and not seed_domain.strip():
            p=urlparse(source_ref.strip())
            seed_domain=(p.hostname or "").strip().lower()
        c=connect();existing=c.execute("SELECT id FROM applications WHERE name=? AND status!='deleted'",(name.strip(),)).fetchone();c.close()
        aid=existing["id"] if existing else create_application(name,"Custom",f"Managed web application: {name}",seed_domain,"official_url" if method=="official_url" else "observed",source_ref,False,u["username"])
        if policy_group_ids:
            c=connect()
            try:
                for gid in {int(x) for x in policy_group_ids}:c.execute("INSERT OR IGNORE INTO policy_group_applications VALUES(?,?)",(gid,aid));c.execute("UPDATE policy_groups SET pending=1 WHERE id=?",(gid,))
                c.commit()
            finally:c.close()
        query=seed_domain if method=="seed_probe" else (source_ref if method=="browser_auto" else name)
        rid=create_run(aid,query,method,u["username"],source_ref=source_ref,client_ip=client_ip,window_minutes=window_minutes,auto_approve=bool(auto_approve));audit(u["username"],"DISCOVERY_START","SUCCESS","discovery_run",rid,auth.client_ip(request),json.dumps({"method":method,"automatic":bool(auto_approve)}))
        if auto_approve:
            return RedirectResponse(f"/applications/{aid}?msg=Application+created.+Dependencies+are+being+discovered+automatically",303)
        return RedirectResponse(f"/applications/discovery/{rid}",303)
    except Exception as exc:return RedirectResponse("/applications/discover?error="+str(exc).replace(" ","+"),303)

@router.post("/discover/har")
async def discover_har_upload(request:Request,name:str=Form(...),seed_domain:str=Form(""),policy_group_ids:list[int]=Form(default=[]),har_file:UploadFile=File(...),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        raw=await har_file.read()
        c=connect();existing=c.execute("SELECT id FROM applications WHERE name=? AND status!='deleted'",(name.strip(),)).fetchone();c.close()
        aid=existing["id"] if existing else create_application(name,"Custom",f"Discovered application: {name}",seed_domain,"observed","HAR workflow",False,u["username"])
        if policy_group_ids:
            c=connect()
            try:
                for gid in {int(x) for x in policy_group_ids}:
                    c.execute("INSERT OR IGNORE INTO policy_group_applications VALUES(?,?)",(gid,aid));c.execute("UPDATE policy_groups SET pending=1 WHERE id=?",(gid,))
                c.commit()
            finally:c.close()
        rid=create_har_run(aid,seed_domain,raw,u["username"])
        audit(u["username"],"DISCOVERY_HAR","SUCCESS","discovery_run",rid,auth.client_ip(request),json.dumps({"filename":har_file.filename,"bytes":len(raw)}))
        return RedirectResponse(f"/applications/discovery/{rid}",303)
    except Exception as exc:
        return RedirectResponse("/applications/discover?error="+str(exc).replace(" ","+"),303)


@router.get("/discovery/{run_id}",response_class=HTMLResponse)
def discovery_result(run_id:int,request:Request):
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    run=get_run(run_id)
    if not run:return HTMLResponse("Not found",404)
    app=get_application(run["application_id"]) if run.get("application_id") else None
    return request.app.state.templates.TemplateResponse(request=request,name="applications/discovery_result.html",context={"request":request,"page_title":"Discovery Review","run":run,"can_approve":can_modify_application(request,app) if app else can_manage(request)})

@router.post("/discovery/{run_id}/approve")
def discovery_approve(run_id:int,request:Request,candidate_ids:list[int]=Form(default=[]),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    run=get_run(run_id)
    if not run:return HTMLResponse("Not found",404)
    app=get_application(run["application_id"]) if run.get("application_id") else None
    if app and not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:r=approve_run(run_id,candidate_ids,u["username"]);audit(u["username"],"DISCOVERY_APPROVE","SUCCESS","discovery_run",run_id,auth.client_ip(request),json.dumps(r));run=get_run(run_id);return RedirectResponse(f"/applications/{run['application_id']}?msg=Discovery+approved+as+pending+change",303)
    except Exception as exc:return RedirectResponse(f"/applications/discovery/{run_id}?error="+str(exc).replace(" ","+"),303)

@router.get("/{application_id}/activity")
def application_activity(application_id:int,request:Request):
    app=get_application(application_id)
    if not app:return {"status":"missing"}
    c=connect()
    try:
        run=c.execute("""SELECT status,error_text,started_at,completed_at
          FROM discovery_runs WHERE application_id=? ORDER BY id DESC LIMIT 1""",(application_id,)).fetchone()
    finally:
        c.close()
    active_dependencies=sum(1 for x in app.get("dependencies",[]) if x.get("dependency_enabled")==1 and x.get("status")=="active")
    return {
        "status": run["status"] if run else "idle",
        "error": run["error_text"] if run else None,
        "started_at": run["started_at"] if run else None,
        "completed_at": run["completed_at"] if run else None,
        "dependency_count": active_dependencies,
        "last_discovery_at": app.get("last_discovery_at"),
        "pending": bool(app.get("pending")),
    }


@router.get("/{application_id}",response_class=HTMLResponse)
def detail(application_id:int,request:Request):
    app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    c=connect()
    try:runs=[dict(x) for x in c.execute("SELECT * FROM discovery_runs WHERE application_id=? ORDER BY id DESC LIMIT 15",(application_id,))]
    finally:c.close()
    return request.app.state.templates.TemplateResponse(request=request,name="applications/detail.html",context={"request":request,"page_title":app["name"],"application":app,"runs":runs})

@router.get("/{application_id}/edit",response_class=HTMLResponse)
def edit_page(application_id:int,request:Request):
    app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="applications/form.html",context={"request":request,"page_title":"Edit Application Policy","application":app,"networks":list_networks(),"groups":list_policy_groups(),"error":None})

@router.post("/{application_id}/edit")
def edit_submit(application_id:int,request:Request,name:str=Form(...),provider:str=Form(""),description:str=Form(""),seed_domain:str=Form(""),source_kind:str=Form("manual"),source_ref:str=Form(""),auto_monitor:int=Form(0),network_ids:list[int]=Form(default=[]),policy_group_ids:list[int]=Form(default=[]),csrf_token:str=Form(...)):
    u=request.state.user;app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:update_application(application_id,name,provider,description,seed_domain,source_kind,source_ref,bool(auto_monitor),network_ids,u["username"],policy_group_ids);audit(u["username"],"APPLICATION_EDIT","SUCCESS","application",application_id,auth.client_ip(request));return RedirectResponse(f"/applications/{application_id}?msg=Application+updated+as+pending+change",303)
    except Exception as exc:return request.app.state.templates.TemplateResponse(request=request,name="applications/form.html",context={"request":request,"page_title":"Edit Application Policy","application":get_application(application_id),"networks":list_networks(),"groups":list_policy_groups(),"error":str(exc)},status_code=400)

@router.post("/{application_id}/delete")
def delete(application_id:int,request:Request,csrf_token:str=Form(...)):
    u=request.state.user;app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        delete_application(application_id,u["username"])
        audit(u["username"],"APPLICATION_DELETE","SUCCESS","application",application_id,auth.client_ip(request))
        return RedirectResponse("/applications?msg=Application+removed+as+pending+change",303)
    except Exception as exc:
        return RedirectResponse(f"/applications/{application_id}?error="+str(exc).replace(" ","+"),303)


@router.post("/{application_id}/status")
def status(application_id:int,request:Request,status:str=Form(...),csrf_token:str=Form(...)):
    u=request.state.user;app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    set_application_status(application_id,status,u["username"]);audit(u["username"],"APPLICATION_"+status.upper(),"SUCCESS","application",application_id,auth.client_ip(request));return RedirectResponse("/applications?msg=Application+state+saved+as+pending",303)


@router.post("/{application_id}/dependency/add")
def dependency_add(application_id:int,request:Request,kind:str=Form(...),destination:str=Form(...),protocol:str=Form(...),reason:str=Form("Manual application dependency"),csrf_token:str=Form(...)):
    u=request.state.user;app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        rid=create_application_dependency(application_id,kind,destination,protocol,u["username"],reason);audit(u["username"],"APPLICATION_DEPENDENCY_ADD","SUCCESS","rule",rid,auth.client_ip(request),json.dumps({"application_id":application_id}));return RedirectResponse(f"/applications/{application_id}?msg=Dependency+added+as+pending+change",303)
    except Exception as exc:return RedirectResponse(f"/applications/{application_id}?error="+str(exc).replace(" ","+"),303)

@router.post("/{application_id}/dependency/{rule_id}/status")
def dependency_status(application_id:int,rule_id:int,request:Request,status:str=Form(...),csrf_token:str=Form(...)):
    u=request.state.user;app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:set_application_dependency_status(application_id,rule_id,status,u["username"]);audit(u["username"],"APPLICATION_DEPENDENCY_"+status.upper(),"SUCCESS","rule",rule_id,auth.client_ip(request));return RedirectResponse(f"/applications/{application_id}?msg=Dependency+state+saved+as+pending",303)
    except Exception as exc:return RedirectResponse(f"/applications/{application_id}?error="+str(exc).replace(" ","+"),303)

@router.post("/{application_id}/discover")
def discover_existing(application_id:int,request:Request,method:str=Form(...),source_ref:str=Form(""),client_ip:str=Form(""),window_minutes:int=Form(10),auto_approve:int=Form(0),csrf_token:str=Form(...)):
    u=request.state.user;app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        catalog_key=app["source_ref"] if method in("catalog","official_api") else None;query=app["seed_domain"] if method=="seed_probe" else (catalog_key or app["name"])
        rid=create_run(application_id,query,method,u["username"],source_ref=source_ref or app.get("source_ref"),client_ip=client_ip,window_minutes=window_minutes,catalog_key=catalog_key,auto_approve=bool(auto_approve))
        if auto_approve:
            return RedirectResponse(f"/applications/{application_id}?msg=Dependency+refresh+started",303)
        return RedirectResponse(f"/applications/discovery/{rid}",303)
    except Exception as exc:return RedirectResponse(f"/applications/{application_id}?error="+str(exc).replace(" ","+"),303)
