from fastapi import Depends
from app.services.policy_lock import policy_guard
import json,ipaddress
from urllib.parse import urlparse,quote_plus
from fastapi import APIRouter,Request,Form,File,UploadFile
from fastapi.responses import HTMLResponse,RedirectResponse,Response
from app import auth
from app.db import audit,connect
from app.services.access_choice import choose_access,save_discovery_access
from app.services.access_model import list_applications,get_application,create_application,update_application,set_application_status,delete_application,list_policy_groups,create_application_dependency,set_application_dependency_status
from app.services.discovery import catalog_search,create_run,create_har_run,get_run,list_runs,approve_run
from app.services.rules import list_networks,list_rules,create_rule
from app.services.apply import save_apply_state,apply_saved_change,apply_message
from app.services.system import cached_system_health
from app.services.learning import latest_session, start_session, stop_session
from app.services.tab_capture import create_capture_run, extension_package, MAX_CAPTURE_BYTES
from app.config import DISCOVERY_MAX_HAR_BYTES
router=APIRouter(dependencies=[Depends(policy_guard)],prefix="/applications")

def can_manage(r):return r.state.user and r.state.user["role"] in("admin","operator")

def admin(r):return r.state.user and r.state.user["role"]=="admin"

def can_modify_application(r,app):
    if not can_manage(r):return False
    return admin(r) if app and app.get("system_managed") else True

def _apply_after_save(request,user,description,baseline_dirty):
    result=apply_saved_change(user["username"],auth.client_ip(request),description,preexisting_dirty=baseline_dirty,role=user["role"])
    return result,apply_message(result)

@router.get("",response_class=HTMLResponse)
def index(request:Request):
    apps=list_applications();runs=list_runs(12);h=cached_system_health();c=connect()
    try:
        pending_candidates=c.execute("SELECT COUNT(*) c FROM application_dependency_candidates WHERE status='pending'").fetchone()["c"]
        profile_count=c.execute("SELECT COUNT(*) c FROM policy_groups WHERE status='active'").fetchone()["c"]
        last_apply=c.execute("SELECT deployed_at,status FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
    finally:c.close()
    stats={
      "applications":len(apps),
      "active":sum(1 for a in apps if a.get("status")=="active"),
      "dependencies":sum(int(a.get("dependency_count") or 0) for a in apps),
      "attention":pending_candidates+sum(1 for r in runs if r.get("status")=="failed"),
      "profiles":profile_count,
      "discovery":(h.get("workers") or {}).get("discovery","unknown"),
      "last_apply":dict(last_apply) if last_apply else None,
    }
    latest={}
    for r in runs:
        aid=r.get("application_id")
        if aid and aid not in latest:latest[aid]=r
    return request.app.state.templates.TemplateResponse(request=request,name="applications/list.html",context={"request":request,"page_title":"Access","standalone":list_rules(management="custom",standalone_only=True),"applications":apps,"runs":runs,"stats":stats,"latest_runs":latest})

@router.get('/allow',response_class=HTMLResponse)
def allow_page(request:Request):
    if not can_manage(request):return HTMLResponse('Forbidden',403)
    return request.app.state.templates.TemplateResponse(request=request,name='applications/allow.html',context={'request':request,'page_title':'Add access','networks':list_networks(),'groups':list_policy_groups()})


@router.post('/allow')
def allow_submit(request:Request,destination:str=Form(...),name:str=Form(''),access_mode:str=Form('none'),network_ids:list[int]=Form(default=[]),policy_group_ids:list[int]=Form(default=[]),csrf_token:str=Form(...)):
    if not can_manage(request):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(request.state.user,csrf_token):return HTMLResponse('Invalid request',403)
    target=destination.strip()
    try:
        networks,groups,_=choose_access(access_mode,network_ids,policy_group_ids)
        try:ip=ipaddress.ip_network(target,strict=False)
        except ValueError:ip=None
        if ip:
            if not networks and not groups:raise ValueError('Choose a profile or VLAN for this IP.')
            baseline=save_apply_state()['dirty']
            result=create_rule('ip',str(ip),'BOTH',networks,request.state.user['username'],('Access label: '+name.strip()) if name.strip() else 'Allowed from Access',policy_group_ids=groups)
            audit(request.state.user['username'],'IP_CREATE','SUCCESS','rule',result['id'],auth.client_ip(request))
            applied,msg=_apply_after_save(request,request.state.user,'Allow IP '+str(ip),baseline)
            return RedirectResponse('/applications?'+('msg' if applied.get('ok') else 'error')+'='+quote_plus(msg),303)
        url=target if '://' in target else 'https://'+target
        parsed=urlparse(url)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:raise ValueError('Enter a website, domain or IPv4 address.')
        if not name.strip():
            c=connect()
            try:
                existing=c.execute("SELECT name FROM applications WHERE status!='deleted' AND seed_domain=?",(parsed.hostname,)).fetchone()
                if existing:
                    name=existing['name']
                    if access_mode=='none':access_mode='keep'
            finally:c.close()
        return discover_custom(request,name=name.strip() or parsed.hostname,method='browser_auto',source_ref=url,seed_domain=parsed.hostname,auto_approve=1,access_mode=access_mode,network_ids=networks,policy_group_ids=groups,csrf_token=csrf_token)
    except ValueError as exc:
        return request.app.state.templates.TemplateResponse(request=request,name='applications/allow.html',context={'request':request,'page_title':'Add access','networks':list_networks(),'groups':list_policy_groups(),'error':str(exc),'draft_destination':destination,'draft_name':name,'access_groups':policy_group_ids if access_mode=='profiles' else [],'access_networks':network_ids if access_mode=='networks' else []},status_code=400)


@router.get("/add",response_class=HTMLResponse)
def add_page(request:Request):
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="applications/form.html",context={"request":request,"page_title":"Add Application Policy","application":None,"networks":list_networks(),"groups":list_policy_groups(),"error":None})

@router.post("/add")
def add_submit(request:Request,name:str=Form(...),provider:str=Form(""),description:str=Form(""),seed_domain:str=Form(""),source_kind:str=Form("manual"),source_ref:str=Form(""),auto_monitor:int=Form(0),network_ids:list[int]=Form(default=[]),policy_group_ids:list[int]=Form(default=[]),csrf_token:str=Form(...),access_mode:str=Form("")):
    u=request.state.user
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        network_ids,policy_group_ids,_=choose_access(access_mode,network_ids,policy_group_ids,None)
        aid=create_application(name,provider,description,seed_domain,source_kind,source_ref,bool(auto_monitor),u["username"]);update_application(aid,name,provider,description,seed_domain,source_kind,source_ref,bool(auto_monitor),network_ids,u["username"],policy_group_ids);audit(u["username"],"APPLICATION_CREATE","SUCCESS","application",aid,auth.client_ip(request))
        result,msg=_apply_after_save(request,u,f"Save application {name}",baseline_dirty)
        key="msg" if result.get("ok") else "error"
        return RedirectResponse(f"/applications/{aid}?{key}="+quote_plus(msg),303)
    except Exception as exc:return request.app.state.templates.TemplateResponse(request=request,name="applications/form.html",context={"request":request,"page_title":"Add Application Policy","application":None,"networks":list_networks(),"groups":list_policy_groups(),"error":str(exc)},status_code=400)

@router.get("/discover",response_class=HTMLResponse)
def discover_page(request:Request,query:str=""):
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="applications/discover.html",context={"request":request,"page_title":"Discover Application","query":query,"catalog":catalog_search(query) if query else [],"networks":list_networks(),"groups":list_policy_groups(),"error":None})

@router.post("/discover/catalog")
def discover_catalog(request:Request,catalog_key:str=Form(...),policy_group_ids:list[int]=Form(default=[]),csrf_token:str=Form(...),access_mode:str=Form(""),network_ids:list[int]=Form(default=[])):
    u=request.state.user
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    item=next((x for x in catalog_search("") if x["key"]==catalog_key),None)
    if not item:return RedirectResponse("/applications/discover?error=Unknown+catalog+application",303)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        c=connect();existing=c.execute("SELECT id FROM applications WHERE name=? AND status!='deleted'",(item["name"],)).fetchone();c.close()
        aid=existing["id"] if existing else create_application(item["name"],item["provider"],item["description"],item["seed_domain"],item.get("source_kind",item["method"]),item.get("source_ref",catalog_key),bool(item.get("auto_monitor")),u["username"],system_managed=False)
        save_discovery_access(aid,access_mode,network_ids,policy_group_ids)
        method=item["method"]
        rid=create_run(aid,item.get("seed_domain") or item["name"],method,u["username"],source_ref=item.get("source_ref"),catalog_key=catalog_key,auto_apply=bool(u["role"]=="admin"),baseline_dirty=baseline_dirty);audit(u["username"],"DISCOVERY_START","SUCCESS","discovery_run",rid,auth.client_ip(request),json.dumps({"catalog":catalog_key,"method":method}));return RedirectResponse(f"/applications/discovery/{rid}",303)
    except Exception as exc:return RedirectResponse("/applications/discover?error="+str(exc).replace(" ","+"),303)

@router.post("/discover/custom")
def discover_custom(request:Request,name:str=Form(...),seed_domain:str=Form(""),method:str=Form(...),source_ref:str=Form(""),client_ip:str=Form(""),window_minutes:int=Form(10),auto_approve:int=Form(0),policy_group_ids:list[int]=Form(default=[]),csrf_token:str=Form(...),access_mode:str=Form(""),network_ids:list[int]=Form(default=[])):
    u=request.state.user
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        if method=="browser_auto" and not seed_domain.strip():
            p=urlparse(source_ref.strip())
            seed_domain=(p.hostname or "").strip().lower()
        c=connect();existing=c.execute("SELECT id FROM applications WHERE name=? AND status!='deleted'",(name.strip(),)).fetchone();c.close()
        aid=existing["id"] if existing else create_application(name,"Custom",f"Managed web application: {name}",seed_domain,"official_url" if method=="official_url" else "observed",source_ref,False,u["username"])
        save_discovery_access(aid,access_mode,network_ids,policy_group_ids)
        query=seed_domain if method=="seed_probe" else (source_ref if method=="browser_auto" else name)
        rid=create_run(aid,query,method,u["username"],source_ref=source_ref,client_ip=client_ip,window_minutes=window_minutes,auto_approve=bool(auto_approve),auto_apply=bool(auto_approve and u["role"]=="admin"),baseline_dirty=baseline_dirty);audit(u["username"],"DISCOVERY_START","SUCCESS","discovery_run",rid,auth.client_ip(request),json.dumps({"method":method,"automatic":bool(auto_approve)}))
        if auto_approve:
            return RedirectResponse(f"/applications/{aid}?msg=Application+created.+Dependencies+are+being+discovered+automatically",303)
        return RedirectResponse(f"/applications/discovery/{rid}",303)
    except Exception as exc:return RedirectResponse("/applications/discover?error="+str(exc).replace(" ","+"),303)

@router.post("/discover/har")
async def discover_har_upload(request:Request,name:str=Form(...),seed_domain:str=Form(""),policy_group_ids:list[int]=Form(default=[]),har_file:UploadFile=File(...),csrf_token:str=Form(...),access_mode:str=Form(""),network_ids:list[int]=Form(default=[])):
    u=request.state.user
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        raw=await har_file.read(DISCOVERY_MAX_HAR_BYTES+1)
        if len(raw)>DISCOVERY_MAX_HAR_BYTES:raise ValueError('HAR file is too large')
        c=connect();existing=c.execute("SELECT id FROM applications WHERE name=? AND status!='deleted'",(name.strip(),)).fetchone();c.close()
        aid=existing["id"] if existing else create_application(name,"Custom",f"Discovered application: {name}",seed_domain,"observed","HAR workflow",False,u["username"])
        save_discovery_access(aid,access_mode,network_ids,policy_group_ids)
        rid=create_har_run(aid,seed_domain,raw,u["username"],auto_apply=bool(u["role"]=="admin"),baseline_dirty=baseline_dirty)
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
    try:
        baseline_dirty=save_apply_state()['dirty'] or bool(run.get('baseline_dirty'))
        r=approve_run(run_id,candidate_ids,u["username"])
        audit(u["username"],"DISCOVERY_APPROVE","SUCCESS","discovery_run",run_id,auth.client_ip(request),json.dumps(r))
        run=get_run(run_id)
        result,msg=_apply_after_save(request,u,f"Approve discovered dependencies for application {run['application_id']}",baseline_dirty)
        key="msg" if result.get("ok") else "error"
        return RedirectResponse(f"/applications/{run['application_id']}?{key}="+quote_plus(msg),303)
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
    learning=latest_session(application_id)
    return {
        "learning": learning,
        "status": run["status"] if run else "idle",
        "error": run["error_text"] if run else None,
        "started_at": run["started_at"] if run else None,
        "completed_at": run["completed_at"] if run else None,
        "dependency_count": active_dependencies,
        "last_discovery_at": app.get("last_discovery_at"),
        "pending": bool(app.get("pending")),
    }


@router.get('/capture/extension.zip')
def capture_extension(request:Request):
    if not can_manage(request):return HTMLResponse('Forbidden',403)
    return Response(extension_package(),media_type='application/zip',headers={'Content-Disposition':'attachment; filename="SWG-Tab-Capture.zip"'})


@router.post('/{application_id}/capture')
async def upload_capture(application_id:int,request:Request,capture_file:UploadFile=File(...),csrf_token:str=Form(...)):
    user=request.state.user
    app=get_application(application_id)
    if not app:return HTMLResponse('Not found',404)
    if not can_modify_application(request,app):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(user,csrf_token):return HTMLResponse('Invalid request',403)
    try:
        raw=await capture_file.read(MAX_CAPTURE_BYTES+1)
        rid=create_capture_run(application_id,raw,user['username'],baseline_dirty=save_apply_state()['dirty'])
        audit(user['username'],'TAB_CAPTURE_IMPORT','REVIEW_REQUIRED','discovery_run',rid,auth.client_ip(request))
        return RedirectResponse(f'/applications/discovery/{rid}',303)
    except ValueError as exc:
        return RedirectResponse(f'/applications/{application_id}?error='+quote_plus(str(exc)),303)


@router.post('/{application_id}/capture/har')
async def upload_application_har(application_id:int,request:Request,har_file:UploadFile=File(...),csrf_token:str=Form(...)):
    user=request.state.user
    app=get_application(application_id)
    if not app:return HTMLResponse('Not found',404)
    if not can_modify_application(request,app):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(user,csrf_token):return HTMLResponse('Invalid request',403)
    try:
        if not app.get('seed_domain'):raise ValueError('Set the application seed domain before importing its HAR.')
        raw=await har_file.read(DISCOVERY_MAX_HAR_BYTES+1)
        rid=create_har_run(application_id,app['seed_domain'],raw,user['username'],auto_apply=False,baseline_dirty=save_apply_state()['dirty'])
        audit(user['username'],'APPLICATION_HAR_IMPORT','REVIEW_REQUIRED','discovery_run',rid,auth.client_ip(request))
        return RedirectResponse(f'/applications/discovery/{rid}',303)
    except ValueError as exc:
        return RedirectResponse(f'/applications/{application_id}?error='+quote_plus(str(exc)),303)


@router.get("/{application_id}",response_class=HTMLResponse)
def detail(application_id:int,request:Request):
    app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    c=connect()
    try:runs=[dict(x) for x in c.execute("SELECT * FROM discovery_runs WHERE application_id=? ORDER BY id DESC LIMIT 15",(application_id,))]
    finally:c.close()
    return request.app.state.templates.TemplateResponse(request=request,name="applications/detail.html",context={"request":request,"page_title":app["name"],"application":app,"runs":runs,"learning":latest_session(application_id)})


@router.post("/{application_id}/learning")
def learning_action(application_id:int,request:Request,csrf_token:str=Form(...),action:str=Form(...),client_ip:str=Form("")):
    user=request.state.user
    if not admin(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(user,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        if action=="start":
            start_session(application_id,client_ip,user["username"])
            message="Learning started for 10 minutes. Use only this application on the selected device"
        elif action=="stop":
            stop_session(application_id,user["username"])
            message="Learning stopped. Learned dependencies remain in the application"
        else:raise ValueError("Unsupported learning action.")
        return RedirectResponse(f"/applications/{application_id}?msg="+quote_plus(message),303)
    except ValueError as exc:
        return RedirectResponse(f"/applications/{application_id}?error="+quote_plus(str(exc)),303)

@router.get("/{application_id}/edit",response_class=HTMLResponse)
def edit_page(application_id:int,request:Request):
    app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="applications/form.html",context={"request":request,"page_title":"Edit Application Policy","application":app,"networks":list_networks(),"groups":list_policy_groups(),"error":None})

@router.post("/{application_id}/edit")
def edit_submit(application_id:int,request:Request,name:str=Form(...),provider:str=Form(""),description:str=Form(""),seed_domain:str=Form(""),source_kind:str=Form("manual"),source_ref:str=Form(""),auto_monitor:int=Form(0),network_ids:list[int]=Form(default=[]),policy_group_ids:list[int]=Form(default=[]),csrf_token:str=Form(...),access_mode:str=Form("")):
    u=request.state.user;app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        network_ids,policy_group_ids,_=choose_access(access_mode,network_ids,policy_group_ids,app)
        update_application(application_id,name,provider,description,seed_domain,source_kind,source_ref,bool(auto_monitor),network_ids,u["username"],policy_group_ids);audit(u["username"],"APPLICATION_EDIT","SUCCESS","application",application_id,auth.client_ip(request))
        result,msg=_apply_after_save(request,u,f"Save application {name}",baseline_dirty)
        key="msg" if result.get("ok") else "error"
        return RedirectResponse(f"/applications/{application_id}?{key}="+quote_plus(msg),303)
    except Exception as exc:return request.app.state.templates.TemplateResponse(request=request,name="applications/form.html",context={"request":request,"page_title":"Edit Application Policy","application":get_application(application_id),"networks":list_networks(),"groups":list_policy_groups(),"error":str(exc)},status_code=400)

@router.post("/{application_id}/delete")
def delete(application_id:int,request:Request,csrf_token:str=Form(...)):
    u=request.state.user;app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        name=app["name"]
        delete_application(application_id,u["username"])
        audit(u["username"],"APPLICATION_DELETE","SUCCESS","application",application_id,auth.client_ip(request))
        result,msg=_apply_after_save(request,u,f"Delete application {name}",baseline_dirty)
        key="msg" if result.get("ok") else "error"
        return RedirectResponse("/applications?"+key+"="+quote_plus(msg),303)
    except Exception as exc:
        return RedirectResponse(f"/applications/{application_id}?error="+str(exc).replace(" ","+"),303)


@router.post("/{application_id}/status")
def status(application_id:int,request:Request,status:str=Form(...),csrf_token:str=Form(...)):
    u=request.state.user;app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    baseline_dirty=save_apply_state()["dirty"]
    set_application_status(application_id,status,u["username"]);audit(u["username"],"APPLICATION_"+status.upper(),"SUCCESS","application",application_id,auth.client_ip(request))
    result,msg=_apply_after_save(request,u,f"Set application {app['name']} {status}",baseline_dirty)
    key="msg" if result.get("ok") else "error"
    return RedirectResponse("/applications?"+key+"="+quote_plus(msg),303)


@router.post("/{application_id}/dependency/add")
def dependency_add(application_id:int,request:Request,kind:str=Form(...),destination:str=Form(...),protocol:str=Form(...),reason:str=Form("Manual application dependency"),csrf_token:str=Form(...)):
    u=request.state.user;app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        rid=create_application_dependency(application_id,kind,destination,protocol,u["username"],reason);audit(u["username"],"APPLICATION_DEPENDENCY_ADD","SUCCESS","rule",rid,auth.client_ip(request),json.dumps({"application_id":application_id}))
        result,msg=_apply_after_save(request,u,f"Add dependency to {app['name']}",baseline_dirty)
        key="msg" if result.get("ok") else "error"
        return RedirectResponse(f"/applications/{application_id}?{key}="+quote_plus(msg),303)
    except Exception as exc:return RedirectResponse(f"/applications/{application_id}?error="+str(exc).replace(" ","+"),303)

@router.post("/{application_id}/dependency/{rule_id}/status")
def dependency_status(application_id:int,rule_id:int,request:Request,status:str=Form(...),csrf_token:str=Form(...)):
    u=request.state.user;app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        set_application_dependency_status(application_id,rule_id,status,u["username"]);audit(u["username"],"APPLICATION_DEPENDENCY_"+status.upper(),"SUCCESS","rule",rule_id,auth.client_ip(request))
        result,msg=_apply_after_save(request,u,f"Update dependency in {app['name']}",baseline_dirty)
        key="msg" if result.get("ok") else "error"
        return RedirectResponse(f"/applications/{application_id}?{key}="+quote_plus(msg),303)
    except Exception as exc:return RedirectResponse(f"/applications/{application_id}?error="+str(exc).replace(" ","+"),303)

@router.post("/{application_id}/discover")
def discover_existing(application_id:int,request:Request,method:str=Form(...),source_ref:str=Form(""),client_ip:str=Form(""),window_minutes:int=Form(10),auto_approve:int=Form(0),csrf_token:str=Form(...)):
    u=request.state.user;app=get_application(application_id)
    if not app:return HTMLResponse("Not found",404)
    if not can_modify_application(request,app):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        catalog_key=app["source_ref"] if method in("catalog","official_api") else None;query=app["seed_domain"] if method=="seed_probe" else (catalog_key or app["name"])
        rid=create_run(application_id,query,method,u["username"],source_ref=source_ref or app.get("source_ref"),client_ip=client_ip,window_minutes=window_minutes,catalog_key=catalog_key,auto_approve=bool(auto_approve),auto_apply=bool(auto_approve and u["role"]=="admin"),baseline_dirty=baseline_dirty)
        if auto_approve:
            return RedirectResponse(f"/applications/{application_id}?msg=Dependency+refresh+started",303)
        return RedirectResponse(f"/applications/discovery/{rid}",303)
    except Exception as exc:return RedirectResponse(f"/applications/{application_id}?error="+str(exc).replace(" ","+"),303)
