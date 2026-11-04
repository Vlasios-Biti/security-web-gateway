import json
from urllib.parse import quote_plus
from fastapi import APIRouter,Request,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.db import audit
from app.services.access_model import list_policy_groups,get_policy_group,create_policy_group,update_policy_group,set_policy_group_status,list_applications
from app.services.rules import list_networks,list_rules
from app.services.apply import save_apply_state,apply_saved_change,apply_message
router=APIRouter(prefix="/policies/groups")

def can_manage(r):return r.state.user and r.state.user["role"] in("admin","operator")
def _apply_after_save(request,u,description,baseline_dirty):
    result=apply_saved_change(u["username"],auth.client_ip(request),description,preexisting_dirty=baseline_dirty,role=u["role"])
    return result,apply_message(result)
def can_modify_group(r,g):
    if not can_manage(r):return False
    return r.state.user["role"]=="admin" if g and g.get("system_managed") else True

def _ctx(request,group=None,error=None):
    custom=[r for r in list_rules(management="custom",standalone_only=True) if r["status"]!="deleted"]
    return {"request":request,"page_title":"Edit Access Profile" if group else "Add Access Profile","group":group,"applications":list_applications(),"rules":custom,"networks":list_networks(),"error":error}

@router.get("",response_class=HTMLResponse)
def index(request:Request):
    return request.app.state.templates.TemplateResponse(request=request,name="groups/list.html",context={"request":request,"page_title":"Policy Groups / Access Profiles","groups":list_policy_groups()})

@router.get("/add",response_class=HTMLResponse)
def add_page(request:Request):
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="groups/form.html",context=_ctx(request))

@router.post("/add")
def add_submit(request:Request,name:str=Form(...),description:str=Form(""),application_ids:list[int]=Form(default=[]),rule_ids:list[int]=Form(default=[]),network_ids:list[int]=Form(default=[]),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        gid=create_policy_group(name,description,application_ids,rule_ids,network_ids,u["username"]);audit(u["username"],"POLICY_GROUP_CREATE","SUCCESS","policy_group",gid,auth.client_ip(request),json.dumps({"name":name}))
        applied,msg=_apply_after_save(request,u,"Save access profile "+name,baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse("/policies/groups?"+key+"="+quote_plus(msg),303)
    except Exception as exc:return request.app.state.templates.TemplateResponse(request=request,name="groups/form.html",context=_ctx(request,error=str(exc)),status_code=400)

@router.get("/{group_id}/edit",response_class=HTMLResponse)
def edit_page(group_id:int,request:Request):
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    g=get_policy_group(group_id)
    if not g:return HTMLResponse("Not found",404)
    if not can_modify_group(request,g):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="groups/form.html",context=_ctx(request,g))

@router.post("/{group_id}/edit")
def edit_submit(group_id:int,request:Request,name:str=Form(...),description:str=Form(""),application_ids:list[int]=Form(default=[]),rule_ids:list[int]=Form(default=[]),network_ids:list[int]=Form(default=[]),csrf_token:str=Form(...)):
    u=request.state.user;g=get_policy_group(group_id)
    if not g:return HTMLResponse("Not found",404)
    if not can_modify_group(request,g):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        update_policy_group(group_id,name,description,application_ids,rule_ids,network_ids,u["username"]);audit(u["username"],"POLICY_GROUP_EDIT","SUCCESS","policy_group",group_id,auth.client_ip(request))
        applied,msg=_apply_after_save(request,u,"Save access profile "+name,baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse("/policies/groups?"+key+"="+quote_plus(msg),303)
    except Exception as exc:return request.app.state.templates.TemplateResponse(request=request,name="groups/form.html",context=_ctx(request,get_policy_group(group_id),str(exc)),status_code=400)

@router.post("/{group_id}/status")
def status(group_id:int,request:Request,status:str=Form(...),csrf_token:str=Form(...)):
    u=request.state.user;g=get_policy_group(group_id)
    if not g:return HTMLResponse("Not found",404)
    if not can_modify_group(request,g):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    baseline_dirty=save_apply_state()["dirty"]
    set_policy_group_status(group_id,status,u["username"]);audit(u["username"],"POLICY_GROUP_"+status.upper(),"SUCCESS","policy_group",group_id,auth.client_ip(request))
    applied,msg=_apply_after_save(request,u,"Update access profile "+g["name"],baseline_dirty)
    key="msg" if applied.get("ok") else "error"
    return RedirectResponse("/policies/groups?"+key+"="+quote_plus(msg),303)
