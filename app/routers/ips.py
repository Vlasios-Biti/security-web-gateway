import json
from urllib.parse import quote_plus
from fastapi import APIRouter,Request,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.db import audit
from app.services.rules import list_rules,list_networks,get_rule,create_rule,update_rule,set_status
from app.services.access_model import list_policy_groups
from app.services.apply import save_apply_state,apply_saved_change,apply_message
KIND="ip";BASE="/rules/ips";router=APIRouter(prefix=BASE)
def can_manage(u):return u and u["role"] in("admin","operator")
def _apply_after_save(request,u,description,baseline_dirty):
    result=apply_saved_change(u["username"],auth.client_ip(request),description,preexisting_dirty=baseline_dirty,role=u["role"])
    return result,apply_message(result)
@router.get("",response_class=HTMLResponse)
def index(request:Request):return request.app.state.templates.TemplateResponse(request=request,name="ips/list.html",context={"request":request,"page_title":"Allowed Destination IPs","rules":list_rules(KIND,"custom",standalone_only=True),"networks":list_networks(),"groups":list_policy_groups()})
@router.get("/add",response_class=HTMLResponse)
def add_page(request:Request):
    if not can_manage(request.state.user):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="ips/form.html",context={"request":request,"page_title":"Add ALLOW Destination IP","rule":None,"networks":list_networks(),"groups":list_policy_groups(),"error":None})
@router.post("/add")
def add_submit(request:Request,destination:str=Form(...),protocol:str=Form(...),scope_mode:str=Form("selected"),network_ids:list[int]=Form(default=[]),policy_group_ids:list[int]=Form(default=[]),reason:str=Form(...),change_reference:str=Form(""),expires_at:str=Form(""),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(u):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        r=create_rule(KIND,destination,protocol,network_ids,u["username"],reason,change_reference,expires_at,scope_mode=scope_mode,policy_group_ids=policy_group_ids);audit(u["username"],"IP_CREATE","SUCCESS","rule",r["id"],auth.client_ip(request),json.dumps(r))
        applied,msg=_apply_after_save(request,u,"Save IP rule "+destination,baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse(BASE+"?"+key+"="+quote_plus(msg),303)
    except Exception as exc:return request.app.state.templates.TemplateResponse(request=request,name="ips/form.html",context={"request":request,"page_title":"Add ALLOW Destination IP","rule":None,"networks":list_networks(),"groups":list_policy_groups(),"error":str(exc)},status_code=400)
@router.get("/{rule_id}/edit",response_class=HTMLResponse)
def edit_page(rule_id:int,request:Request):
    if not can_manage(request.state.user):return HTMLResponse("Forbidden",403)
    rule=get_rule(rule_id)
    if not rule or rule["management_type"]!="custom":return HTMLResponse("Not found",404)
    return request.app.state.templates.TemplateResponse(request=request,name="ips/form.html",context={"request":request,"page_title":"Edit ALLOW Destination IP","rule":rule,"networks":list_networks(),"groups":list_policy_groups(),"error":None})
@router.post("/{rule_id}/edit")
def edit_submit(rule_id:int,request:Request,destination:str=Form(...),protocol:str=Form(...),scope_mode:str=Form("selected"),network_ids:list[int]=Form(default=[]),policy_group_ids:list[int]=Form(default=[]),reason:str=Form(...),change_reference:str=Form(""),expires_at:str=Form(""),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(u):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        r=update_rule(rule_id,destination,protocol,network_ids,u["username"],reason,change_reference,expires_at,scope_mode=scope_mode,policy_group_ids=policy_group_ids);audit(u["username"],"IP_EDIT","SUCCESS","rule",rule_id,auth.client_ip(request),json.dumps(r))
        applied,msg=_apply_after_save(request,u,"Save IP rule "+destination,baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse(BASE+"?"+key+"="+quote_plus(msg),303)
    except Exception as exc:return request.app.state.templates.TemplateResponse(request=request,name="ips/form.html",context={"request":request,"page_title":"Edit ALLOW Destination IP","rule":get_rule(rule_id),"networks":list_networks(),"groups":list_policy_groups(),"error":str(exc)},status_code=400)
@router.post("/{rule_id}/status")
def status(rule_id:int,request:Request,status:str=Form(...),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(u):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        set_status(rule_id,status,u["username"]);audit(u["username"],"IP_"+status.upper(),"SUCCESS","rule",rule_id,auth.client_ip(request))
        applied,msg=_apply_after_save(request,u,"Update IP rule",baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse(BASE+"?"+key+"="+quote_plus(msg),303)
    except Exception as exc:return RedirectResponse(BASE+"?error="+str(exc).replace(" ","+"),303)
