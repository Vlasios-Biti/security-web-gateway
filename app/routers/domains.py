import json
from fastapi import APIRouter,Request,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.db import audit
from app.services.rules import list_rules,list_networks,get_rule,create_rule,update_rule,set_status
from app.services.access_model import list_policy_groups
KIND="domain";BASE="/rules/domains";router=APIRouter(prefix=BASE)
def can_manage(u):return u and u["role"] in("admin","operator")
@router.get("",response_class=HTMLResponse)
def index(request:Request):
    return request.app.state.templates.TemplateResponse(request=request,name="domains/list.html",context={"request":request,"page_title":"Allowed Domains","rules":list_rules(KIND,"custom",standalone_only=True),"networks":list_networks(),"groups":list_policy_groups()})
@router.get("/add",response_class=HTMLResponse)
def add_page(request:Request):
    if not can_manage(request.state.user):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="domains/form.html",context={"request":request,"page_title":"Add ALLOW Domain","rule":None,"networks":list_networks(),"groups":list_policy_groups(),"error":None})
@router.post("/add")
def add_submit(request:Request,destination:str=Form(...),protocol:str=Form(...),scope_mode:str=Form("selected"),network_ids:list[int]=Form(default=[]),policy_group_ids:list[int]=Form(default=[]),reason:str=Form(...),change_reference:str=Form(""),expires_at:str=Form(""),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(u):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        result=create_rule(KIND,destination,protocol,network_ids,u["username"],reason,change_reference,expires_at,scope_mode=scope_mode,policy_group_ids=policy_group_ids);audit(u["username"],"DOMAIN_CREATE","SUCCESS","rule",result["id"],auth.client_ip(request),json.dumps(result));return RedirectResponse(BASE+"?msg=Rule+created+as+pending+change",303)
    except Exception as exc:return request.app.state.templates.TemplateResponse(request=request,name="domains/form.html",context={"request":request,"page_title":"Add ALLOW Domain","rule":None,"networks":list_networks(),"groups":list_policy_groups(),"error":str(exc)},status_code=400)
@router.get("/{rule_id}/edit",response_class=HTMLResponse)
def edit_page(rule_id:int,request:Request):
    if not can_manage(request.state.user):return HTMLResponse("Forbidden",403)
    rule=get_rule(rule_id)
    if not rule or rule["management_type"]!="custom":return HTMLResponse("Not found",404)
    return request.app.state.templates.TemplateResponse(request=request,name="domains/form.html",context={"request":request,"page_title":"Edit ALLOW Domain","rule":rule,"networks":list_networks(),"groups":list_policy_groups(),"error":None})
@router.post("/{rule_id}/edit")
def edit_submit(rule_id:int,request:Request,destination:str=Form(...),protocol:str=Form(...),scope_mode:str=Form("selected"),network_ids:list[int]=Form(default=[]),policy_group_ids:list[int]=Form(default=[]),reason:str=Form(...),change_reference:str=Form(""),expires_at:str=Form(""),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(u):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        result=update_rule(rule_id,destination,protocol,network_ids,u["username"],reason,change_reference,expires_at,scope_mode=scope_mode,policy_group_ids=policy_group_ids);audit(u["username"],"DOMAIN_EDIT","SUCCESS","rule",rule_id,auth.client_ip(request),json.dumps(result));return RedirectResponse(BASE+"?msg=Rule+updated+as+pending+change",303)
    except Exception as exc:return request.app.state.templates.TemplateResponse(request=request,name="domains/form.html",context={"request":request,"page_title":"Edit ALLOW Domain","rule":get_rule(rule_id),"networks":list_networks(),"groups":list_policy_groups(),"error":str(exc)},status_code=400)
@router.post("/{rule_id}/status")
def status(rule_id:int,request:Request,status:str=Form(...),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(u):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:set_status(rule_id,status,u["username"]);audit(u["username"],"DOMAIN_"+status.upper(),"SUCCESS","rule",rule_id,auth.client_ip(request));return RedirectResponse(BASE+"?msg=Change+saved+as+pending",303)
    except Exception as exc:return RedirectResponse(BASE+"?error="+str(exc).replace(" ","+"),303)
