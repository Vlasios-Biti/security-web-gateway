from fastapi import Depends
from app.services.policy_lock import policy_guard
import json
from urllib.parse import quote_plus
from fastapi import APIRouter,Request,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.db import audit
from app.services.access_model import delete_policy_group, list_policy_groups,get_policy_group,create_policy_group,update_policy_group,set_policy_group_status,list_applications
from app.services.rules import list_networks,list_rules
from app.services.profile_setup import save_profile_setup
from app.services.apply import save_apply_state,apply_saved_change,apply_message
router=APIRouter(dependencies=[Depends(policy_guard)],prefix="/policies/groups")

def can_manage(r):return r.state.user and r.state.user["role"] in("admin","operator")
def _apply_after_save(request,u,description,baseline_dirty):
    result=apply_saved_change(u["username"],auth.client_ip(request),description,preexisting_dirty=baseline_dirty,role=u["role"])
    return result,apply_message(result)
def can_modify_group(r,g):
    if not can_manage(r):return False
    return r.state.user["role"]=="admin" if g and g.get("system_managed") else True

def _ctx(request,group=None,error=None,new_cidr="",new_vlan_id="",copy_source=None):
    custom=[r for r in list_rules(management="custom",standalone_only=True) if r["status"]!="deleted"]
    return {"request":request,"page_title":"Copy profile" if copy_source else ("Edit profile & VLANs" if group and group.get("id") else "Create profile & VLAN"),"group":group,"applications":list_applications(),"rules":custom,"networks":list_networks(False),"error":error,"new_cidr":new_cidr,"new_vlan_id":new_vlan_id,"copy_source":copy_source}

@router.get("",response_class=HTMLResponse)
def index(request:Request):
    return request.app.state.templates.TemplateResponse(request=request,name="groups/list.html",context={"request":request,"page_title":"Profiles & VLANs","groups":list_policy_groups(),"unassigned_networks":[n for n in list_networks(False) if not n["policy_groups"]]})

@router.get("/add",response_class=HTMLResponse)
def add_page(request:Request,network_id:int|None=None):
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    draft=None
    if network_id is not None:
        selected=next((n for n in list_networks(False) if n['id']==network_id),None)
        if not selected:return HTMLResponse('Not found',404)
        draft={'id':None,'name':selected['name'],'description':'','application_ids':[],'rule_ids':[],'network_ids':[network_id]}
    return request.app.state.templates.TemplateResponse(request=request,name="groups/form.html",context=_ctx(request,draft))

@router.post("/add")
def add_submit(request:Request,name:str=Form(...),description:str=Form(""),application_ids:list[int]=Form(default=[]),rule_ids:list[int]=Form(default=[]),network_ids:list[int]=Form(default=[]),csrf_token:str=Form(...),new_cidr:str=Form(""),new_vlan_id:str=Form(""),combined_setup:bool=Form(False)):
    u=request.state.user
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    if (new_cidr.strip() or new_vlan_id.strip()) and u["role"]!="admin":return HTMLResponse("Only administrators can create VLANs",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        setup=save_profile_setup(name,description,application_ids,rule_ids,network_ids,u["username"],new_cidr,new_vlan_id,require_network=combined_setup);gid=setup["group_id"];audit(u["username"],"POLICY_GROUP_CREATE","SUCCESS","policy_group",gid,auth.client_ip(request),json.dumps({"name":name,"network_created":setup["network"]}))
        applied,msg=_apply_after_save(request,u,"Save access profile "+name,baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse("/policies/groups?"+key+"="+quote_plus(msg),303)
    except Exception as exc:return request.app.state.templates.TemplateResponse(request=request,name="groups/form.html",context=_ctx(request,{"id":None,"name":name,"description":description,"application_ids":application_ids,"rule_ids":rule_ids,"network_ids":network_ids},str(exc),new_cidr,new_vlan_id),status_code=400)

@router.get('/{group_id}/copy',response_class=HTMLResponse)
def copy_page(group_id:int,request:Request):
    if not can_manage(request):return HTMLResponse('Forbidden',403)
    source=get_policy_group(group_id)
    if not source or source['status']=='deleted':return HTMLResponse('Not found',404)
    draft={**source,'id':None,'name':source['name']+' (copy)','network_ids':[]}
    return request.app.state.templates.TemplateResponse(request=request,name='groups/form.html',context=_ctx(request,draft,copy_source=source))


@router.get("/{group_id}/edit",response_class=HTMLResponse)
def edit_page(group_id:int,request:Request):
    if not can_manage(request):return HTMLResponse("Forbidden",403)
    g=get_policy_group(group_id)
    if not g:return HTMLResponse("Not found",404)
    if not can_modify_group(request,g):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="groups/form.html",context=_ctx(request,g))

@router.post("/{group_id}/edit")
def edit_submit(group_id:int,request:Request,name:str=Form(...),description:str=Form(""),application_ids:list[int]=Form(default=[]),rule_ids:list[int]=Form(default=[]),network_ids:list[int]=Form(default=[]),csrf_token:str=Form(...),new_cidr:str=Form(""),new_vlan_id:str=Form(""),combined_setup:bool=Form(False)):
    u=request.state.user;g=get_policy_group(group_id)
    if not g:return HTMLResponse("Not found",404)
    if not can_modify_group(request,g):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    if (new_cidr.strip() or new_vlan_id.strip()) and u["role"]!="admin":return HTMLResponse("Only administrators can create VLANs",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        setup=save_profile_setup(name,description,application_ids,rule_ids,network_ids,u["username"],new_cidr,new_vlan_id,group_id=group_id);audit(u["username"],"POLICY_GROUP_EDIT","SUCCESS","policy_group",group_id,auth.client_ip(request),json.dumps({"network_created":setup["network"]}))
        applied,msg=_apply_after_save(request,u,"Save access profile "+name,baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse("/policies/groups?"+key+"="+quote_plus(msg),303)
    except Exception as exc:return request.app.state.templates.TemplateResponse(request=request,name="groups/form.html",context=_ctx(request,{"id":group_id,"name":name,"description":description,"application_ids":application_ids,"rule_ids":rule_ids,"network_ids":network_ids},str(exc),new_cidr,new_vlan_id),status_code=400)

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


@router.post('/{group_id}/delete')
def delete(group_id:int,request:Request,csrf_token:str=Form(...)):
    user=request.state.user;group=get_policy_group(group_id)
    if not group or group['status']=='deleted':return HTMLResponse('Not found',404)
    if not can_modify_group(request,group):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(user,csrf_token):return HTMLResponse('Invalid request',403)
    try:
        baseline=save_apply_state()['dirty'];delete_policy_group(group_id,user['username'])
        audit(user['username'],'POLICY_GROUP_DELETE','SUCCESS','policy_group',group_id,auth.client_ip(request))
        applied,msg=_apply_after_save(request,user,'Delete access profile '+group['name'],baseline)
        return RedirectResponse('/policies/groups?'+('msg' if applied.get('ok') else 'error')+'='+quote_plus(msg),303)
    except ValueError as exc:return RedirectResponse('/policies/groups?error='+quote_plus(str(exc)),303)
