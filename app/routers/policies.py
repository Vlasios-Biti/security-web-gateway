from fastapi import Depends
from app.services.policy_lock import policy_guard
import json
from urllib.parse import quote_plus
from fastapi import APIRouter,Request,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.db import audit,connect
from app.services.rules import list_networks,get_network,create_network,update_network,set_network_enabled,delete_network
from app.services.access_model import list_policy_groups,effective_network_ids_for_rule
from app.services.apply import save_apply_state,apply_saved_change,apply_message
router=APIRouter(dependencies=[Depends(policy_guard)],prefix="/policies")
def admin(request):return request.state.user and request.state.user["role"]=="admin"
def _apply_after_save(request,u,description,baseline_dirty):
    result=apply_saved_change(u["username"],auth.client_ip(request),description,preexisting_dirty=baseline_dirty,role=u["role"])
    return result,apply_message(result)

def stats():
    c=connect();out={}
    try:
        nets=[dict(x) for x in c.execute("SELECT id FROM networks")]
        rules=[dict(x) for x in c.execute("SELECT id,rule_type,scope_mode FROM rules WHERE status='active'")]
        for n in nets:out[n["id"]]={"domains":0,"ips":0,"applications":0,"groups":0}
        for r in rules:
            for nid in effective_network_ids_for_rule(c,r["id"],r.get("scope_mode") or "selected"):
                if nid in out:out[nid]["domains" if r["rule_type"]=="domain" else "ips"]+=1
        for n in nets:
            nid=n["id"]
            out[nid]["groups"]=c.execute("SELECT COUNT(*) c FROM policy_group_networks pgn JOIN policy_groups pg ON pg.id=pgn.group_id AND pg.status='active' WHERE pgn.network_id=?",(nid,)).fetchone()["c"]
            out[nid]["applications"]=c.execute("""SELECT COUNT(DISTINCT aid) c FROM (
              SELECT an.application_id aid FROM application_networks an JOIN applications a ON a.id=an.application_id AND a.status='active' WHERE an.network_id=?
              UNION SELECT pga.application_id FROM policy_group_networks pgn JOIN policy_groups pg ON pg.id=pgn.group_id AND pg.status='active' JOIN policy_group_applications pga ON pga.group_id=pg.id JOIN applications a ON a.id=pga.application_id AND a.status='active' WHERE pgn.network_id=?)""",(nid,nid)).fetchone()["c"]
        return out
    finally:c.close()

@router.get("/networks",response_class=HTMLResponse)
def page(request:Request):
    return request.app.state.templates.TemplateResponse(request=request,name="policies/networks.html",context={"request":request,"page_title":"Networks & VLANs","networks":list_networks(False),"stats":stats()})

def _network_form(request, network=None, error=None, copy_source=None):
    return {"request":request,"page_title":"Copy network" if copy_source else ("Edit network" if network and network.get("id") else "Add network"),
            "network":network,"copy_source":copy_source,"error":error,"groups":list_policy_groups()}


@router.get("/networks/{network_id}/copy",response_class=HTMLResponse)
def copy_page(network_id:int,request:Request):
    if not admin(request):return HTMLResponse("Forbidden",403)
    source=get_network(network_id)
    if not source:return HTMLResponse("Not found",404)
    draft={**source,"id":None,"name":source["name"]+" (copy)","cidr":"","vlan_id":None}
    return request.app.state.templates.TemplateResponse(request=request,name="policies/network_form.html",context=_network_form(request,draft,copy_source=source))


@router.get("/networks/add",response_class=HTMLResponse)
def add_page(request:Request):
    if not admin(request):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="policies/network_form.html",context={"request":request,"page_title":"Add network","network":None,"error":None,"available_networks":list_networks(False),"groups":list_policy_groups()})

@router.post("/networks/add")
def add_submit(request:Request,name:str=Form(...),vlan_id:str=Form(""),cidr:str=Form(...),proxy_enabled:bool=Form(True),description:str=Form(""),clone_from_network_id:str=Form(""),policy_group_ids:list[int]=Form(default=[]),reason:str=Form(""),change_reference:str=Form(""),csrf_token:str=Form(...)):
    u=request.state.user
    if not admin(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        r=create_network(name,cidr,u["username"],reason.strip() or ("Copied network access" if clone_from_network_id else "Created network"),change_reference,vlan_id,description,proxy_enabled,clone_from_network_id or None,policy_group_ids);audit(u["username"],"NETWORK_CREATE","SUCCESS","network",r["id"],auth.client_ip(request),json.dumps(r))
        applied,msg=_apply_after_save(request,u,"Save network "+name,baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse("/policies/networks?"+key+"="+quote_plus(msg),303)
    except Exception as exc:
        draft={"id":None,"name":name,"cidr":cidr,"vlan_id":vlan_id,"description":description,"proxy_enabled":proxy_enabled,"policy_group_ids":policy_group_ids,"change_reference":change_reference}
        source=get_network(int(clone_from_network_id)) if clone_from_network_id.isdigit() else None
        return request.app.state.templates.TemplateResponse(request=request,name="policies/network_form.html",context=_network_form(request,draft,str(exc),source),status_code=400)

@router.get("/networks/{network_id}/edit",response_class=HTMLResponse)
def edit_page(network_id:int,request:Request):
    if not admin(request):return HTMLResponse("Forbidden",403)
    n=get_network(network_id)
    if not n:return HTMLResponse("Not found",404)
    return request.app.state.templates.TemplateResponse(request=request,name="policies/network_form.html",context={"request":request,"page_title":"Edit network","network":n,"error":None,"available_networks":[],"groups":list_policy_groups()})

@router.post("/networks/{network_id}/edit")
def edit_submit(network_id:int,request:Request,name:str=Form(...),vlan_id:str=Form(""),cidr:str=Form(...),proxy_enabled:bool=Form(True),description:str=Form(""),policy_group_ids:list[int]=Form(default=[]),reason:str=Form(""),change_reference:str=Form(""),csrf_token:str=Form(...)):
    u=request.state.user
    if not admin(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        r=update_network(network_id,name,cidr,u["username"],reason.strip() or "Updated network",change_reference,vlan_id,description,proxy_enabled,policy_group_ids);audit(u["username"],"NETWORK_EDIT","SUCCESS","network",network_id,auth.client_ip(request),json.dumps(r))
        applied,msg=_apply_after_save(request,u,"Save network "+name,baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse("/policies/networks?"+key+"="+quote_plus(msg),303)
    except Exception as exc:
        draft={"id":network_id,"name":name,"cidr":cidr,"vlan_id":vlan_id,"description":description,"proxy_enabled":proxy_enabled,"policy_group_ids":policy_group_ids,"change_reference":change_reference}
        return request.app.state.templates.TemplateResponse(request=request,name="policies/network_form.html",context=_network_form(request,draft,str(exc)),status_code=400)

@router.post("/networks/{network_id}/toggle")
def toggle(network_id:int,request:Request,enabled:int=Form(...),reason:str=Form(""),csrf_token:str=Form(...)):
    u=request.state.user
    if not admin(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        set_network_enabled(network_id,bool(enabled),u["username"],reason);audit(u["username"],"NETWORK_STATE","SUCCESS","network",network_id,auth.client_ip(request))
        applied,msg=_apply_after_save(request,u,"Update network state",baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse("/policies/networks?"+key+"="+quote_plus(msg),303)
    except Exception as exc:return RedirectResponse("/policies/networks?error="+str(exc).replace(" ","+"),303)

@router.post("/networks/{network_id}/delete")
def delete(network_id:int,request:Request,csrf_token:str=Form(...),return_to:str=Form("")):
    u=request.state.user
    if not admin(request):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    destination="/policies/groups" if return_to=="profiles" else "/policies/networks"
    try:
        baseline_dirty=save_apply_state()["dirty"]
        delete_network(network_id,u["username"]);audit(u["username"],"NETWORK_DELETE","SUCCESS","network",network_id,auth.client_ip(request))
        applied,msg=_apply_after_save(request,u,"Delete network",baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse(destination+"?"+key+"="+quote_plus(msg),303)
    except Exception as exc:return RedirectResponse(destination+"?error="+quote_plus(str(exc)),303)
