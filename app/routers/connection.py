from fastapi import Depends
from app.services.policy_lock import policy_guard
import json
from urllib.parse import quote_plus
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from app import auth
from app.config import MODE, PROXY_IP, PROXY_PORT
from app.services.connectivity import connection_policy, save_connection_policy, windows_package
from app.services.pac_policy import render_pac
from app.services.pc_services import service_profiles, save_service
from app.services.access_model import list_policy_groups

router=APIRouter(dependencies=[Depends(policy_guard)],prefix="/connection")


def _admin(request):
    return request.state.user and request.state.user["role"] == "admin"


@router.get("", response_class=HTMLResponse)
def page(request: Request):
    if not _admin(request):
        return HTMLResponse("Forbidden", 403)
    return request.app.state.templates.TemplateResponse(request=request, name="connection.html", context={
        "page_title": "Connection", "request": request, "policy": connection_policy(),
        "pac_url": f"http://{PROXY_IP}:8081/proxy.pac", "proxy_endpoint": f"{PROXY_IP}:{PROXY_PORT}", "mode": MODE,
        "pc_services":service_profiles(), "groups":list_policy_groups()})


@router.get('/bypass',response_class=HTMLResponse)
def bypass_page(request:Request):
    if not _admin(request):return HTMLResponse('Forbidden',403)
    return request.app.state.templates.TemplateResponse(request=request,name='bypass.html',context={'request':request,'page_title':'Proxy bypass','policy':connection_policy()})


@router.post('/bypass')
def bypass_save(request:Request,csrf_token:str=Form(...),bypass:str=Form('')):
    if not _admin(request):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(request.state.user,csrf_token):return HTMLResponse('Invalid request',403)
    try:
        policy=connection_policy();policy['bypass']=bypass.splitlines()
        save_connection_policy(policy,request.state.user['username'],auth.client_ip(request))
        return RedirectResponse('/connection/bypass?msg=Bypass+destinations+saved',303)
    except (ValueError,OSError,RuntimeError) as exc:return RedirectResponse('/connection/bypass?error='+quote_plus(str(exc)),303)


@router.post('/services/{service_key}')
def save_pc_service(service_key:str,request:Request,csrf_token:str=Form(...),enabled:bool=Form(False),policy_group_ids:list[int]=Form(default=[])):
    user=request.state.user
    if not _admin(request):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(user,csrf_token):return HTMLResponse('Invalid request',403)
    from app.services.apply import save_apply_state,apply_saved_change,apply_message
    from app.db import audit
    try:
        baseline=save_apply_state()['dirty']
        aid=save_service(service_key,enabled,policy_group_ids,user['username'])
        audit(user['username'],'PC_SERVICE_SAVE','SAVED','application',aid,auth.client_ip(request))
        result=apply_saved_change(user['username'],auth.client_ip(request),'Update PC service '+service_key,preexisting_dirty=baseline,role=user['role'])
        key='msg' if result.get('ok') else 'error'
        return RedirectResponse('/connection?'+key+'='+quote_plus(apply_message(result))+'#pc-services',303)
    except ValueError as exc:
        return RedirectResponse('/connection?error='+quote_plus(str(exc))+'#pc-services',303)


@router.post("")
def save(request: Request, csrf_token: str = Form(...), fail_open: bool = Form(False), internal_direct: bool = Form(False), bypass: str = Form("")):
    user = request.state.user
    if not _admin(request):
        return HTMLResponse("Forbidden", 403)
    if not auth.check_csrf(user, csrf_token):
        return HTMLResponse("Invalid request", 403)
    try:
        save_connection_policy({"fail_open": fail_open, "internal_direct": internal_direct, "bypass": bypass.splitlines()}, user["username"], auth.client_ip(request))
        message = "Connection policy published" if MODE == "production" else "Preview saved. Production PAC is unchanged"
        return RedirectResponse("/connection?msg=" + quote_plus(message), 303)
    except (ValueError, OSError, RuntimeError) as exc:
        return RedirectResponse("/connection?error=" + quote_plus(str(exc)), 303)


@router.get('/edge-policy.json')
def edge_policy_download(request:Request):
    if not _admin(request):return HTMLResponse('Forbidden',403)
    value={'ProxyMode':'pac_script','ProxyPacUrl':f'http://{PROXY_IP}:8081/proxy.pac','ProxyPacMandatory':not connection_policy()['fail_open']}
    return Response(json.dumps(value,indent=2),media_type='application/json',headers={'Content-Disposition':'attachment; filename="Edge-ProxySettings.json"'})


@router.get("/windows.zip")
def download_windows(request: Request):
    if not _admin(request):
        return HTMLResponse("Forbidden", 403)
    return Response(windows_package(), media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="SWG-Windows.zip"'})


@router.get("/preview.pac")
def preview(request: Request):
    if not _admin(request):
        return HTMLResponse("Forbidden", 403)
    return Response(render_pac(connection_policy(), PROXY_IP, PROXY_PORT), media_type="text/plain")
