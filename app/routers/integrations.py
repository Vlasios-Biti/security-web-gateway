from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from urllib.parse import quote_plus
from app import auth
from app.services import integrations

router=APIRouter(prefix='/system/integrations')


def admin(request):return request.state.user and request.state.user['role']=='admin'


def render(request, raw='', error=''):
    return request.app.state.templates.TemplateResponse(request=request,name='system/integrations.html',context={'request':request,'page_title':'Integrations API','tokens':integrations.tokens(),'new_token':raw,'error':error})


@router.get('',response_class=HTMLResponse)
def page(request:Request):
    if not admin(request):return HTMLResponse('Forbidden',403)
    return render(request)


@router.post('')
def create(request:Request,name:str=Form(...),scopes:list[str]=Form(default=[]),days:int=Form(90),csrf_token:str=Form(...)):
    if not admin(request):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(request.state.user,csrf_token):return HTMLResponse('Invalid request',403)
    try:return render(request,integrations.create_token(name,scopes,days,request.state.user['username']))
    except ValueError as exc:return render(request,error=str(exc))


@router.post('/revoke')
def revoke(request:Request,token_id:int=Form(...),csrf_token:str=Form(...)):
    if not admin(request):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(request.state.user,csrf_token):return HTMLResponse('Invalid request',403)
    integrations.revoke_token(token_id,request.state.user['username'])
    return RedirectResponse('/system/integrations?msg=Token+revoked',303)
