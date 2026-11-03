import json
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from app import auth
from app.db import connect, audit
from app.services.policy_explain import explain_policy, explain_event
from app.services.access_model import create_application_dependency, get_application

router=APIRouter(prefix='/intelligence')

def _manage(request):
    return request.state.user and request.state.user['role'] in ('admin','operator')

@router.get('/simulator',response_class=HTMLResponse)
def simulator_page(request:Request):
    return request.app.state.templates.TemplateResponse(request=request,name='intelligence/simulator.html',context={'request':request,'page_title':'Policy Simulator','result':None,'error':None})

@router.post('/simulator',response_class=HTMLResponse)
def simulator_run(request:Request,client_ip:str=Form(...),destination:str=Form(...),port:int=Form(443),method:str=Form('CONNECT'),destination_ip:str=Form('')):
    try:
        result=explain_policy(client_ip,destination,port,method,destination_ip)
        return request.app.state.templates.TemplateResponse(request=request,name='intelligence/simulator.html',context={'request':request,'page_title':'Policy Simulator','result':result,'error':None})
    except Exception as exc:
        return request.app.state.templates.TemplateResponse(request=request,name='intelligence/simulator.html',context={'request':request,'page_title':'Policy Simulator','result':None,'error':str(exc)},status_code=400)

@router.get('/why-blocked/{event_id}',response_class=HTMLResponse)
def why_blocked(event_id:int,request:Request):
    result=explain_event(event_id)
    if not result:return HTMLResponse('Not found',404)
    return request.app.state.templates.TemplateResponse(request=request,name='intelligence/why_blocked.html',context={'request':request,'page_title':'Why Blocked?','result':result})

@router.get('/dependency-candidates',response_class=HTMLResponse)
def dependency_candidates(request:Request):
    c=connect()
    try:
        rows=[dict(r) for r in c.execute("""SELECT adc.*,a.name application_name FROM application_dependency_candidates adc
            JOIN applications a ON a.id=adc.application_id WHERE adc.status='pending'
            ORDER BY adc.confidence_score DESC,adc.request_count DESC,adc.last_seen_at DESC LIMIT 500""")]
    finally:c.close()
    return request.app.state.templates.TemplateResponse(request=request,name='intelligence/dependency_candidates.html',context={'request':request,'page_title':'Dependency Candidates','rows':rows})

@router.post('/dependency-candidates/{candidate_id}/review')
def review_candidate(candidate_id:int,request:Request,action:str=Form(...),csrf_token:str=Form(...)):
    u=request.state.user
    if not _manage(request):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse('Invalid request',403)
    c=connect()
    try:
        row=c.execute('SELECT * FROM application_dependency_candidates WHERE id=? AND status=\'pending\'',(candidate_id,)).fetchone()
        if not row:return HTMLResponse('Candidate not found',404)
        row=dict(row)
    finally:c.close()
    try:
        if action=='approve':
            rid=create_application_dependency(row['application_id'],'domain',row['destination'],row['protocol'],u['username'],'Approved dependency candidate')
            status='approved';details={'rule_id':rid}
        elif action=='ignore':
            status='ignored';details={}
        else:return HTMLResponse('Unsupported action',400)
        c=connect()
        try:
            c.execute("UPDATE application_dependency_candidates SET status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?",(status,u['username'],candidate_id));c.commit()
        finally:c.close()
        audit(u['username'],'DEPENDENCY_CANDIDATE_'+status.upper(),'SUCCESS','dependency_candidate',candidate_id,auth.client_ip(request),json.dumps(details))
        return RedirectResponse('/intelligence/dependency-candidates?msg=Candidate+reviewed',303)
    except Exception as exc:
        return RedirectResponse('/intelligence/dependency-candidates?error='+str(exc).replace(' ','+'),303)
