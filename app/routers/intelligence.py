import json
from urllib.parse import quote_plus, urlencode, parse_qs
from fastapi import APIRouter, Request, Form, Depends
from app.services.policy_lock import policy_guard
from fastapi.responses import HTMLResponse, RedirectResponse

from app import auth
from app.db import connect, audit
from app.services.policy_explain import explain_policy, explain_event
from app.services.access_model import create_application_dependency, get_application
from app.services.apply import save_apply_state,apply_saved_change,apply_message

router=APIRouter(prefix='/intelligence',dependencies=[Depends(policy_guard)])

def _manage(request):
    return request.state.user and request.state.user['role'] in ('admin','operator')

@router.get('/simulator',response_class=HTMLResponse)
def simulator_page(request:Request):
    return request.app.state.templates.TemplateResponse(request=request,name='intelligence/simulator.html',context={'request':request,'page_title':'Policy Simulator','result':None,'error':None,'inputs':{}})

@router.post('/simulator',response_class=HTMLResponse)
def simulator_run(request:Request,client_ip:str=Form(...),destination:str=Form(...),port:int=Form(443),method:str=Form('CONNECT'),destination_ip:str=Form('')):
    inputs={'client_ip':client_ip,'destination':destination,'port':port,'method':method,'destination_ip':destination_ip}
    try:
        result=explain_policy(client_ip,destination,port,method,destination_ip)
        return request.app.state.templates.TemplateResponse(request=request,name='intelligence/simulator.html',context={'request':request,'page_title':'Policy Simulator','result':result,'error':None,'inputs':inputs})
    except (ValueError,TypeError) as exc:
        return request.app.state.templates.TemplateResponse(request=request,name='intelligence/simulator.html',context={'request':request,'page_title':'Policy Simulator','result':None,'error':str(exc),'inputs':inputs},status_code=400)

@router.get('/why-blocked/{event_id}',response_class=HTMLResponse)
def why_blocked(event_id:int,request:Request):
    result=explain_event(event_id)
    if not result:return HTMLResponse('Not found',404)
    return request.app.state.templates.TemplateResponse(request=request,name='intelligence/why_blocked.html',context={'request':request,'page_title':'Why Blocked?','result':result})

@router.get('/dependency-candidates',response_class=HTMLResponse)
def dependency_candidates(request:Request):
    from app.services.dependency_assignment import catalog,suggestions
    try: filters=_candidate_filters(request.query_params)
    except ValueError as exc:return HTMLResponse(str(exc),400)
    clauses=[];args=[]
    for field in ('application_id','status','confidence'):
        if filters[field]:clauses.append('adc.'+field+'=?');args.append(filters[field])
    if filters['q']:
        clauses.append("instr(lower(adc.destination),lower(?))>0");args.append(filters['q'])
    where=' WHERE '+' AND '.join(clauses) if clauses else ''
    source=' FROM application_dependency_candidates adc JOIN applications a ON a.id=adc.application_id'
    c=connect()
    try:
        applications=[dict(r) for r in c.execute("SELECT a.id,a.name,a.status FROM applications a WHERE a.status!='deleted' OR EXISTS(SELECT 1 FROM application_dependency_candidates adc WHERE adc.application_id=a.id) ORDER BY a.name COLLATE NOCASE,a.id")]
        selected_application=next((a for a in applications if a['id']==filters['application_id']),None)
        latest_discovery=None
        if selected_application:
            run=c.execute('SELECT id,status,method FROM discovery_runs WHERE application_id=? ORDER BY id DESC LIMIT 1',(selected_application['id'],)).fetchone()
            latest_discovery=dict(run) if run else None
            selected_application['dependency_count']=c.execute("SELECT COUNT(*) FROM application_rules ar JOIN rules r ON r.id=ar.rule_id WHERE ar.application_id=? AND ar.enabled=1 AND r.status='active'",(selected_application['id'],)).fetchone()[0]
        total=c.execute('SELECT COUNT(*)'+source+where,args).fetchone()[0]
        pages=max(1,(total+49)//50);filters['page']=min(filters['page'],pages)
        rows=[dict(r) for r in c.execute('SELECT adc.*,a.name application_name'+source+where+
            ' ORDER BY adc.confidence_score DESC,adc.request_count DESC,adc.last_seen_at DESC,adc.id DESC LIMIT 50 OFFSET ?',args+[(filters['page']-1)*50])]
        apps=catalog(c)
        for row in rows:row['suggestions']=suggestions(row['destination'],row['application_id'],apps)
    finally:c.close()
    query=urlencode({k:v for k,v in filters.items() if k!='page'})
    return request.app.state.templates.TemplateResponse(request=request,name='intelligence/dependency_candidates.html',context={'request':request,'page_title':'Dependency Candidates','rows':rows,'applications':applications,'selected_application':selected_application,'latest_discovery':latest_discovery,'filters':filters,'total':total,'pages':pages,'nav_query':query,'return_filters':urlencode(filters)})


def _candidate_filters(values):
    try:
        application_id=int(values.get('application_id',0));page=int(values.get('page',1))
    except (ValueError,TypeError):raise ValueError('Invalid application or page.')
    status=values.get('status','pending');confidence=values.get('confidence','');q=values.get('q','').strip()
    if application_id<0 or application_id>9223372036854775807 or not 1<=page<=1000000000:raise ValueError('Invalid application or page.')
    if status not in ('pending','approved','ignored','') or confidence not in ('high','medium','low',''):raise ValueError('Invalid candidate filter.')
    if len(q)>200:raise ValueError('Search must be at most 200 characters.')
    return {'application_id':application_id,'q':q,'status':status,'confidence':confidence,'page':page}

@router.get('/dependency-candidates/{candidate_id}/move',response_class=HTMLResponse)
def candidate_move_page(candidate_id:int,request:Request):
    from app.services.dependency_assignment import catalog,suggestions
    if not _manage(request):return HTMLResponse('Forbidden',403)
    c=connect()
    try:
        row=c.execute("SELECT * FROM application_dependency_candidates WHERE id=? AND status='pending'",(candidate_id,)).fetchone()
        if not row:return HTMLResponse('Not found',404)
        source=get_application(row['application_id'])
        if not source or (source['system_managed'] and request.state.user['role']!='admin'):return HTMLResponse('Forbidden',403)
        targets=[a for a in catalog(c) if a['id']!=source['id'] and (request.state.user['role']=='admin' or not a['system_managed'])]
        try:filters=urlencode(_candidate_filters(request.query_params))
        except ValueError:return HTMLResponse('Invalid filters',400)
    finally:c.close()
    return request.app.state.templates.TemplateResponse(request=request,name='applications/move_dependency.html',context={'request':request,'page_title':'Move suggestion','source':source,'destination':row['destination'],'protocol':row['protocol'],'targets':targets,'suggestions':suggestions(row['destination'],source['id'],targets),'form_action':f'/intelligence/dependency-candidates/{candidate_id}/review','fields':{'action':'reassign','filters':filters},'back_url':'/intelligence/dependency-candidates?'+filters,'is_candidate':True})


@router.post('/dependency-candidates/{candidate_id}/review')
def review_candidate(candidate_id:int,request:Request,action:str=Form(...),csrf_token:str=Form(...),filters:str=Form(''),target_application_id:int=Form(0)):
    u=request.state.user
    if not _manage(request):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse('Invalid request',403)
    try:
        parsed=parse_qs(filters,max_num_fields=10,keep_blank_values=True) if isinstance(filters,str) else {}
        back=_candidate_filters({k:v[-1] for k,v in parsed.items()})
    except (ValueError,TypeError):return HTMLResponse('Invalid candidate filters',400)
    return_url='/intelligence/dependency-candidates?'+urlencode(back)+'&'
    c=connect()
    try:
        row=c.execute('SELECT * FROM application_dependency_candidates WHERE id=? AND status=\'pending\'',(candidate_id,)).fetchone()
        if not row:return HTMLResponse('Candidate not found',404)
        row=dict(row)
    finally:c.close()
    application=get_application(row['application_id'])
    if not application:return HTMLResponse('Application not found',404)
    if application['system_managed'] and u['role']!='admin':return HTMLResponse('Forbidden',403)
    try:
        if action=='reassign':
            from app.services.dependency_assignment import move_candidate
            move_candidate(candidate_id,target_application_id,u['username'])
            return RedirectResponse(return_url+'msg=Suggestion+moved.+No+access+was+granted.',303)
        baseline_dirty=save_apply_state()["dirty"]
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
        if action=='approve':
            applied=apply_saved_change(u['username'],auth.client_ip(request),'Approve dependency candidate',preexisting_dirty=baseline_dirty,role=u['role'])
            msg=apply_message(applied);key='msg' if applied.get('ok') else 'error'
            return RedirectResponse(return_url+key+'='+quote_plus(msg),303)
        return RedirectResponse(return_url+'msg=Candidate+ignored',303)
    except Exception as exc:
        return RedirectResponse(return_url+'error='+quote_plus(str(exc)),303)
