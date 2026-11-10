import re
from urllib.parse import quote_plus
from fastapi import APIRouter,Request,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.config import MODE
from app.services.notifications import settings,save_settings,history,queue_test
from app.services.notification_config import public_settings
from app.db import connect

router=APIRouter(prefix='/system/notifications')
def admin(request):return request.state.user and request.state.user['role']=='admin'


@router.get('',response_class=HTMLResponse)
def page(request:Request):
    if not admin(request):return HTMLResponse('Forbidden',403)
    c=connect()
    try:
        incidents=[dict(r) for r in c.execute('SELECT * FROM health_incidents WHERE active=1 ORDER BY severity,code')]
        last=c.execute("SELECT value FROM settings WHERE key='health_monitor_last_run'").fetchone()
    finally:c.close()
    return request.app.state.templates.TemplateResponse(request=request,name='system/notifications.html',context={'request':request,'page_title':'Health notifications',
        'cfg':public_settings(settings()),'deliveries':history(),'incidents':incidents,'last_run':last['value'] if last else 'Not sampled yet','mode':MODE})


@router.post('')
def save(request:Request,csrf_token:str=Form(...),enabled:bool=Form(False),email_enabled:bool=Form(False),slack_enabled:bool=Form(False),
 smtp_host:str=Form(''),smtp_port:int=Form(587),smtp_tls:str=Form('starttls'),smtp_username:str=Form(''),smtp_password:str=Form(''),sender:str=Form(''),recipients:str=Form(''),
 slack_webhook:str=Form(''),clear_smtp_password:bool=Form(False),clear_slack_webhook:bool=Form(False),minimum_severity:str=Form('warning'),confirmation_samples:int=Form(2),recovery_samples:int=Form(2),
 repeat_minutes:int=Form(60),disk_percent:int=Form(85),memory_percent:int=Form(90),certificate_days:int=Form(30),telemetry_lag_seconds:int=Form(120),cpu_percent:int=Form(90),backup_age_hours:int=Form(72)):
    if not admin(request):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(request.state.user,csrf_token):return HTMLResponse('Invalid request',403)
    value={k:v for k,v in locals().copy().items() if k not in ('request','csrf_token')}
    value['recipients']=[x.strip() for x in re.split(r'[,;\n]',recipients) if x.strip()]
    try:
        save_settings(value,request.state.user['username'],auth.client_ip(request))
        return RedirectResponse('/system/notifications?msg='+quote_plus('Settings saved. Channels run from the health monitor timer.' if MODE=='production' else 'Preview saved; outbound delivery is disabled.'),303)
    except ValueError as exc:
        return RedirectResponse('/system/notifications?error='+quote_plus(str(exc)),303)
    except (RuntimeError,OSError):
        # Credential validation/transport errors must not echo submitted secrets.
        return RedirectResponse('/system/notifications?error=Settings+could+not+be+saved.+Check+addresses,+TLS,+channel+credentials+and+thresholds.',303)


@router.post('/test/{channel}')
def test(channel:str,request:Request,csrf_token:str=Form(...)):
    if not admin(request):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(request.state.user,csrf_token):return HTMLResponse('Invalid request',403)
    try:
        queue_test(channel,request.state.user['username'])
        return RedirectResponse('/system/notifications?msg=Test+queued.+Its+result+will+appear+in+delivery+history.',303)
    except ValueError as exc:return RedirectResponse('/system/notifications?error='+quote_plus(str(exc)),303)


@router.get('/status')
def delivery_status(request:Request):
    if not admin(request):return HTMLResponse('Forbidden',403)
    c=connect()
    try:last=c.execute("SELECT value FROM settings WHERE key='health_monitor_last_run'").fetchone()
    finally:c.close()
    return {'deliveries':history(),'last_run':last['value'] if last else 'Not sampled yet'}
