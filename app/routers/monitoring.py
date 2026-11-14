import re
from urllib.parse import quote_plus
from fastapi import APIRouter,Request,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.config import MODE,PROXY_IP
from app.services.notifications import settings,save_settings,history,queue_test
from app.services.notification_config import public_settings, SLACK_TOPICS
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
    return request.app.state.templates.TemplateResponse(request=request,name='system/notifications.html',context={'request':request,'page_title':'Alerts & SNMP',
        'slack_topics':SLACK_TOPICS,'gateway_ip':PROXY_IP,'cfg':public_settings(settings()),'deliveries':history(),'incidents':incidents,'last_run':last['value'] if last else 'Not sampled yet','mode':MODE})


@router.post('')
def save(request:Request,csrf_token:str=Form(...),enabled:bool=Form(False),email_enabled:bool=Form(False),slack_enabled:bool=Form(False),
 smtp_host:str=Form(''),smtp_port:int=Form(587),smtp_tls:str=Form('starttls'),smtp_username:str=Form(''),smtp_password:str=Form(''),sender:str=Form(''),recipients:str=Form(''),
 slack_webhook:str=Form(''),slack_topics:list[str]=Form(default=list(SLACK_TOPICS)),slack_minimum_severity:str=Form('inherit'),slack_recovery:bool=Form(False),slack_repeat_minutes:int=Form(-1),slack_format:str=Form('detailed'),slack_mentions:str=Form(''),slack_mention_critical_only:bool=Form(False),slack_destination:str=Form(''),slack_options_present:bool=Form(False),clear_smtp_password:bool=Form(False),clear_slack_webhook:bool=Form(False),minimum_severity:str=Form('warning'),confirmation_samples:int=Form(2),recovery_samples:int=Form(2),
 repeat_minutes:int=Form(60),disk_percent:int=Form(85),memory_percent:int=Form(90),certificate_days:int=Form(30),telemetry_lag_seconds:int=Form(120),cpu_percent:int=Form(90),backup_age_hours:int=Form(72),snmp_enabled:bool=Form(False),snmp_agent_enabled:bool=Form(False),snmp_host:str=Form(''),snmp_port:int=Form(162),snmp_bind:str=Form('127.0.0.1'),snmp_agent_port:int=Form(1161),snmp_managers:str=Form(''),snmp_community:str=Form(''),clear_snmp_community:bool=Form(False),snmp_oid:str=Form('1.3.6.1.4.1.32473.42')):
    if not admin(request):return HTMLResponse('Forbidden',403)
    if not auth.check_csrf(request.state.user,csrf_token):return HTMLResponse('Invalid request',403)
    value={k:v for k,v in locals().copy().items() if k not in ('request','csrf_token')}
    value.pop('slack_options_present')
    if slack_options_present:
        value['slack_topics']=[x for x in slack_topics if x!='__none__']
        value['slack_mentions']=[x.strip() for x in re.split(r'[,;\s]+',slack_mentions) if x.strip()]
    else:
        # Preserve stored per-channel options for older clients posting the old form.
        current=settings()
        for key in ('slack_topics','slack_minimum_severity','slack_recovery','slack_repeat_minutes','slack_format','slack_mentions','slack_mention_critical_only','slack_destination'):value[key]=current[key]
    value['snmp_managers']=[x.strip() for x in re.split(r'[,;\n]',snmp_managers) if x.strip()]
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
