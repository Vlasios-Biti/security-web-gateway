"""Persistent health incidents, independent channel delivery and retry backoff."""
import http.client
import json
import os
import re
import smtplib
import ssl
import tempfile
import time
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlsplit
from app.config import MODE,DATA_ROOT,MANAGEMENT_FQDN
from app.db import connect,audit
from app.services.notification_config import PATH,read_settings,validate_settings,public_settings


def config_path():return PATH if MODE=='production' else DATA_ROOT/'notifications-preview.json'
def settings():return read_settings(config_path())


def save_settings(value,actor,source_ip=None):
    validated=validate_settings(value,settings())
    if MODE=='production':
        from app.services.deployment import helper_request
        result=helper_request('save_notifications',settings=value)
        if not result.get('ok'):raise ValueError(result.get('message') or 'Notification configuration failed.')
    else:
        path=config_path();path.parent.mkdir(parents=True,exist_ok=True)
        fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.notifications-')
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as stream:json.dump(validated,stream)
            os.chmod(tmp,0o600);os.replace(tmp,path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    audit(actor,'NOTIFICATION_SETTINGS','SUCCESS' if MODE=='production' else 'CANDIDATE_ONLY','settings','health',source_ip,
          json.dumps({k:validated[k] for k in ('enabled','email_enabled','slack_enabled')}))


def conditions(health,perf,drift,cfg,cache_stale=False,backup_age_hours=None):
    found={}
    def add(code,severity,title,detail):found[code]={'severity':severity,'title':title,'detail':str(detail)[:300]}
    for key,title in [('squid_status','Proxy service'),('nginx_status','Management HTTPS'),('app_status','Management application')]:
        if health.get(key) not in ('active','warming',None):add(key,'critical',title+' is unavailable',health.get(key))
    if health.get('port_ok') is False:add('proxy_listener','critical','Proxy listener is unavailable','Clients cannot reach the proxy port.')
    for key,limit,title in [('disk',cfg['disk_percent'],'Disk utilization'),('memory',cfg['memory_percent'],'Memory utilization')]:
        value=(health.get(key) or {}).get('percent')
        if value is not None and value>=limit:add(key,'critical' if value>=97 else 'warning',title+' is high',f'{value}% (threshold {limit}%)')
    if perf and perf.get('cpu_percent') is not None and perf['cpu_percent']>=cfg['cpu_percent']:add('cpu','warning','CPU utilization is high',str(perf['cpu_percent'])+'%')
    if cfg['backup_age_hours'] and (backup_age_hours is None or backup_age_hours>cfg['backup_age_hours']):add('backup','warning','Configuration backup needs attention','No recent successful backup is recorded.')
    cert=health.get('certificate') or {};days=cert.get('days_remaining')
    if cert.get('state')=='unknown':add('certificate_check','warning','Certificate monitoring is unavailable','Review the management certificate configuration.')
    if days is not None and days<=cfg['certificate_days']:add('certificate','critical' if days<=7 else 'warning','Management certificate expires soon',f'{days} days remaining')
    for row in health.get('dns',[]):
        if not row.get('ok'):add('dns','warning','A DNS resolver is unavailable','Check configured enterprise DNS resolvers.')
    for key,value in (health.get('workers') or {}).items():
        if value!='active':add('worker_'+key,'warning','Background worker needs attention',key+': '+str(value))
    if (health.get('ntp') or {}).get('ok') is False:add('ntp','warning','Clock synchronization needs attention','Review NTP status.')
    if perf and perf.get('telemetry_lag_seconds') is not None and perf['telemetry_lag_seconds']>cfg['telemetry_lag_seconds']:
        add('telemetry','warning','Traffic telemetry is delayed',f"{round(perf['telemetry_lag_seconds'])} seconds behind")
    if drift.get('state')=='drift':add('policy_drift','critical','Live proxy configuration differs from the published policy','Review Activity before applying changes.')
    if cache_stale:add('sampler','warning','Performance sampling is stale','Check the performance timer.')
    return found


def update_incidents(found,cfg,now=None):
    now=time.time() if now is None else now;c=connect()
    try:
        c.execute('BEGIN IMMEDIATE')
        existing={r['code']:dict(r) for r in c.execute('SELECT * FROM health_incidents')}
        for code in sorted(set(existing)|set(found)):
            old=existing.get(code);event=found.get(code)
            if old is None:
                old={'active':0,'bad_samples':0,'good_samples':0,'generation':0,'changed_epoch':now,**event}
            bad=(old['bad_samples']+1) if event else 0;good=0 if event else old['good_samples']+1
            active=old['active'];generation=old['generation'];changed=old['changed_epoch']
            severity=(event or old)['severity']
            if event and (not active and bad>=cfg['confirmation_samples'] or active and severity!=old['severity']):
                active=1;generation+=1;changed=now
            if not event and active and good>=cfg['recovery_samples']:
                active=0;generation+=1;changed=now
            item=event or old
            c.execute('''INSERT INTO health_incidents(code,severity,title,detail,active,bad_samples,good_samples,generation,changed_epoch,updated_epoch)
             VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(code) DO UPDATE SET severity=excluded.severity,title=excluded.title,detail=excluded.detail,
             active=excluded.active,bad_samples=excluded.bad_samples,good_samples=excluded.good_samples,generation=excluded.generation,changed_epoch=excluded.changed_epoch,updated_epoch=excluded.updated_epoch''',
             (code,severity,item['title'],item['detail'],active,min(bad,1000),min(good,1000),generation,changed,now))
        c.commit()
    finally:c.close()


def send_channel(channel,cfg,body):
    if channel=='email':
        message=EmailMessage();message['From']=cfg['sender'];message['To']=', '.join(cfg['recipients'])
        message['Subject']='Security Web Gateway health update';message.set_content(body)
        context=ssl.create_default_context()
        if cfg['smtp_tls']=='ssl':client=smtplib.SMTP_SSL(cfg['smtp_host'],cfg['smtp_port'],timeout=15,context=context)
        else:client=smtplib.SMTP(cfg['smtp_host'],cfg['smtp_port'],timeout=15)
        with client:
            if cfg['smtp_tls']=='starttls':client.ehlo();client.starttls(context=context);client.ehlo()
            if cfg['smtp_username']:client.login(cfg['smtp_username'],cfg['smtp_password'])
            refused=client.send_message(message)
            if refused:raise RuntimeError('SMTP_RECIPIENT_REJECTED')
    elif channel=='slack':
        url=urlsplit(cfg['slack_webhook'])
        # No redirects: the secret path must never be forwarded to another host.
        connection=http.client.HTTPSConnection(url.hostname,443,timeout=12,context=ssl.create_default_context())
        try:
            payload=json.dumps({'text':'Security Web Gateway health update','blocks':[{'type':'section','text':{'type':'plain_text','text':body[:2900]}}]})
            connection.request('POST',url.path,body=payload,headers={'Content-Type':'application/json'})
            response=connection.getresponse();result=response.read(256)
            if response.status!=200 or result.strip()!=b'ok':raise RuntimeError('SLACK_HTTP_'+str(response.status))
        finally:connection.close()
    elif channel=='snmp':
        from app.services.snmp import send_trap
        send_trap(cfg,body)
    else:raise ValueError('Unsupported channel')


def _error_code(exc):
    # Never persist SMTP responses, webhook URLs, credentials or response bodies.
    if isinstance(exc,RuntimeError) and re.fullmatch(r'(SLACK_HTTP_\d{3}|SMTP_RECIPIENT_REJECTED)',str(exc)):return str(exc)
    return type(exc).__name__[:64]


def deliver(cfg,now=None):
    now=time.time() if now is None else now
    if MODE!='production' or not cfg['enabled']:return {'sent':0,'failed':0}
    sent=failed=0
    for channel in ('email','slack','snmp'):
        if not cfg[channel+'_enabled']:continue
        c=connect()
        try:
            due=[]
            for row in c.execute('SELECT * FROM health_incidents WHERE generation>0 ORDER BY active DESC,severity,code'):
                event=dict(row);prior=c.execute('SELECT * FROM health_delivery_state WHERE code=? AND channel=?',(event['code'],channel)).fetchone()
                prior=dict(prior) if prior else {'generation':0,'revision':0,'last_active':0,'last_sent_epoch':0,'next_attempt_epoch':0,'failures':0,'attempt_generation':0}
                if prior['next_attempt_epoch']>now and prior['revision']==cfg['revision'] and prior['attempt_generation']==event['generation']:continue
                if not event['active'] and not prior['last_active']:continue
                if event['active'] and cfg['minimum_severity']=='critical' and event['severity']!='critical':continue
                new=event['generation']!=prior['generation'] or prior['revision']!=cfg['revision']
                reminder=bool(event['active'] and cfg['repeat_minutes'] and now-prior['last_sent_epoch']>=cfg['repeat_minutes']*60)
                if new or reminder:due.append((event,prior))
                if len(due)>=10:break
        finally:c.close()
        if not due:continue
        lines=[f'Security Web Gateway — {MANAGEMENT_FQDN}', '']
        for event,prior in due:
            label='ALERT' if event['active'] else 'RECOVERED'
            lines.append(f"{label} [{event['severity'].upper()}] {event['title'][:80]}: {event['detail'][:120]}")
        error=None
        try:send_channel(channel,cfg,'\n'.join(lines))
        except Exception as exc:error=_error_code(exc)
        c=connect()
        try:
            for event,prior in due:
                failures=prior['failures']+1 if error else 0
                c.execute('''INSERT INTO health_delivery_state(code,channel,generation,revision,last_active,last_sent_epoch,next_attempt_epoch,failures,attempt_generation)
                 VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(code,channel) DO UPDATE SET generation=excluded.generation,revision=excluded.revision,last_active=excluded.last_active,
                 last_sent_epoch=excluded.last_sent_epoch,next_attempt_epoch=excluded.next_attempt_epoch,failures=excluded.failures,attempt_generation=excluded.attempt_generation''',
                 (event['code'],channel,prior['generation'] if error else event['generation'],cfg['revision'],prior['last_active'] if error else event['active'],
                  prior['last_sent_epoch'] if error else now,now+min(3600,60*2**min(failures,6)) if error else 0,failures,event['generation']))
            c.execute('INSERT INTO health_deliveries(channel,kind,result,event_count,error_code) VALUES(?,?,?,?,?)',(channel,'HEALTH','FAILED' if error else 'SENT',len(due),error))
            c.execute('DELETE FROM health_deliveries WHERE id NOT IN (SELECT id FROM health_deliveries ORDER BY id DESC LIMIT 1000)');c.commit()
        finally:c.close()
        if error:failed+=1
        else:sent+=1
    return {'sent':sent,'failed':failed}


def queue_test(channel,actor):
    cfg=settings()
    if MODE!='production':raise ValueError('Outbound tests are disabled in candidate preview.')
    if channel not in ('email','slack','snmp') or not cfg[channel+'_enabled']:raise ValueError('Configure and enable that channel first.')
    c=connect()
    try:
        if c.execute("SELECT 1 FROM health_test_queue WHERE channel=? AND status='pending'",(channel,)).fetchone():raise ValueError('A test is already queued.')
        c.execute('INSERT INTO health_test_queue(channel,requested_by,revision,requested_epoch) VALUES(?,?,?,?)',(channel,actor,cfg['revision'],time.time()));c.commit()
    finally:c.close()
    audit(actor,'NOTIFICATION_TEST','QUEUED','settings',channel)


def process_tests(cfg):
    if MODE!='production':return
    c=connect()
    try:rows=[dict(r) for r in c.execute("SELECT * FROM health_test_queue WHERE status='pending' ORDER BY id LIMIT 10")]
    finally:c.close()
    for row in rows:
        valid=cfg[row['channel']+'_enabled'] and row['revision']==cfg['revision'] and time.time()-row['requested_epoch']<600
        status='CANCELLED';error=None
        if valid:
            try:send_channel(row['channel'],cfg,f'Security Web Gateway — {MANAGEMENT_FQDN}\nAdministrator-requested channel test. No incident is implied.');status='SENT'
            except Exception as exc:status='FAILED';error=_error_code(exc)
        c=connect()
        try:
            c.execute('UPDATE health_test_queue SET status=? WHERE id=?',(status.lower(),row['id']))
            c.execute('INSERT INTO health_deliveries(channel,kind,result,event_count,error_code) VALUES(?,?,?,?,?)',(row['channel'],'TEST',status,1,error));c.commit()
        finally:c.close()


def history():
    c=connect()
    try:return [dict(r) for r in c.execute('SELECT * FROM health_deliveries ORDER BY id DESC LIMIT 30')]
    finally:c.close()
