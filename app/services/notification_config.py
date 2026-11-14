"""Structured health-channel configuration, shared with the privileged helper."""
import json
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

SLACK_TOPICS={'services':'Proxy & management services','resources':'CPU, memory & disk','dns':'DNS resolution','certificate':'HTTPS certificate','backup':'Configuration backups','workers':'Background workers','clock':'Clock synchronization','traffic':'Traffic telemetry','policy':'Policy drift'}


def event_topic(code):
    if code in ('squid_status','nginx_status','app_status','proxy_listener'):return 'services'
    if code in ('disk','memory','cpu'):return 'resources'
    if code.startswith('certificate'):return 'certificate'
    if code.startswith('worker_'):return 'workers'
    return {'backup':'backup','dns':'dns','ntp':'clock','telemetry':'traffic','sampler':'traffic','policy_drift':'policy','expiry':'policy'}.get(code,'services')

PATH=Path('/etc/security-web-gateway/notifications.json')
DEFAULTS={'enabled':False,'email_enabled':False,'slack_enabled':False,'smtp_host':'','smtp_port':587,'smtp_tls':'starttls',
 'smtp_username':'','smtp_password':'','sender':'','recipients':[],'slack_webhook':'','minimum_severity':'warning',
 'confirmation_samples':2,'recovery_samples':2,'repeat_minutes':60,'disk_percent':85,'memory_percent':90,
 'certificate_days':30,'telemetry_lag_seconds':120,'cpu_percent':90,'backup_age_hours':72,'revision':0,'slack_topics':list(SLACK_TOPICS),'slack_minimum_severity':'inherit','slack_recovery':True,'slack_repeat_minutes':-1,'slack_format':'detailed','slack_mentions':[],'slack_mention_critical_only':True,'slack_destination':'','snmp_enabled':False,'snmp_agent_enabled':False,'snmp_host':'','snmp_port':162,'snmp_bind':'127.0.0.1','snmp_agent_port':1161,'snmp_managers':[],'snmp_community':'','snmp_oid':'1.3.6.1.4.1.32473.42'}


def _email(value):
    if not isinstance(value,str) or len(value)>254 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}",value):
        raise ValueError('Use plain valid email addresses, without names or line breaks.')
    return value


def validate_settings(value,previous=None):
    if not isinstance(value,dict):raise ValueError('Invalid notification settings.')
    old={**DEFAULTS,**(previous or {})};result={**DEFAULTS}
    for key in ('enabled','email_enabled','slack_enabled','snmp_enabled','snmp_agent_enabled'):
        if type(value.get(key,False)) is not bool:raise ValueError('Invalid channel switch.')
        result[key]=value.get(key,False)
    for key in ('smtp_host','smtp_username','sender'):
        item=value.get(key,'')
        if not isinstance(item,str) or len(item)>254 or any(ord(x)<32 for x in item):raise ValueError('Invalid SMTP field.')
        result[key]=item.strip()
    if result['smtp_host'] and not re.fullmatch(r'[a-zA-Z0-9._:-]+',result['smtp_host']):raise ValueError('Use an SMTP hostname or IP without a URL or port.')
    for key,low,high in [('smtp_port',1,65535),('confirmation_samples',1,10),('recovery_samples',1,10),('repeat_minutes',0,1440),('disk_percent',50,99),('memory_percent',50,99),('certificate_days',1,90),('telemetry_lag_seconds',30,3600),('cpu_percent',50,99),('backup_age_hours',0,720)]:
        item=value.get(key,DEFAULTS[key])
        if type(item) is not int or not low<=item<=high:raise ValueError('Invalid setting: '+key)
        result[key]=item
    result['smtp_tls']=value.get('smtp_tls','starttls')
    if result['smtp_tls'] not in ('starttls','ssl'):raise ValueError('Choose STARTTLS or implicit TLS.')
    result['minimum_severity']=value.get('minimum_severity','warning')
    if result['minimum_severity'] not in ('warning','critical'):raise ValueError('Invalid minimum severity.')
    for key in ('slack_recovery','slack_mention_critical_only'):
        item=value.get(key,DEFAULTS[key])
        if type(item) is not bool:raise ValueError('Invalid Slack notification switch.')
        result[key]=item
    topics=value.get('slack_topics',list(SLACK_TOPICS))
    if not isinstance(topics,list) or any(not isinstance(x,str) or x not in SLACK_TOPICS for x in topics):raise ValueError('Choose valid Slack event categories.')
    result['slack_topics']=list(dict.fromkeys(topics))
    result['slack_minimum_severity']=value.get('slack_minimum_severity','inherit')
    if result['slack_minimum_severity'] not in ('inherit','warning','critical'):raise ValueError('Invalid Slack severity.')
    repeat=value.get('slack_repeat_minutes',-1)
    if type(repeat) is not int or not -1<=repeat<=1440:raise ValueError('Invalid Slack repeat interval.')
    result['slack_repeat_minutes']=repeat
    result['slack_format']=value.get('slack_format','detailed')
    if result['slack_format'] not in ('detailed','compact'):raise ValueError('Choose compact or detailed Slack messages.')
    mentions=value.get('slack_mentions',[])
    if not isinstance(mentions,list) or len(mentions)>10 or any(not isinstance(x,str) or not re.fullmatch(r'[UWS][A-Z0-9]{2,31}',x) for x in mentions):raise ValueError('Use up to 10 Slack member IDs (U/W...) or user-group IDs (S...), separated by commas.')
    result['slack_mentions']=list(dict.fromkeys(mentions))
    destination=value.get('slack_destination','')
    if not isinstance(destination,str) or len(destination)>80 or any(ord(x)<32 for x in destination):raise ValueError('Invalid Slack channel label.')
    result['slack_destination']=destination.strip()
    recipients=value.get('recipients',[])
    if not isinstance(recipients,list) or len(recipients)>20:raise ValueError('Use up to twenty recipients.')
    if any(not isinstance(x,str) for x in recipients):raise ValueError('Invalid recipient.')
    result['recipients']=list(dict.fromkeys(_email(x.strip()) for x in recipients if isinstance(x,str) and x.strip()))
    if result['sender']:_email(result['sender'])
    for key,clear in [('smtp_password','clear_smtp_password'),('slack_webhook','clear_slack_webhook'),('snmp_community','clear_snmp_community')]:
        item=value.get(key,'')
        if not isinstance(item,str) or len(item)>2048 or any(ord(x)<32 for x in item):raise ValueError('Invalid credential field.')
        result[key]='' if value.get(clear) is True else (item or old.get(key,''))
    if result['slack_webhook']:
        try:
            u=urlsplit(result['slack_webhook']);port=u.port
        except ValueError as exc:raise ValueError('Invalid Slack webhook URL.') from None
        if u.scheme!='https' or u.hostname not in ('hooks.slack.com','hooks.slack-gov.com') or port not in (None,443) or u.username or u.password or u.query or u.fragment or not re.fullmatch(r'/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+',u.path):
            raise ValueError('Use a Slack Incoming Webhook HTTPS URL from hooks.slack.com or hooks.slack-gov.com.')
    identity_changed=result['smtp_host'].lower()!=str(old.get('smtp_host','')).lower() or result['smtp_username']!=old.get('smtp_username','')
    if identity_changed and old.get('smtp_password') and not value.get('smtp_password') and value.get('clear_smtp_password') is not True:
        raise ValueError('SMTP server or username changed. Re-enter or clear the password before saving.')
    if result['email_enabled'] and not (result['smtp_host'] and result['sender'] and result['recipients']):raise ValueError('Email requires SMTP host, sender and recipients.')
    if result['smtp_username'] and result['email_enabled'] and not result['smtp_password']:raise ValueError('SMTP authentication requires a password.')
    if result['slack_enabled'] and not result['slack_webhook']:raise ValueError('Configure a Slack webhook before enabling Slack.')
    for key,low,high in [('snmp_port',1,65535),('snmp_agent_port',1024,65535)]:
        item=value.get(key,DEFAULTS[key])
        if type(item) is not int or not low<=item<=high:raise ValueError('Invalid SNMP port.')
        result[key]=item
    for key in ('snmp_host','snmp_bind'):
        item=value.get(key,DEFAULTS[key])
        if not isinstance(item,str):raise ValueError('Use an IPv4 address for SNMP.')
        if item:
            try:ip=ipaddress.IPv4Address(item)
            except ValueError:raise ValueError('Use an IPv4 address for SNMP.') from None
            if ip.is_unspecified or ip.is_multicast or str(ip)=='255.255.255.255':raise ValueError('Use a specific unicast IPv4 address for SNMP.')
        result[key]=item
    managers=value.get('snmp_managers',[])
    if not isinstance(managers,list) or len(managers)>16:raise ValueError('Use up to 16 SNMP manager addresses or subnets.')
    result['snmp_managers']=[]
    for item in managers:
        try:net=ipaddress.ip_network(item,strict=False)
        except (ValueError,TypeError):raise ValueError('Invalid SNMP manager IPv4 subnet.') from None
        if net.version!=4 or net.prefixlen<8:raise ValueError('Use specific SNMP manager IPv4 addresses/subnets, not all networks.')
        result['snmp_managers'].append(str(net))
    oid=value.get('snmp_oid',DEFAULTS['snmp_oid'])
    if not isinstance(oid,str) or not re.fullmatch(r'1\.3\.6\.1\.4\.1\.[1-9][0-9]*(?:\.[0-9]+){1,12}',oid) or any(int(x)>2147483647 for x in oid.split('.')):raise ValueError('Use a numeric enterprise SNMP OID.')
    result['snmp_oid']=oid
    if result['snmp_enabled'] or result['snmp_agent_enabled']:
        if not (16<=len(result['snmp_community'])<=128 and result['snmp_community'].isascii() and result['snmp_community'].isprintable()):raise ValueError('Set an SNMP community of 16–128 characters.')
    if result['snmp_enabled'] and not result['snmp_host']:raise ValueError('Set the SNMP notification receiver IP.')
    if result['snmp_agent_enabled'] and (not result['snmp_bind'] or not result['snmp_managers']):raise ValueError('Set the SNMP listener IP and permitted manager IPs.')
    result['revision']=int(old.get('revision',0))+1
    return result


def read_settings(path=None):
    p=Path(path) if path else PATH
    if not p.is_file():return {**DEFAULTS}
    if p.stat().st_size>32768:raise ValueError('Notification configuration is oversized.')
    value=json.loads(p.read_text(encoding='utf-8'))
    return {**DEFAULTS,**value}


def public_settings(value):
    result={**value}
    result['smtp_password_configured']=bool(result.pop('smtp_password',''))
    result['slack_webhook_configured']=bool(result.pop('slack_webhook',''))
    result['snmp_community_configured']=bool(result.pop('snmp_community',''))
    return result
