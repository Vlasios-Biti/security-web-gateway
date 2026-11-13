"""Bounded SNMPv2c read-only polling and UDP notifications on a private management network."""
import hmac,ipaddress,socket,time
from pyasn1.codec.ber import decoder,encoder
from pysnmp.proto import api
v2=api.v2c
START=time.monotonic()

def _oid(value):return tuple(int(x) for x in value.split('.'))

def send_trap(cfg,body):
    pdu=v2.SNMPv2TrapPDU();v2.apiTrapPDU.set_defaults(pdu)
    base=cfg['snmp_oid'];severity=3 if 'CRITICAL' in body else (2 if 'WARNING' in body else 1)
    v2.apiTrapPDU.set_varbinds(pdu,[('1.3.6.1.2.1.1.3.0',v2.TimeTicks(int((time.monotonic()-START)*100)%4294967296)),('1.3.6.1.6.3.1.1.4.1.0',v2.ObjectIdentifier(base+'.0.1')),(base+'.10.0',v2.OctetString(body[:2400].encode('utf-8'))),(base+'.11.0',v2.Integer32(severity))])
    message=v2.Message();v2.apiMessage.set_defaults(message);v2.apiMessage.set_community(message,cfg['snmp_community']);v2.apiMessage.set_pdu(message,pdu)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:stream.sendto(encoder.encode(message),(cfg['snmp_host'],cfg['snmp_port']))


def snapshot(cfg):
    from app.db import connect
    from app.config import APP_VERSION,MANAGEMENT_FQDN
    from app.services.performance import latest_performance
    from app.services.system import cached_system_health
    health=cached_system_health();perf=latest_performance() or {};c=connect()
    try:incidents=[dict(r) for r in c.execute('SELECT severity FROM health_incidents WHERE active=1')]
    finally:c.close()
    state=3 if any(r['severity']=='critical' for r in incidents) else (2 if incidents else (0 if health.get('cache_stale',True) else 1))
    base=cfg['snmp_oid']
    values={base+'.1.0':v2.Integer32(state),base+'.2.0':v2.Gauge32(len(incidents)),base+'.3.0':v2.Integer32(round(float(perf.get('cpu_percent') or 0)*100)),base+'.4.0':v2.Integer32(round(float((health.get('memory') or {}).get('percent') or 0)*100)),base+'.5.0':v2.Integer32(round(float((health.get('disk') or {}).get('percent') or 0)*100)),base+'.6.0':v2.Integer32(1 if health.get('cache_stale',True) else 0),base+'.7.0':v2.Integer32(1 if health.get('port_ok') is True else (0 if health.get('port_ok') is False else -1)),base+'.8.0':v2.OctetString(APP_VERSION),'1.3.6.1.2.1.1.1.0':v2.OctetString('Security Web Gateway '+APP_VERSION),'1.3.6.1.2.1.1.3.0':v2.TimeTicks(int((time.monotonic()-START)*100)%4294967296),'1.3.6.1.2.1.1.5.0':v2.OctetString(MANAGEMENT_FQDN)}
    return {_oid(oid):value for oid,value in values.items()}


def respond(packet,source,cfg,values):
    if not cfg.get('snmp_agent_enabled') or len(packet)>8192:return None
    try:
        if not any(ipaddress.ip_address(source) in ipaddress.ip_network(net) for net in cfg['snmp_managers']):return None
        message,rest=decoder.decode(packet,asn1Spec=v2.Message())
        if rest or int(v2.apiMessage.get_version(message))!=1:return None
        community=v2.apiMessage.get_community(message).asOctets()
        if not hmac.compare_digest(community,cfg['snmp_community'].encode('utf-8')):return None
        pdu=v2.apiMessage.get_pdu(message);bindings=v2.apiPDU.get_varbinds(pdu)
        if len(bindings)>16:return None
        response=v2.apiMessage.get_response(message);reply=v2.apiMessage.get_pdu(response);keys=sorted(values);out=[]
        def next_value(oid):
            found=next((key for key in keys if key>tuple(oid)),None)
            return (found,values[found]) if found else (tuple(oid),v2.EndOfMibView(''))
        if pdu.tagSet==v2.GetRequestPDU.tagSet:
            out=[(tuple(oid),values.get(tuple(oid),v2.NoSuchInstance(''))) for oid,_ in bindings]
        elif pdu.tagSet==v2.GetNextRequestPDU.tagSet:out=[next_value(oid) for oid,_ in bindings]
        elif pdu.tagSet==v2.GetBulkRequestPDU.tagSet:
            count=min(max(int(v2.apiBulkPDU.get_non_repeaters(pdu)),0),len(bindings));repetitions=min(max(int(v2.apiBulkPDU.get_max_repetitions(pdu)),0),8)
            out=[next_value(oid) for oid,_ in bindings[:count]];current=[tuple(oid) for oid,_ in bindings[count:]]
            for _ in range(repetitions):
                batch=[next_value(oid) for oid in current];out.extend(batch);current=[oid for oid,_ in batch]
                if len(out)>=48:break
            out=out[:48]
        elif pdu.tagSet==v2.SetRequestPDU.tagSet:
            # SET never modifies any state.
            v2.apiPDU.set_error_status(reply,6);v2.apiPDU.set_error_index(reply,1);out=bindings
        else:return None
        v2.apiPDU.set_varbinds(reply,out);encoded=encoder.encode(response)
        return encoded if len(encoded)<=8192 else None
    except Exception:return None
