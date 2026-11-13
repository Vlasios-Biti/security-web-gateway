#!/usr/bin/env python3
import json,socket,sys,time,ipaddress
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.config import MODE
from app.services.notifications import settings
from app.services.snmp import respond,snapshot

def main():
    stream=None;signature=None;values={};sampled=0;tokens={};total_second=-1;total=0
    while True:
        try:
            cfg=settings();current=(cfg['revision'],cfg['snmp_agent_enabled'],cfg['snmp_bind'],cfg['snmp_agent_port'])
            if current!=signature:
                if stream:stream.close();stream=None
                if MODE=='production' and cfg['snmp_agent_enabled']:
                    stream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);stream.bind((cfg['snmp_bind'],cfg['snmp_agent_port']));stream.settimeout(1)
                signature=current
            if not stream:time.sleep(2);continue
            if time.monotonic()-sampled>5:values=snapshot(cfg);sampled=time.monotonic()
            try:packet,peer=stream.recvfrom(8193)
            except socket.timeout:continue
            # Bound per-manager response rates and memory; disallowed IPs get no response.
            if not any(ipaddress.ip_address(peer[0]) in ipaddress.ip_network(net) for net in cfg['snmp_managers']):continue
            now=int(time.monotonic());key=(peer[0],now)
            if now!=total_second:total_second=now;total=0
            total+=1
            if total>100:continue
            if len(tokens)>512:tokens={k:v for k,v in tokens.items() if k[1]>=now-1}
            if key not in tokens and len(tokens)>=512:continue
            tokens[key]=tokens.get(key,0)+1
            if tokens[key]>10:continue
            reply=respond(packet,peer[0],cfg,values)
            if reply:stream.sendto(reply,peer)
        except Exception as exc:
            print(json.dumps({'snmp_error':type(exc).__name__}),flush=True)
            if stream:stream.close();stream=None
            signature=None;time.sleep(5)
if __name__=='__main__':main()
