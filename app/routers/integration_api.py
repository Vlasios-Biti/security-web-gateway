"""Bearer-only read interface for monitoring systems and AI tools."""
import ipaddress
from fastapi import APIRouter, Request, Query, HTTPException
from app.services.integrations import require_scope
from app.services.traffic import client_inventory, client_detail

router=APIRouter(prefix='/api/v1')


@router.get('/clients')
def inventory(request:Request, period:str='24h',q:str=Query('',max_length=200),page:int=Query(1,ge=1),page_size:int=Query(50,ge=25,le=100)):
    require_scope(request,'clients:read')
    if period not in ('1h','24h','7d','30d','all'):raise HTTPException(400,'Invalid period.')
    return {**client_inventory({'range':period},page,page_size,q),'visibility':'Proxy traffic only; DIRECT bypasses are not observed. Names are current IP labels, not historical identity.'}


@router.get('/clients/{client_ip}/traffic')
def activity(request:Request,client_ip:str,period:str='24h',page:int=Query(1,ge=1),page_size:int=Query(50,ge=25,le=100)):
    require_scope(request,'traffic:read')
    try:ip=str(ipaddress.ip_address(client_ip))
    except ValueError:raise HTTPException(400,'Invalid client IP.')
    if period not in ('1h','24h','7d','30d','all'):raise HTTPException(400,'Invalid period.')
    return {**client_detail(ip,period,page=page,page_size=page_size),'visibility':'Squid observations by source IP; NAT/DHCP may make identity ambiguous. Application attribution is a policy match, not a process measurement.'}
