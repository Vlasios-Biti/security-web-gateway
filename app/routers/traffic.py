from urllib.parse import urlencode

from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, Response, RedirectResponse

from app import auth
from app.db import audit
from app.services.traffic import (
    list_events, traffic_summary, clients, client_inventory, client_detail, filter_options,
    export_csv, export_xlsx, telemetry_health, update_retention, top_items,
)

router = APIRouter(prefix="/traffic")


def _filters(request, forced_decision=None, default_range="1h"):
    q = request.query_params
    import ipaddress
    from datetime import datetime
    for key in ('network_id','application_id','port'):
        value=q.get(key,'').strip()
        if value:
            try:number=int(value)
            except ValueError:raise HTTPException(400,'Invalid '+key+'. Use a positive whole number.') from None
            if number<1 or number>9223372036854775807 or (key=='port' and number>65535):raise HTTPException(400,'Invalid '+key+'.')
    if q.get('client_ip','').strip():
        try:ipaddress.ip_address(q['client_ip'].strip())
        except ValueError:raise HTTPException(400,'Invalid client IP.') from None
    dates={}
    for key in ('date_from','date_to'):
        if q.get(key):
            try:dates[key]=datetime.fromisoformat(q[key]).timestamp()
            except (ValueError,OverflowError):raise HTTPException(400,'Invalid '+key+'.') from None
    if dates.get('date_from',0)>dates.get('date_to',float('inf')):raise HTTPException(400,'Start date must be before end date.')
    data = {
        "range": q.get("range", default_range),
        "date_from": q.get("date_from", ""),
        "date_to": q.get("date_to", ""),
        "client_ip": q.get("client_ip", "").strip(),
        "destination": q.get("destination", "").strip(),
        "destination_ip": q.get("destination_ip", "").strip(),
        "decision": forced_decision or q.get("decision", "").strip().upper(),
        "method": q.get("method", "").strip().upper(),
        "network_id": q.get("network_id", "").strip(),
        "application_id": q.get("application_id", "").strip(),
        "port": q.get("port", "").strip(),
        "traffic_path": q.get("traffic_path", "").strip().upper(),
        "include_system": "1" if q.get("include_system", "").strip().lower() in ("1","true","yes","on") else "",
        "q": q.get("q", "").strip(),
    }
    if data["decision"] not in ("", "ALLOW", "DENY", "INFO"): data["decision"] = ""
    if data["method"] not in ("", "CONNECT", "GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE", "PATCH"): data["method"] = ""
    if data["traffic_path"] not in ("", "PROXY", "DIRECT", "EMERGENCY-DIRECT"): data["traffic_path"] = ""
    return data


def _render_explorer(request, title="Traffic Explorer", forced_decision=None, default_range="1h"):
    f = _filters(request, forced_decision, default_range)
    try: page = int(request.query_params.get("page", "1"))
    except Exception: page = 1
    try: page_size = int(request.query_params.get("page_size", "100"))
    except Exception: page_size = 100
    result = list_events(f, page, page_size)
    summary = traffic_summary(f)
    opts = filter_options()
    health = telemetry_health()
    export_params = {k:v for k,v in f.items() if v not in (None,"")}
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="traffic/explorer.html",
        context={
            "request": request, "page_title": title, "filters": f, "result": result,
            "summary": summary, "options": opts, "health": health,
            "export_query": urlencode(export_params),
            "nav_query": urlencode({**export_params,"page_size":result["page_size"]}),
            "top_destinations": top_items(f,"destination_host",8),
            "top_apps": top_items(f,"application_names",8),
        },
    )


@router.get("/explorer", response_class=HTMLResponse)
def explorer(request: Request):
    return _render_explorer(request)


@router.get("/live", response_class=HTMLResponse)
def live(request: Request):
    return _render_explorer(request, "Live Traffic", default_range="15m")


@router.get("/blocked", response_class=HTMLResponse)
def blocked(request: Request):
    return _render_explorer(request, "Blocked Traffic", forced_decision="DENY", default_range="24h")


@router.get("/allowed", response_class=HTMLResponse)
def allowed(request: Request):
    return _render_explorer(request, "Allowed Traffic", forced_decision="ALLOW", default_range="24h")


@router.get("/clients", response_class=HTMLResponse)
def client_page(request: Request):
    range_key=request.query_params.get('range','24h');search=request.query_params.get('q','').strip()[:200]
    try:page=max(1,int(request.query_params.get('page','1')))
    except ValueError:page=1
    inventory=client_inventory({'range':range_key},page,50,search)
    return request.app.state.templates.TemplateResponse(
        request=request,name='traffic/clients.html',
        context={'request':request,'page_title':'PC activity','clients':inventory['rows'],'inventory':inventory,'search':search,
                 'range_key':range_key,'nav_query':urlencode({'range':range_key,'q':search}),'health':telemetry_health()}
    )


@router.get("/clients/{client_ip}", response_class=HTMLResponse)
def client_detail_page(request: Request, client_ip: str):
    import ipaddress
    try:client_ip=str(ipaddress.ip_address(client_ip))
    except ValueError:return RedirectResponse('/traffic/clients?error=Invalid+client+IP',303)
    filters=_filters(request,default_range='24h');filters['client_ip']=client_ip
    try:page=max(1,int(request.query_params.get('page','1')))
    except ValueError:page=1
    try:page_size=max(25,min(500,int(request.query_params.get('page_size','100'))))
    except ValueError:page_size=100
    detail=client_detail(client_ip,filters['range'],filters,page,page_size)
    params={key:value for key,value in filters.items() if value not in (None,'')}
    return request.app.state.templates.TemplateResponse(
        request=request,name='traffic/client_detail.html',
        context={'request':request,'page_title':'PC activity','detail':detail,'range_key':filters['range'],'filters':filters,
                 'export_query':urlencode(params),'nav_query':urlencode({**params,'page_size':page_size}),
                 'ranges':[('1h','Last hour'),('24h','Last 24 hours'),('7d','Last 7 days'),('30d','Last 30 days'),('all','All retained')]})


@router.get("/export.csv")
def export_csv_route(request: Request):
    f=_filters(request,default_range="24h")
    payload=export_csv(f)
    stamp=__import__('datetime').datetime.now().strftime('%Y%m%d-%H%M%S')
    return Response(payload,media_type="text/csv; charset=utf-8",headers={"Content-Disposition":f'attachment; filename="security-web-gateway-traffic-{stamp}.csv"'})


@router.get("/export.xlsx")
def export_xlsx_route(request: Request):
    f=_filters(request,default_range="24h")
    payload=export_xlsx(f)
    stamp=__import__('datetime').datetime.now().strftime('%Y%m%d-%H%M%S')
    return Response(payload,media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",headers={"Content-Disposition":f'attachment; filename="security-web-gateway-traffic-{stamp}.xlsx"'})


@router.post("/settings/retention")
def retention(request: Request, days: int = Form(...), csrf_token: str = Form(...)):
    user=request.state.user
    if not user or user["role"]!="admin":
        return RedirectResponse("/traffic/explorer?error=Admin+role+required",303)
    if not auth.check_csrf(user,csrf_token):
        audit(user["username"],"TELEMETRY_RETENTION","FAILED",source_ip=auth.client_ip(request),details_json='{"reason":"csrf"}')
        return RedirectResponse("/traffic/explorer?error=Invalid+CSRF",303)
    new_days=update_retention(days)
    audit(user["username"],"TELEMETRY_RETENTION","SUCCESS",object_type="settings",object_id="telemetry_retention_days",source_ip=auth.client_ip(request),details_json=f'{{"days":{new_days}}}')
    return RedirectResponse(f"/traffic/explorer?msg=Telemetry+retention+set+to+{new_days}+days",303)
