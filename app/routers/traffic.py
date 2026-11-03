from urllib.parse import urlencode

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, Response, RedirectResponse

from app import auth
from app.db import audit
from app.services.traffic import (
    list_events, traffic_summary, clients, client_detail, filter_options,
    export_csv, export_xlsx, telemetry_health, update_retention, top_items,
)

router = APIRouter(prefix="/traffic")


def _filters(request, forced_decision=None, default_range="1h"):
    q = request.query_params
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
    range_key=request.query_params.get("range","24h")
    return request.app.state.templates.TemplateResponse(
        request=request,name="traffic/clients.html",
        context={"request":request,"page_title":"Proxy Clients","clients":clients({"range":range_key}),"range_key":range_key,"health":telemetry_health()}
    )


@router.get("/clients/{client_ip}", response_class=HTMLResponse)
def client_detail_page(request: Request, client_ip: str):
    range_key=request.query_params.get("range","24h")
    try: detail=client_detail(client_ip,range_key)
    except Exception:
        return RedirectResponse("/traffic/clients?error=Invalid+client+IP",303)
    return request.app.state.templates.TemplateResponse(
        request=request,name="traffic/client_detail.html",
        context={"request":request,"page_title":f"Client {client_ip}","detail":detail,"range_key":range_key}
    )


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
