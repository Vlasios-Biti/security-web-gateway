from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from app.services.system import service_status, disk_usage, memory_usage, load_average, port_open, dns_health
from app.services.traffic import dashboard_payload, telemetry_health
from app.services.rules import pending_count, list_networks
from app.services.deployment import drift_status
from app.db import connect
from app.config import SERVICE_NAME

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def page(request: Request):
    c = connect()
    try:
        domains = c.execute("SELECT COUNT(*) c FROM rules WHERE rule_type='domain' AND status!='deleted'").fetchone()["c"]
        system_domains = c.execute("SELECT COUNT(*) c FROM rules WHERE rule_type='domain' AND management_type='system' AND status!='deleted'").fetchone()["c"]
        custom_domains = c.execute("SELECT COUNT(*) c FROM rules WHERE rule_type='domain' AND management_type='custom' AND status!='deleted'").fetchone()["c"]
        ips = c.execute("SELECT COUNT(*) c FROM rules WHERE rule_type='ip' AND status!='deleted'").fetchone()["c"]
        audits = [dict(x) for x in c.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 7")]
        last_dep = c.execute("SELECT version,status,created_by,deployed_at FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
        last_dep = dict(last_dep) if last_dep else None
    finally:
        c.close()
    traffic = dashboard_payload(60)
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="overview.html",
        context={
            "request": request, "page_title": "Security Operations Overview", "traffic": traffic,
            "telemetry_health": telemetry_health(),
            "squid_status": service_status("squid"), "nginx_status": service_status("nginx"),
            "app_status": service_status(SERVICE_NAME), "port_ok": port_open(), "dns": dns_health(),
            "disk": disk_usage(), "memory": memory_usage(), "load": load_average(), "domain_count": domains,
            "system_domain_count": system_domains, "custom_domain_count": custom_domains, "ip_count": ips,
            "network_count": len(list_networks(False)), "pending_count": pending_count(), "drift": drift_status(),
            "audit_rows": audits, "last_deployment": last_dep,
        },
    )
