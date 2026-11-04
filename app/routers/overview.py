from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.services.system import cached_system_health
from app.services.traffic import dashboard_payload, telemetry_health
from app.services.rules import pending_count
from app.services.deployment import drift_status
from app.db import connect
from app.config import PROXY_IP, PROXY_PORT
from app.services.performance import latest_performance

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def page(request: Request):
    c = connect()
    try:
        domains = c.execute("SELECT COUNT(*) c FROM rules WHERE rule_type='domain' AND status!='deleted'").fetchone()["c"]
        system_domains = c.execute("SELECT COUNT(*) c FROM rules WHERE rule_type='domain' AND management_type='system' AND status!='deleted'").fetchone()["c"]
        custom_domains = c.execute("SELECT COUNT(*) c FROM rules WHERE rule_type='domain' AND management_type='custom' AND status!='deleted'").fetchone()["c"]
        ips = c.execute("SELECT COUNT(*) c FROM rules WHERE rule_type='ip' AND status!='deleted'").fetchone()["c"]
        network_count = c.execute("SELECT COUNT(*) c FROM networks WHERE enabled=1 AND proxy_enabled=1").fetchone()["c"]
        app_count = c.execute("SELECT COUNT(*) c FROM applications WHERE status='active'").fetchone()["c"]
        profile_count = c.execute("SELECT COUNT(*) c FROM policy_groups WHERE status='active'").fetchone()["c"]
        audits = [dict(x) for x in c.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 8")]
        last_dep = c.execute("SELECT version,status,created_by,deployed_at FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
        last_backup = c.execute("SELECT timestamp,result FROM audit_events WHERE action='SYSTEM_BACKUP' ORDER BY id DESC LIMIT 1").fetchone()
        last_dep = dict(last_dep) if last_dep else None
    finally:
        c.close()

    traffic = dashboard_payload(60)
    health = cached_system_health()
    perf = latest_performance()
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="overview.html",
        context={
            "request": request,
            "page_title": "Dashboard",
            "traffic": traffic,
            "telemetry_health": telemetry_health(),
            "squid_status": health["squid_status"],
            "nginx_status": health["nginx_status"],
            "app_status": health["app_status"],
            "port_ok": health["port_ok"],
            "dns": health["dns"],
            "disk": health["disk"],
            "memory": health["memory"],
            "load": health["load"],
            "domain_count": domains,
            "system_domain_count": system_domains,
            "custom_domain_count": custom_domains,
            "ip_count": ips,
            "network_count": network_count,
            "application_count": app_count,
            "profile_count": profile_count,
            "pending_count": pending_count(),
            "drift": drift_status(),
            "audit_rows": audits,
            "last_deployment": last_dep,
            "last_backup": dict(last_backup) if last_backup else None,
            "perf": perf,
            "health_cache": health,
            "proxy_ip": PROXY_IP,
            "proxy_port": PROXY_PORT,
        },
    )
