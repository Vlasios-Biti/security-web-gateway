from fastapi import APIRouter, Query
from app.services.traffic import dashboard_payload
from app.services.system import disk_usage, memory_usage, service_status, dns_health
from app.config import SERVICE_NAME

router = APIRouter(prefix="/api")


@router.get("/dashboard/traffic")
def dashboard_traffic(minutes: int = Query(60, ge=15, le=1440)):
    return dashboard_payload(minutes)


@router.get("/dashboard/health")
def dashboard_health():
    return {
        "squid": service_status("squid"),
        "nginx": service_status("nginx"),
        "proxy_manager": service_status(SERVICE_NAME),
        "disk": disk_usage(),
        "memory": memory_usage(),
        "dns": dns_health(),
    }
