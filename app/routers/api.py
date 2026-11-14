from fastapi import APIRouter, Query
from app.services.traffic import dashboard_payload
from app.services.system import cached_system_health

router = APIRouter(prefix="/api")


@router.get("/dashboard/traffic")
def dashboard_traffic(minutes: int = Query(60, ge=15, le=1440)):
    return dashboard_payload(minutes)


@router.get("/dashboard/health")
def dashboard_health():
    health=cached_system_health()
    return {
        'squid':health['squid_status'],'nginx':health['nginx_status'],
        'proxy_manager':health['app_status'],'disk':health['disk'],
        'memory':health['memory'],'dns':health['dns'],
        'cache_stale':health.get('cache_stale',True),'generated_at':health.get('generated_at'),
    }
