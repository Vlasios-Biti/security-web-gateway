from app.config import MODE
from app.services.deployment import helper_request

def validate_squid():
    if MODE != "production": return {"ok": False, "message": "Privileged validation is disabled in candidate preview mode."}
    return helper_request("validate_squid")

def reload_squid():
    if MODE != "production": return {"ok": False, "message": "Reload is disabled in candidate preview mode."}
    return helper_request("reload_squid")

def create_backup():
    if MODE != "production": return {"ok": False, "message": "Backup creation is disabled in candidate preview mode."}
    return helper_request("backup")
