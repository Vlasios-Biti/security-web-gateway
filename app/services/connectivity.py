import io
import json
import re
import zipfile
from pathlib import Path
from app.config import APP_ROOT, MODE, PROXY_IP, PROXY_PORT
from app.db import connect
from app.services.pac_policy import validate_policy, render_pac

POLICY_KEY = "connection_policy"
PAC_FILE = Path("/etc/security-web-gateway/proxy.pac")


def connection_policy():
    c = connect()
    try:
        row = c.execute("SELECT value FROM settings WHERE key=?", (POLICY_KEY,)).fetchone()
    finally:
        c.close()
    if row:
        return validate_policy(json.loads(row["value"]))
    # Import existing static defaults on upgrade; do not discard business bypasses.
    text = PAC_FILE.read_text(encoding="utf-8") if PAC_FILE.is_file() else ""
    bypass = re.findall(r'"(\d+\.\d+\.\d+\.\d+)"\s*:\s*true', text)
    suffix = re.search(r'var internalSuffix = "([^"]+)"', text)
    if suffix:
        bypass.append("*." + suffix.group(1).lstrip("."))
    return validate_policy({"fail_open": "; DIRECT" in text if text else True, "internal_direct": True, "bypass": bypass})


def save_connection_policy(policy, actor, source_ip=None):
    policy = validate_policy(policy)
    # Serialize changes across workers, retaining the old DB state if publishing fails.
    c = connect()
    try:
        c.execute("BEGIN IMMEDIATE")
        if MODE == "production":
            from app.services.deployment import helper_request
            result = helper_request("publish_pac", policy=policy)
            if not result.get("ok"):
                raise ValueError(result.get("message") or "PAC publishing failed.")
        c.execute("INSERT INTO settings(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP", (POLICY_KEY, json.dumps(policy)))
        c.execute("INSERT INTO audit_events(actor,action,object_type,source_ip,result,details_json) VALUES(?,'CONNECTION_POLICY','settings',?,?,?)", (actor, source_ip, "SUCCESS" if MODE == "production" else "CANDIDATE_ONLY", json.dumps(policy)))
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()
    return policy


def windows_package():
    pac_url = f"http://{PROXY_IP}:8081/proxy.pac"
    out = io.BytesIO()
    source = APP_ROOT / "tools/windows/Proxy-Control-v1.3.1"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in source.rglob("*"):
            if path.is_file() and not any(x in path.relative_to(source).parts for x in ("dist", "build", "__pycache__")):
                archive.writestr(path.relative_to(source).as_posix(), path.read_bytes())
        archive.writestr("Install-Managed-Proxy.ps1", f'''#requires -version 5.1
#requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
& "$PSScriptRoot\\payload\\Proxy-Control-Endpoint.ps1" -Mode Install -PacUrl "{pac_url}"
if ($LASTEXITCODE -ne 0) {{ throw "Proxy installation failed." }}
''')
        archive.writestr("Build-For-This-Gateway.ps1", f'& "$PSScriptRoot\\Build-Proxy-Control-Setup.ps1" -PacUrl "{pac_url}"\r\n')
        archive.writestr('GPO-DEPLOYMENT.txt', '''Deploy the entire extracted package through your managed GPO startup or Intune install process.
Run Install-Managed-Proxy.ps1 with administrator/SYSTEM rights using your approved script signing policy.
Test on one computer before rollout. Do not run a script directly from an untrusted writable share.
The package controls Windows system proxy settings; applications with independent stacks need their own settings.
Microsoft Edge ProxySettings JSON can be downloaded from Connection in the gateway GUI.
For fail-open operation, the router must allow direct egress and DNS must remain available without this gateway.
''')
        archive.writestr("START-HERE.txt", f'''SECURITY WEB GATEWAY - WINDOWS SETUP
PAC: {pac_url}

1. Extract the entire ZIP on the Windows PC.
2. Open Windows PowerShell as Administrator in that folder.
3. Run: .\\Install-Managed-Proxy.ps1
   If execution policy blocks the script, use your organisation's approved signing/deployment process.
4. Check: .\\payload\\Proxy-Control-Endpoint.ps1 -Mode Status

To create the optional GUI installer on Windows:
  .\\Build-For-This-Gateway.ps1
Then deploy the generated dist\\Proxy-Control-Setup-v1.3.1.exe.

Connection policy is managed centrally in Connection. PAC changes are picked up
when clients refresh their PAC; open connections may need to be reopened.
DIRECT uses the PC's existing routing table and configured DNS. It does not change
the router or DNS. PAC-aware applications honour these settings; applications with
their own network stacks need separate management. Proxy unavailability fallback
depends on client timeout behaviour. An HTTP 403 policy denial is not an outage.
Administrator privileges are required to disable or uninstall. Uninstall restores
the original settings backed up at first installation.
''')
    return out.getvalue()
