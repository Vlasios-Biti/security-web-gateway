"""Import hostname-only evidence from the optional selected-tab recorder."""
import hashlib
import io
import ipaddress
import json
import zipfile
from app.config import APP_ROOT
from app.db import connect
from app.security import normalize_domain
from app.services.discovery import _classify_endpoint, _persist_candidates

MAX_CAPTURE_BYTES = 1024 * 1024


def parse_capture(raw, seed_domain):
    if len(raw) > MAX_CAPTURE_BYTES:
        raise ValueError('Capture exceeds 1 MiB.')
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError('Invalid capture JSON.') from exc
    if not isinstance(payload, dict) or payload.get('format')!='swg-tab-capture-v1' or payload.get('scope')!='selected-tab':
        raise ValueError('Use a capture exported by the SWG selected-tab recorder.')
    if not isinstance(payload.get('seed_host'),str):raise ValueError('Invalid capture seed domain.')
    captured_seed = normalize_domain(payload['seed_host'], allow_wildcard=False)
    seed = normalize_domain(seed_domain, allow_wildcard=False)
    if captured_seed != seed and not captured_seed.endswith('.'+seed):
        raise ValueError('This capture started on another domain. Select the matching application or start capture on its website.')
    rows = payload.get('destinations')
    if not isinstance(rows, list) or not rows or len(rows)>500:
        raise ValueError('Capture must contain 1–500 destination records.')
    items = {}
    for row in rows:
        if not isinstance(row,dict):raise ValueError('Invalid destination record.')
        if not isinstance(row.get('host'),str):raise ValueError('Invalid destination hostname.')
        host = normalize_domain(row['host'], allow_wildcard=False)
        try: ipaddress.ip_address(host)
        except ValueError: pass
        else: raise ValueError('IP-literal destinations are not supported by the tab recorder.')
        protocol = row.get('protocol')
        if protocol not in ('HTTP','HTTPS'):
            raise ValueError('Only HTTP/HTTPS on ports 80/443 are supported.')
        count = row.get('request_count',1)
        if type(count) is not int or not 1<=count<=100000:
            raise ValueError('Invalid request count.')
        resource_types = row.get('resource_types',[])
        if not isinstance(resource_types,list) or len(resource_types)>20 or any(not isinstance(t,str) or len(t)>40 for t in resource_types):
            raise ValueError('Invalid resource types.')
        allowed_types={'main_frame','sub_frame','stylesheet','script','image','font','object','xmlhttprequest','xhr','fetch','ping','csp_report','media','websocket','webtransport','other'}
        if set(resource_types)-allowed_types:raise ValueError('Unsupported resource type.')
        classification,recommendation = _classify_endpoint(host,resource_types,seed)
        # Store only normalized evidence. Uploaded extra fields (headers, URLs,
        # cookies, payloads, passwords) are never copied into the database.
        key = (host,protocol)
        if key in items:
            items[key]['request_count'] = min(100000,items[key]['request_count']+count)
            continue
        items[key] = {'endpoint_type':'domain','destination':host,'protocol':protocol,'required':host==seed,
            'selected':recommendation!='ignore','source':'browser-selected-tab','confidence':'high',
            'classification':classification,'recommendation':recommendation,'request_count':count,
            'first_seen_context':'Selected browser tab','metadata':{'scope':'selected-tab','seed_host':captured_seed,'resource_types':resource_types}}
    return list(items.values())


def create_capture_run(application_id,raw,actor,baseline_dirty=False):
    c = connect()
    try:
        app = c.execute("SELECT seed_domain FROM applications WHERE id=? AND status!='deleted'", (application_id,)).fetchone()
        if not app or not app['seed_domain']:
            raise ValueError('Set the application seed domain before importing its capture.')
        items = parse_capture(raw,app['seed_domain'])
        c.execute('BEGIN IMMEDIATE')
        # Reuse the passive workflow-import schema; evidence source distinguishes
        # selected-tab exports from HAR. Import never applies production policy.
        cur = c.execute("INSERT INTO discovery_runs(application_id,query,method,status,source_ref,source_version,started_by,completed_at,auto_apply,baseline_dirty) VALUES(?,?,'har_import','ready','browser-selected-tab',?,?,CURRENT_TIMESTAMP,0,?)", (application_id,app['seed_domain'],hashlib.sha256(raw).hexdigest()[:16],actor,int(baseline_dirty)))
        run_id = cur.lastrowid
        _persist_candidates(c,run_id,items)
        c.commit()
        return run_id
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def extension_package():
    root = APP_ROOT/'tools/browser/swg-tab-capture'
    out = io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.iterdir()):
            if path.is_file():archive.writestr(path.name,path.read_bytes())
    return out.getvalue()
