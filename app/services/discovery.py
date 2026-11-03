import csv,hashlib,http.client,ipaddress,io,json,os,re,socket,ssl,time,uuid
from datetime import datetime,timedelta
from html import unescape
from urllib.parse import urlparse,urljoin
from app.config import SQUID_ACCESS_LOG, DISCOVERY_BROWSER_TIMEOUT_MS, DISCOVERY_BROWSER_MAX_PAGES, DISCOVERY_MAX_HAR_BYTES
from app.db import connect
from app.security import normalize_domain,normalize_ip

MAX_FETCH=2*1024*1024
UA="Security-Web-Gateway-Discovery/3.1"
HOST_RE=re.compile(r"(?i)(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
IPCIDR_RE=re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![/0-9])")
URL_RE=re.compile(r"(?i)https?://[^\s\"'<>]+")

CATALOG=[
 {"key":"microsoft-teams","name":"Microsoft Teams","provider":"Microsoft","method":"official_api","source_kind":"official_api","source_ref":"microsoft-teams","seed_domain":"teams.microsoft.com","description":"Microsoft Teams endpoints from the Microsoft 365 official IP/URL Web Service.","official":True,"auto_monitor":True},
 {"key":"microsoft-365","name":"Microsoft 365","provider":"Microsoft","method":"official_api","source_kind":"official_api","source_ref":"microsoft-365","seed_domain":"microsoft365.com","description":"Microsoft 365 endpoints from the Microsoft official IP/URL Web Service.","official":True,"auto_monitor":True},
 {"key":"zoom-workplace","name":"Zoom Workplace","provider":"Zoom","method":"official_url","source_kind":"official_url","source_ref":"https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0060548","seed_domain":"zoom.us","description":"Review endpoint candidates extracted from Zoom's official network firewall/proxy guidance.","official":True,"auto_monitor":False},
 {"key":"slack","name":"Slack","provider":"Slack","method":"official_url","source_kind":"official_url","source_ref":"https://slack.com/help/articles/360001603387-Manage-Slack-connection-issues","seed_domain":"slack.com","description":"Review endpoint candidates extracted from Slack's official connection and allowlist guidance.","official":True,"auto_monitor":False},
 {"key":"github","name":"GitHub","provider":"GitHub","method":"official_url","source_kind":"official_url","source_ref":"https://docs.github.com/en/get-started/using-github/allowing-access-to-githubs-services-from-a-restricted-network","seed_domain":"github.com","description":"Review endpoint candidates extracted from GitHub's official restricted-network guidance.","official":True,"auto_monitor":False},
 {"key":"github-copilot","name":"GitHub Copilot","provider":"GitHub","method":"official_url","source_kind":"official_url","source_ref":"https://docs.github.com/en/copilot/reference/copilot-allowlist-reference","seed_domain":"github.com","description":"Review endpoint candidates extracted from GitHub's official Copilot allowlist reference.","official":True,"auto_monitor":False},
]

def catalog_search(query=""):
    q=query.strip().lower()
    return [x for x in CATALOG if not q or q in x["name"].lower() or q in x["provider"].lower() or q in x["key"]]


def _public_addresses(host,port):
    try:
        rows=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Discovery source DNS resolution failed.") from exc
    out=[]
    for row in rows:
        value=row[4][0]
        try:ip=ipaddress.ip_address(value)
        except ValueError:continue
        if not ip.is_global:
            raise ValueError("Discovery source resolved to a private/reserved address; request blocked by SSRF protection.")
        if value not in out:out.append(value)
    if not out:raise ValueError("Discovery source has no public IP address.")
    return out


def _assert_public_https(url):
    p=urlparse(url)
    if p.scheme!="https" or not p.hostname or p.username or p.password:
        raise ValueError("Discovery source must be a public HTTPS URL without embedded credentials.")
    if p.port not in (None,443):
        raise ValueError("Discovery source must use standard HTTPS port 443.")
    _public_addresses(p.hostname,443)
    return url


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to an already-vetted public IP.

    The TLS SNI/certificate hostname remains the original hostname. Pinning the
    TCP destination prevents a DNS-rebinding change between validation and the
    actual outbound request.
    """
    def __init__(self,host,pinned_ip,timeout=12):
        super().__init__(host,443,timeout=timeout,context=ssl.create_default_context())
        self._pinned_ip=pinned_ip
    def connect(self):
        sock=socket.create_connection((self._pinned_ip,443),self.timeout,self.source_address)
        self.sock=self._context.wrap_socket(sock,server_hostname=self.host)


def _fetch_once(url):
    p=urlparse(url);addresses=_public_addresses(p.hostname,443)
    path=p.path or "/"
    if p.query:path+="?"+p.query
    last=None
    for addr in addresses:
        conn=None
        try:
            conn=_PinnedHTTPSConnection(p.hostname,addr,timeout=12)
            conn.request("GET",path,headers={"Host":p.hostname,"User-Agent":UA,"Accept":"application/json,text/plain,text/html;q=0.8,*/*;q=0.2","Connection":"close"})
            resp=conn.getresponse()
            if resp.status in (301,302,303,307,308):
                location=resp.getheader("Location")
                resp.read(min(MAX_FETCH,65536));conn.close()
                if not location:raise ValueError("Discovery source redirect omitted Location header.")
                return None,None,urljoin(url,location),True
            if resp.status<200 or resp.status>=300:
                body=resp.read(min(MAX_FETCH,65536));raise ValueError(f"Discovery source returned HTTP {resp.status}.")
            data=resp.read(MAX_FETCH+1)
            if len(data)>MAX_FETCH:raise ValueError("Discovery response exceeds 2 MiB safety limit.")
            ctype=(resp.getheader("Content-Type") or "").lower();final=url
            conn.close();return data,ctype,final,False
        except (OSError,ssl.SSLError,http.client.HTTPException) as exc:
            last=exc
            if conn:
                try:conn.close()
                except Exception:pass
    raise ValueError("Discovery source connection failed.") from last


def safe_fetch(url):
    current=_assert_public_https(url)
    for _ in range(6):
        data,ctype,target,redirect=_fetch_once(current)
        if not redirect:return data,ctype,target
        current=_assert_public_https(target)
    raise ValueError("Discovery source exceeded the redirect limit.")


def _protocol_from_ports(tcp_ports):
    s=str(tcp_ports or "")
    has80=bool(re.search(r"(^|[,\s])80($|[,\s])",s));has443=bool(re.search(r"(^|[,\s])443($|[,\s])",s))
    if has80 and has443:return "BOTH"
    if has80:return "HTTP"
    return "HTTPS"


def _clean_host(value):
    value=value.strip().lower().rstrip(".,;:)]}")
    # URLs in official endpoint feeds can include paths.
    if "://" in value:
        value=urlparse(value).hostname or ""
    else:
        value=value.split("/",1)[0].split(":",1)[0]
    if value.startswith("."):value="*"+value
    try:return normalize_domain(value,allow_wildcard=True)
    except Exception:return None


def _dedupe(items):
    out={}
    rank={"low":1,"medium":2,"high":3}
    for x in items:
        k=(x["endpoint_type"],x["destination"],x["protocol"])
        old=out.get(k)
        if not old or rank.get(x.get("confidence","medium"),2)>rank.get(old.get("confidence","medium"),2):out[k]=x
    return list(out.values())


def discover_microsoft(catalog_key):
    if catalog_key not in("microsoft-teams","microsoft-365"):raise ValueError("Unsupported Microsoft catalog entry.")
    rid=str(uuid.uuid4())
    version_url=f"https://endpoints.office.com/version/worldwide?clientrequestid={rid}"
    endpoint_url=f"https://endpoints.office.com/endpoints/worldwide?clientrequestid={rid}"
    version=None
    try:
        raw,_,_=safe_fetch(version_url);v=json.loads(raw.decode("utf-8"));version=v.get("latest") if isinstance(v,dict) else str(v)
    except Exception:version=None
    raw,_,final=safe_fetch(endpoint_url);payload=json.loads(raw.decode("utf-8"));items=[]
    areas={"Skype","Common"} if catalog_key=="microsoft-teams" else None
    for row in payload:
        if areas and row.get("serviceArea") not in areas:continue
        required=bool(row.get("required",True));proto=_protocol_from_ports(row.get("tcpPorts"));meta={k:row.get(k) for k in("id","serviceArea","serviceAreaDisplayName","category","tcpPorts","udpPorts","expressRoute") if row.get(k) is not None}
        for u in row.get("urls") or []:
            host=_clean_host(u)
            if host:items.append({"endpoint_type":"domain","destination":host,"protocol":proto,"required":required,"source":"microsoft-official","confidence":"high","metadata":meta})
        # Only IP ranges that are relevant to web proxy ports are candidates. UDP-only media ranges are preserved in metadata but not widened into Squid ACLs.
        ports=str(row.get("tcpPorts") or "")
        if "80" in ports or "443" in ports:
            for ip in row.get("ips") or []:
                try:dest=normalize_ip(ip)
                except Exception:continue
                items.append({"endpoint_type":"ip","destination":dest,"protocol":proto,"required":required,"source":"microsoft-official","confidence":"high","metadata":meta})
    return _dedupe(items),version,final


def _extract_strings(obj):
    if isinstance(obj,str):yield obj
    elif isinstance(obj,dict):
        for v in obj.values():yield from _extract_strings(v)
    elif isinstance(obj,(list,tuple)):
        for v in obj:yield from _extract_strings(v)


def discover_official_url(url):
    raw,ctype,final=safe_fetch(url);text=raw.decode("utf-8",errors="replace");strings=[]
    structured=False
    if "json" in ctype or text.lstrip().startswith(("{","[")):
        try:strings=list(_extract_strings(json.loads(text)));structured=True
        except Exception:strings=[text]
    elif "csv" in ctype:
        strings=[cell for row in csv.reader(io.StringIO(text)) for cell in row];structured=True
    else:
        strings=[text]
    source_host=(urlparse(final).hostname or "").lower()
    dconf="high" if structured else "medium"
    ipconf="medium" if structured else "low"
    items=[]
    for value in strings:
        for u in URL_RE.findall(value):
            h=_clean_host(u)
            if h and h!=source_host:items.append({"endpoint_type":"domain","destination":h,"protocol":"HTTPS","required":True,"source":"official-feed" if structured else "official-doc","confidence":dconf,"metadata":{"source_url":final}})
        for h0 in HOST_RE.findall(value):
            h=_clean_host(h0)
            if h and h!=source_host:items.append({"endpoint_type":"domain","destination":h,"protocol":"HTTPS","required":True,"source":"official-feed" if structured else "official-doc","confidence":dconf,"metadata":{"source_url":final}})
        for ip0 in IPCIDR_RE.findall(value):
            try:dest=normalize_ip(ip0)
            except Exception:continue
            items.append({"endpoint_type":"ip","destination":dest,"protocol":"HTTPS","required":True,"source":"official-feed" if structured else "official-doc","confidence":ipconf,"metadata":{"source_url":final}})
    return _dedupe(items),hashlib.sha256(raw).hexdigest()[:16],final


def _parse_squid_line(raw):
    p=raw.split(None,9)
    if len(p)<7:return None
    try:epoch=float(p[0])
    except Exception:return None
    return {"epoch":epoch,"client":p[2],"result":p[3],"method":p[5],"destination":p[6]}


def _dest_from_squid(value):
    val=value.strip()
    if "://" in val:
        p=urlparse(val);host=p.hostname;port=p.port or (443 if p.scheme=="https" else 80)
    else:
        host=val;port=443
        if val.count(":")==1:
            h,p0=val.rsplit(":",1)
            if p0.isdigit():host=h;port=int(p0)
    if not host:return None
    try:return {"endpoint_type":"ip","destination":normalize_ip(host),"protocol":"HTTPS" if port==443 else "HTTP"}
    except Exception:pass
    try:return {"endpoint_type":"domain","destination":normalize_domain(host),"protocol":"HTTPS" if port==443 else "HTTP"}
    except Exception:return None


def discover_observed(client_ip,window_minutes=10):
    try:ipaddress.ip_address(client_ip)
    except Exception as exc:raise ValueError("A valid test client IP is required for observed discovery.") from exc
    minutes=max(1,min(int(window_minutes),120));cutoff=time.time()-minutes*60;seen={}
    try:
        with open(SQUID_ACCESS_LOG,"r",encoding="utf-8",errors="replace") as f:
            from collections import deque
            lines=deque(f,maxlen=150000)
    except Exception as exc:raise ValueError("Squid access log is not readable by the management service.") from exc
    for raw in lines:
        x=_parse_squid_line(raw)
        if not x or x["epoch"]<cutoff or x["client"]!=client_ip:continue
        d=_dest_from_squid(x["destination"])
        if not d:continue
        k=(d["endpoint_type"],d["destination"],d["protocol"]);z=seen.setdefault(k,{**d,"required":True,"source":"squid-observed","confidence":"medium","metadata":{"hits":0,"allowed":0,"denied":0}});z["metadata"]["hits"]+=1
        if "DENIED" in x["result"]:z["metadata"]["denied"]+=1
        else:z["metadata"]["allowed"]+=1
    for z in seen.values():z["confidence"]="high" if z["metadata"]["hits"]>=2 else "medium"
    return list(seen.values()),None,f"squid:{client_ip}:{minutes}m"


def discover_seed(seed_domain):
    seed=normalize_domain(seed_domain,allow_wildcard=False);url="https://"+seed+"/";raw,ctype,final=safe_fetch(url);text=unescape(raw.decode("utf-8",errors="replace"));items=[{"endpoint_type":"domain","destination":seed,"protocol":"HTTPS","required":True,"source":"seed","confidence":"high","metadata":{"source_url":final}}]
    for u in URL_RE.findall(text):
        h=_clean_host(u)
        if h:items.append({"endpoint_type":"domain","destination":h,"protocol":"HTTPS","required":False,"source":"seed-page","confidence":"low","metadata":{"source_url":final}})
    return _dedupe(items),hashlib.sha256(raw).hexdigest()[:16],final


_NOISE_TOKENS=(
    "doubleclick.","googletagmanager.","google-analytics.","analytics.","amplitude.","segment.",
    "hotjar.","clarity.","adsrvr.","linkedin.com","facebook.com","connect.facebook.net","tiktok.com",
    "browser.events.data.microsoft.com","events.data.microsoft.com","activity.windows.com","grammarly.com",
)

def _classify_endpoint(host,resource_types=None,seed_host=None):
    h=(host or "").lower();types={str(x).lower() for x in (resource_types or [])}
    if seed_host and (h==seed_host or h.endswith("."+seed_host)):
        return "first_party","allow"
    if any(t in h for t in _NOISE_TOKENS):
        return "analytics_or_background","ignore"
    if any(x in h for x in ("auth.","login.","identity.","oauth.","sso.")):
        return "authentication","allow"
    if "websocket" in types or any(x in h for x in ("signalr","realtime","socket")):
        return "realtime","allow"
    if types.intersection({"xhr","fetch"}) or any(x in h for x in ("api.","-api.",".api.")):
        return "api","allow"
    if any(x in h for x in ("cdn.","static.","assets.","akamai","cloudfront")):
        return "cdn","review"
    if any(x in h for x in ("blob.core.windows.net","storage.","s3.amazonaws.com")):
        return "storage","review"
    return "third_party","review"


def _public_request_host(url):
    p=urlparse(url)
    if p.scheme not in ("http","https","ws","wss") or not p.hostname:
        return None
    host=p.hostname.lower().rstrip(".")
    # HAR analysis is passive: it does not connect to the destination, therefore
    # DNS resolution is unnecessary and would make offline analysis unreliable.
    # Literal private/reserved IPs are still excluded from public-app evidence.
    try:
        ip=ipaddress.ip_address(host)
        if not ip.is_global:return None
    except ValueError:
        pass
    return host


def discover_browser(target_url,max_pages=None):
    target=(target_url or "").strip()
    if not target:
        raise ValueError("Application URL is required for browser discovery.")
    if "://" not in target:
        target="https://"+target
    _assert_public_https(target)
    seed_host=urlparse(target).hostname.lower().rstrip(".")
    max_pages=max(1,min(int(max_pages or DISCOVERY_BROWSER_MAX_PAGES),12))
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise ValueError("Playwright runtime is not installed. Run deploy/install_playwright.sh on the server.") from exc

    observed={}
    dns_cache={}
    blocked=[]

    def vet(url):
        try:
            p=urlparse(url)
            if p.scheme not in ("http","https","ws","wss") or not p.hostname:
                return None
            key=(p.hostname,p.port or (443 if p.scheme in ("https","wss") else 80))
            if key not in dns_cache:
                try:_public_addresses(*key);dns_cache[key]=True
                except Exception:dns_cache[key]=False
            if not dns_cache[key]:
                blocked.append(p.hostname);return None
            return p.hostname.lower().rstrip(".")
        except Exception:
            return None

    def capture(req,context_name):
        host=vet(req.url)
        if not host:return
        key=("domain",host,"HTTPS" if urlparse(req.url).scheme in ("https","wss") else "HTTP")
        row=observed.setdefault(key,{"endpoint_type":"domain","destination":host,"protocol":key[2],"required":False,
            "source":"browser-runtime","confidence":"medium","metadata":{"hits":0,"resource_types":[],"methods":[],"sample_urls":[],"contexts":[]}})
        m=row["metadata"];m["hits"]+=1
        rt=str(getattr(req,"resource_type","") or "").lower();method=str(getattr(req,"method","") or "GET").upper()
        if rt and rt not in m["resource_types"]:m["resource_types"].append(rt)
        if method and method not in m["methods"]:m["methods"].append(method)
        if len(m["sample_urls"])<3:
            u=req.url.split("?",1)[0][:512]
            if u not in m["sample_urls"]:m["sample_urls"].append(u)
        if context_name not in m["contexts"]:m["contexts"].append(context_name)

    with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,args=["--disable-dev-shm-usage"])
        context=browser.new_context(ignore_https_errors=False,service_workers="allow")
        current_context={"name":"initial-page"}
        def route_handler(route,request):
            if request.url.startswith(("data:","about:","blob:")):
                route.continue_();return
            if vet(request.url):
                capture(request,current_context["name"]);route.continue_()
            else:
                route.abort()
        context.route("**/*",route_handler)
        page=context.new_page()
        page.goto(target,wait_until="domcontentloaded",timeout=DISCOVERY_BROWSER_TIMEOUT_MS)
        try: page.wait_for_load_state("networkidle",timeout=min(DISCOVERY_BROWSER_TIMEOUT_MS,10000))
        except Exception: pass
        page.wait_for_timeout(1500)
        try:
            links=page.eval_on_selector_all("a[href]","els => els.map(a => a.href)")
        except Exception:
            links=[]
        candidates=[]
        bad_words=("logout","signout","delete","remove","unsubscribe","destroy")
        for u in links:
            try:
                pp=urlparse(u)
                if pp.scheme!="https" or pp.hostname!=seed_host:continue
                if any(x in (pp.path or "").lower() for x in bad_words):continue
                clean=pp._replace(fragment="").geturl()
                if clean not in candidates:candidates.append(clean)
            except Exception:pass
            if len(candidates)>=max_pages-1:break
        for idx,u in enumerate(candidates,1):
            current_context["name"]=f"same-origin-page-{idx}"
            try:
                page.goto(u,wait_until="domcontentloaded",timeout=DISCOVERY_BROWSER_TIMEOUT_MS)
                page.wait_for_timeout(800)
            except Exception:
                continue
        browser.close()

    items=[]
    for row in observed.values():
        cls,rec=_classify_endpoint(row["destination"],row["metadata"].get("resource_types"),seed_host)
        hits=int(row["metadata"].get("hits",0))
        row["classification"]=cls;row["recommendation"]=rec;row["request_count"]=hits
        row["first_seen_context"]=(row["metadata"].get("contexts") or [None])[0]
        row["required"] = row["destination"]==seed_host or cls in ("authentication","api","realtime")
        row["selected"] = rec=="allow" or row["required"]
        row["confidence"] = "high" if row["required"] or hits>=2 else "medium"
        items.append(row)
    if seed_host not in {x["destination"] for x in items}:
        items.append({"endpoint_type":"domain","destination":seed_host,"protocol":"HTTPS","required":True,"selected":True,
            "source":"browser-runtime","confidence":"high","classification":"first_party","recommendation":"allow","request_count":1,
            "first_seen_context":"initial-page","metadata":{"hits":1,"blocked_private_hosts":sorted(set(blocked))[:20]}})
    version=hashlib.sha256(json.dumps(sorted((x["destination"],x["protocol"],x.get("request_count",0)) for x in items)).encode()).hexdigest()[:16]
    return _dedupe(items),version,target


def discover_har(raw_bytes,seed_domain=None):
    if len(raw_bytes)>DISCOVERY_MAX_HAR_BYTES:
        raise ValueError("HAR upload exceeds the configured 10 MiB safety limit.")
    try:payload=json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:raise ValueError("Invalid HAR JSON file.") from exc
    entries=((payload.get("log") or {}).get("entries") or []) if isinstance(payload,dict) else []
    if not isinstance(entries,list):raise ValueError("HAR file does not contain log.entries.")
    seed=normalize_domain(seed_domain,allow_wildcard=False) if seed_domain else None
    seen={}
    for entry in entries[:200000]:
        req=(entry or {}).get("request") or {};url=req.get("url") or ""
        try:host=_public_request_host(url)
        except Exception:continue
        if not host:continue
        scheme=urlparse(url).scheme.lower();proto="HTTPS" if scheme in ("https","wss") else "HTTP"
        key=("domain",host,proto)
        z=seen.setdefault(key,{"endpoint_type":"domain","destination":host,"protocol":proto,"required":False,"source":"har-session",
            "confidence":"medium","selected":False,"metadata":{"hits":0,"methods":[],"sample_urls":[]}})
        z["metadata"]["hits"]+=1
        method=str(req.get("method") or "GET").upper()
        if method not in z["metadata"]["methods"]:z["metadata"]["methods"].append(method)
        if len(z["metadata"]["sample_urls"])<3:
            clean=url.split("?",1)[0][:512]
            if clean not in z["metadata"]["sample_urls"]:z["metadata"]["sample_urls"].append(clean)
    items=[]
    for z in seen.values():
        cls,rec=_classify_endpoint(z["destination"],None,seed)
        hits=z["metadata"]["hits"];z.update({"classification":cls,"recommendation":rec,"request_count":hits,"first_seen_context":"HAR workflow"})
        z["required"] = (seed and z["destination"]==seed) or cls in ("authentication","api","realtime")
        z["selected"] = rec=="allow" or z["required"]
        z["confidence"] = "high" if z["required"] or hits>=2 else "medium";items.append(z)
    version=hashlib.sha256(raw_bytes).hexdigest()[:16]
    return _dedupe(items),version,"har-upload"


def _persist_candidates(c,run_id,items):
    for x in items:
        present=c.execute("SELECT id FROM rules WHERE rule_type=? AND destination=? AND status!='deleted'",(x["endpoint_type"],x["destination"])).fetchone()
        selected=1 if x.get("selected",x.get("required",True)) else 0
        c.execute("""INSERT OR IGNORE INTO discovery_candidates(
          run_id,endpoint_type,destination,protocol,required,source,confidence,selected,already_present,metadata_json,
          classification,recommendation,request_count,first_seen_context)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (run_id,x["endpoint_type"],x["destination"],x["protocol"],1 if x.get("required",True) else 0,x.get("source","discovery"),
           x.get("confidence","medium"),selected,1 if present else 0,json.dumps(x.get("metadata") or {},separators=(",",":")),
           x.get("classification","unknown"),x.get("recommendation","review"),int(x.get("request_count",0)),x.get("first_seen_context")))


def _execute_run(c,run_id,application_id,query,method,source_ref,client_ip,window_minutes,catalog_key=None):
    if method in("catalog","official_api"):
        items,version,actual=discover_microsoft(catalog_key or source_ref or query)
    elif method=="official_url":items,version,actual=discover_official_url(source_ref)
    elif method=="observed":items,version,actual=discover_observed(client_ip,window_minutes or 10)
    elif method=="seed_probe":items,version,actual=discover_seed(query)
    elif method=="browser_auto":items,version,actual=discover_browser(source_ref or query)
    else:raise ValueError("Unsupported discovery method.")
    c.execute("BEGIN IMMEDIATE");_persist_candidates(c,run_id,items)
    c.execute("UPDATE discovery_runs SET status='ready',source_ref=?,source_version=?,completed_at=CURRENT_TIMESTAMP,error_text=NULL WHERE id=?",(actual,version,run_id))
    if application_id:c.execute("UPDATE applications SET last_discovery_at=CURRENT_TIMESTAMP,last_source_version=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(version,application_id))
    c.commit()


def create_run(application_id,query,method,actor,source_ref=None,client_ip=None,window_minutes=None,catalog_key=None):
    c=connect();run_id=None
    try:
        cur=c.execute("""INSERT INTO discovery_runs(application_id,query,method,status,source_ref,client_ip,window_minutes,started_by)
          VALUES(?,?,?,'running',?,?,?,?)""",(application_id,query or None,method,source_ref or None,client_ip or None,window_minutes,actor));run_id=cur.lastrowid;c.commit()
        # Browser execution is deliberately deferred to the systemd worker so a
        # Chromium session can never hold an Nginx/GUI request open long enough
        # to produce a 504. The review page can be refreshed while status=running.
        if method=="browser_auto":
            return run_id
        _execute_run(c,run_id,application_id,query,method,source_ref,client_ip,window_minutes,catalog_key)
        return run_id
    except Exception as exc:
        if run_id:
            try:c.execute("UPDATE discovery_runs SET status='failed',error_text=?,completed_at=CURRENT_TIMESTAMP WHERE id=?",(str(exc),run_id));c.commit()
            except Exception:pass
        raise
    finally:c.close()


def process_browser_queue(max_runs=1):
    processed=[]
    for _ in range(max(1,min(int(max_runs),10))):
        c=connect()
        try:
            run=c.execute("""SELECT * FROM discovery_runs
              WHERE method='browser_auto' AND status='running' AND completed_at IS NULL
              ORDER BY id ASC LIMIT 1""").fetchone()
            if not run:break
            run=dict(run)
        finally:c.close()
        c=connect()
        try:
            _execute_run(c,run['id'],run.get('application_id'),run.get('query'),run['method'],run.get('source_ref'),run.get('client_ip'),run.get('window_minutes'))
            processed.append({'id':run['id'],'status':'ready'})
        except Exception as exc:
            try:
                c.rollback();c.execute("UPDATE discovery_runs SET status='failed',error_text=?,completed_at=CURRENT_TIMESTAMP WHERE id=?",(str(exc),run['id']));c.commit()
            except Exception:pass
            processed.append({'id':run['id'],'status':'failed','error':str(exc)})
        finally:c.close()
    return processed


def create_har_run(application_id,seed_domain,raw_bytes,actor):
    c=connect();run_id=None
    try:
        cur=c.execute("""INSERT INTO discovery_runs(application_id,query,method,status,source_ref,started_by)
          VALUES(?,?,'har_import','running','har-upload',?)""",(application_id,seed_domain or None,actor));run_id=cur.lastrowid;c.commit()
        items,version,actual=discover_har(raw_bytes,seed_domain)
        c.execute("BEGIN IMMEDIATE");_persist_candidates(c,run_id,items)
        c.execute("UPDATE discovery_runs SET status='ready',source_ref=?,source_version=?,completed_at=CURRENT_TIMESTAMP WHERE id=?",(actual,version,run_id))
        if application_id:c.execute("UPDATE applications SET last_discovery_at=CURRENT_TIMESTAMP,last_source_version=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(version,application_id))
        c.commit();return run_id
    except Exception as exc:
        if run_id:
            try:c.execute("UPDATE discovery_runs SET status='failed',error_text=?,completed_at=CURRENT_TIMESTAMP WHERE id=?",(str(exc),run_id));c.commit()
            except Exception:pass
        raise
    finally:c.close()


def get_run(run_id):
    c=connect()
    try:
        r=c.execute("""SELECT dr.*,a.name application_name FROM discovery_runs dr LEFT JOIN applications a ON a.id=dr.application_id WHERE dr.id=?""",(run_id,)).fetchone()
        if not r:return None
        d=dict(r);d["candidates"]=[dict(x) for x in c.execute("SELECT * FROM discovery_candidates WHERE run_id=? ORDER BY required DESC,confidence DESC,endpoint_type,destination",(run_id,))];return d
    finally:c.close()


def list_runs(limit=50):
    c=connect()
    try:return [dict(x) for x in c.execute("""SELECT dr.*,a.name application_name,(SELECT COUNT(*) FROM discovery_candidates dc WHERE dc.run_id=dr.id) candidate_count FROM discovery_runs dr LEFT JOIN applications a ON a.id=dr.application_id ORDER BY dr.id DESC LIMIT ?""",(limit,))]
    finally:c.close()


def _category_for_app(c,app):
    slug="app-"+app["slug"];c.execute("INSERT OR IGNORE INTO categories(name,slug,system_managed) VALUES(?,?,?)",(app["name"],slug,app["system_managed"]));return c.execute("SELECT id FROM categories WHERE slug=?",(slug,)).fetchone()["id"]


def _merge_protocol(a,b):
    if a==b:return a
    if "BOTH" in(a,b):return "BOTH"
    return "BOTH"


def approve_run(run_id,selected_ids,actor):
    c=connect()
    try:
        run=c.execute("SELECT * FROM discovery_runs WHERE id=? AND status='ready'",(run_id,)).fetchone()
        if not run:raise ValueError("Discovery run is not ready for approval.")
        if not run["application_id"]:raise ValueError("Discovery run is not attached to an application policy.")
        app=c.execute("SELECT * FROM applications WHERE id=? AND status!='deleted'",(run["application_id"],)).fetchone()
        if not app:raise ValueError("Application policy not found.")
        ids={int(x) for x in selected_ids};rows=[x for x in c.execute("SELECT * FROM discovery_candidates WHERE run_id=?",(run_id,)) if x["id"] in ids]
        if not rows:raise ValueError("Select at least one discovered endpoint.")
        created=0;linked=0;updated=0
        c.execute("BEGIN IMMEDIATE")
        cid=_category_for_app(c,app)
        for x in rows:
            existing=c.execute("SELECT * FROM rules WHERE rule_type=? AND destination=? AND status!='deleted'",(x["endpoint_type"],x["destination"])).fetchone()
            if existing:
                rid=existing["id"]
                # A destination may be shared by multiple applications/profiles.
                # Discovery approval must never widen that global rule silently.
                if existing["protocol"] != x["protocol"] and existing["protocol"] != "BOTH":
                    raise ValueError(
                        f"Protocol conflict for shared destination {x['destination']}: existing rule is {existing['protocol']}, discovered {x['protocol']}. "
                        "Review the shared destination before widening its protocol globally."
                    )
            else:
                management="system" if app["system_managed"] else "custom";fp=hashlib.sha256(f"{x['endpoint_type']}|{x['destination']}|{x['protocol']}|{management}|{cid}".encode()).hexdigest()
                cur=c.execute("""INSERT INTO rules(rule_type,action,destination,protocol,category_id,management_type,status,pending,reason,fingerprint,created_by,updated_by,scope_mode)
                  VALUES(?,'ALLOW',?,?,?,?, 'active',1,?,?,?,?,'selected')""",(x["endpoint_type"],x["destination"],x["protocol"],cid,management,f"Discovered dependency for {app['name']}",fp,actor,actor));rid=cur.lastrowid;created+=1
            c.execute("INSERT OR REPLACE INTO application_rules(application_id,rule_id,required,source,confidence,metadata_json,enabled) VALUES(?,?,?,?,?,?,1)",(app["id"],rid,x["required"],x["source"],x["confidence"],x["metadata_json"]));linked+=1
        c.execute("UPDATE applications SET pending=1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(actor,app["id"]));c.execute("UPDATE discovery_runs SET status='approved' WHERE id=?",(run_id,));c.commit();return {"created":created,"updated":updated,"linked":linked}
    except Exception:c.rollback();raise
    finally:c.close()
