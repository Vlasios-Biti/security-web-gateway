import os
from pathlib import Path

APP_NAME = "Security Web Gateway Manager"
APP_VERSION = "3.4.0"
APP_ROOT = Path(__file__).resolve().parents[1]
MODE = os.getenv("SWG_MODE", "candidate").strip().lower()
SERVICE_NAME = os.getenv("SWG_SERVICE_NAME", "security-web-gateway-candidate" if MODE == "candidate" else "security-web-gateway")
PROXY_IP = os.getenv("SWG_PROXY_IP", "127.0.0.1")
PROXY_PORT = int(os.getenv("SWG_PROXY_PORT", "3128"))
MANAGEMENT_FQDN = os.getenv("SWG_FQDN", "proxy.example.internal")
DATA_ROOT = Path(os.getenv("SWG_DATA_ROOT", "/var/lib/security-web-gateway/candidate" if MODE == "candidate" else "/var/lib/security-web-gateway/prod"))
DB_PATH = Path(os.getenv("SWG_DB_PATH", str(DATA_ROOT / "swg.db")))
CANDIDATE_ROOT = DATA_ROOT / "candidates"
BACKUP_ROOT = Path(os.getenv("SWG_BACKUP_ROOT", "/var/lib/security-web-gateway/backups"))
LIVE_MANAGED_CONF = Path(os.getenv("SWG_LIVE_MANAGED_CONF", "/etc/squid/managed/security-web-gateway.conf"))
SQUID_CONF = Path(os.getenv("SWG_SQUID_CONF", "/etc/squid/squid.conf"))
SQUID_ACCESS_LOG = Path(os.getenv("SWG_SQUID_ACCESS_LOG", "/var/log/squid/access.log"))
GOOGLE_SEARCH_FILE = Path(os.getenv("SWG_GOOGLE_SEARCH_FILE", "/etc/squid/allowlists/google-search.txt"))
GOOGLE_MAPS_FILE = Path(os.getenv("SWG_GOOGLE_MAPS_FILE", "/etc/squid/allowlists/google-maps.txt"))
LEGACY_BUSINESS_FILE = Path(os.getenv("SWG_LEGACY_BUSINESS_FILE", "/etc/squid/allowlists/business-domains.txt"))
DEPLOY_SOCKET = os.getenv("SWG_DEPLOY_SOCKET", "/run/security-web-gateway-deploy.sock")
SESSION_COOKIE = os.getenv("SWG_SESSION_COOKIE", "swg_candidate_session" if MODE == "candidate" else "swg_session")
SESSION_HOURS = 8
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_MINUTES = 15
DEFAULT_DNS_SERVERS = [x.strip() for x in os.getenv("SWG_DNS_SERVERS", "1.1.1.1,8.8.8.8").split(",") if x.strip()]
MAX_IMPORT_BYTES = 2 * 1024 * 1024
MAX_IMPORT_ROWS = 5000

PLAYWRIGHT_BROWSERS_PATH = Path(os.getenv("PLAYWRIGHT_BROWSERS_PATH", "/var/lib/security-web-gateway/playwright"))
DISCOVERY_MAX_HAR_BYTES = int(os.getenv("SWG_DISCOVERY_MAX_HAR_BYTES", str(10 * 1024 * 1024)))
DISCOVERY_BROWSER_TIMEOUT_MS = int(os.getenv("SWG_DISCOVERY_BROWSER_TIMEOUT_MS", "20000"))
DISCOVERY_BROWSER_MAX_PAGES = int(os.getenv("SWG_DISCOVERY_BROWSER_MAX_PAGES", "6"))
SQUID_LOG_DIR = Path(os.getenv("SWG_SQUID_LOG_DIR", "/var/log/squid"))

SESSION_TOUCH_INTERVAL_SECONDS = int(os.getenv("SWG_SESSION_TOUCH_INTERVAL_SECONDS", "60"))
DASHBOARD_CACHE_TTL_SECONDS = int(os.getenv("SWG_DASHBOARD_CACHE_TTL_SECONDS", "20"))
TELEMETRY_BATCH_MAX = int(os.getenv("SWG_TELEMETRY_BATCH_MAX", "10000"))
LOCAL_DNS_CACHE = os.getenv("SWG_LOCAL_DNS_CACHE", "0").strip().lower() in ("1","true","yes","on")
LOCAL_DNS_IP = os.getenv("SWG_LOCAL_DNS_IP", "127.0.0.1")
