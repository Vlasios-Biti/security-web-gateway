#!/usr/bin/env python3
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from app.db import verify_schema
from app.services.deployment import reconcile_pending_if_no_diff
verify_schema();print(json.dumps(reconcile_pending_if_no_diff(),indent=2))
