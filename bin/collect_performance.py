#!/usr/bin/env python3
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from app.db import verify_schema
from app.services.performance import collect_performance_sample
from app.services.system import cache_system_health

if __name__ == '__main__':
    verify_schema()
    out={'performance':collect_performance_sample(),'system_health':cache_system_health(90)}
    print(json.dumps(out, indent=2, sort_keys=True))
