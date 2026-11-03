#!/usr/bin/env python3
import argparse, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from app.db import verify_schema
from app.services.traffic import cleanup_telemetry,cleanup_rotated_squid_logs

def main():
    p=argparse.ArgumentParser();p.add_argument('--telemetry-only',action='store_true');a=p.parse_args()
    verify_schema()
    out={'telemetry':cleanup_telemetry()}
    if not a.telemetry_only: out['squid_logs']=cleanup_rotated_squid_logs()
    print(json.dumps(out,indent=2,sort_keys=True))
if __name__=='__main__': main()
