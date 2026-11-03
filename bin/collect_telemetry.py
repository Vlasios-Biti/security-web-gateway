#!/usr/bin/env python3
import argparse
from app.services.traffic import ingest_access_log, telemetry_health


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--max-events',type=int,default=100000)
    p.add_argument('--no-cleanup',action='store_true')
    a=p.parse_args()
    r=ingest_access_log(max_events=max(1000,min(a.max_events,500000)),cleanup=not a.no_cleanup)
    print(r)
    if r.get('error'):
        raise SystemExit(1)
    print(telemetry_health())

if __name__=='__main__':
    main()
