#!/usr/bin/env python3
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from app.db import verify_schema
from app.services.discovery import process_browser_queue
from app.services.learning import process_learning_sessions
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--max-runs',type=int,default=1);a=p.parse_args();verify_schema();print(json.dumps({'learning':process_learning_sessions(),'browser':process_browser_queue(a.max_runs)},indent=2))
