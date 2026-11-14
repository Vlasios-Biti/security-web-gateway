#!/usr/bin/env python3
import sys,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.db import verify_schema
from app.services.defaults import setup_defaults
if __name__=='__main__':
    verify_schema();print(json.dumps(setup_defaults()))
