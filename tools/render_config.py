#!/usr/bin/env python3
import argparse,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from app.db import verify_schema
from app.services.deployment import generate_config

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args();verify_schema();out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(generate_config(),encoding='utf-8');print(out)
if __name__=='__main__':main()
