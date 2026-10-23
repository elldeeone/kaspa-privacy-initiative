#!/usr/bin/env python3
"""Scoring-only isolated entrypoint; never imports observer or generator."""
import json
from pathlib import Path
import sys
from schema import parse
from score import score

if __name__=='__main__':
    if len(sys.argv)!=4:raise SystemExit('public prediction truth arguments required')
    result=score(*(parse(Path(p).read_bytes()) for p in sys.argv[1:]))
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
