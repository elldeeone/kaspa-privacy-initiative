"""One frozen official native control run; never prepare or tune fixtures here."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def read(path):
    return json.loads(Path(path).read_text())


def save(path,value):
    path=Path(path)
    if path.exists():raise ValueError("refuse overwrite: "+str(path))
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")


def check(pin):
    path=Path(pin["path"])
    data=path.read_bytes()
    if len(data)!=pin["bytes"] or hashlib.sha256(data).hexdigest()!=pin["sha256"]:
        raise ValueError("frozen member changed: "+str(path))


def run(args):
    raw=args.freeze.read_bytes()
    actual=hashlib.sha256(raw).hexdigest()
    if actual!=args.reviewed_freeze_sha256:
        raise ValueError("reviewed freeze identity differs")
    freeze=json.loads(raw)
    for pin in freeze["files"]:check(pin)
    if args.output.exists():raise ValueError("fresh run identity required")
    args.output.mkdir(parents=True)
    binary=Path(freeze["native_binary"]["path"])
    rows=[]
    for expected_path in freeze["expected_tables"]:
        expected=read(expected_path)
        for case in expected["cases"]:
            name=case["case_id"]
            directory=args.output/name
            process=subprocess.run([str(binary),"validate-transaction",case["validation_case"]["path"],str(directory)],
                text=True,capture_output=True,check=False)
            save(directory/"command.json",{"returncode":process.returncode,"stdout":process.stdout,"stderr":process.stderr})
            report_path=directory/"native-validation.json"
            report=read(report_path) if report_path.exists() else {}
            inputs=report.get("per_input_ScriptEngine",[])
            actual_inputs=["ACCEPT" if e.get("accepted") is True else e.get("typed_error","MISSING") for e in inputs]
            match=(process.returncode==0 and report.get("isolation")=="PASS"
                and actual_inputs==case["expected_per_input"]
                and report.get("Full",{}).get("accepted")==case["expected_Full_accepted"])
            rows.append({"case_id":name,"expectation_matched":match,
                "expected_per_input":case["expected_per_input"],"actual_per_input":actual_inputs,
                "expected_Full_accepted":case["expected_Full_accepted"],"report":report,
                "supplied_context_only":case["supplied_context_only"],"intended_cause":case["intended_cause"]})
    result={"classification":"PUBLIC_SYNTHETIC_DO_NOT_FUND","reviewed_freeze_sha256":actual,
        "case_count":len(rows),"matched":sum(r["expectation_matched"] for r in rows),
        "mismatches":sum(not r["expectation_matched"] for r in rows),"cases":rows,
        "scope":"exact frozen supplied-context native Full and every input engine; no accepted chain history/backing/privacy claim"}
    save(args.output/"RESULTS.json",result)
    print(json.dumps({k:result[k] for k in ("case_count","matched","mismatches")}))
    if result["mismatches"]:raise SystemExit(1)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--freeze",required=True,type=Path)
    parser.add_argument("--reviewed-freeze-sha256",required=True)
    parser.add_argument("--output",required=True,type=Path)
    run(parser.parse_args())
