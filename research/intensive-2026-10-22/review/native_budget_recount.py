#!/usr/bin/env python3
"""Independent stdlib full-hash/sighash/budget arithmetic check; no native run.

Serializers are derived directly from rusty-kaspa 01b532e source, not imported
from the producer or its validation script. Only public selected inputs/reports
are read. V1 rest-preimage equality is checked without implementing BLAKE3.
"""
from copy import deepcopy
from hashlib import blake2b, sha256
from pathlib import Path
import json
import sys


def u(value, width):
    return int(value).to_bytes(width, "little")


def blob(value):
    return u(len(value), 8)+value


def h(domain, value):
    return blake2b(value, key=domain.encode(), digest_size=32).digest()


def point(value):
    return bytes.fromhex(value["transactionId"])+u(value["index"],4)


def spk(value):
    raw=bytes.fromhex(value)
    return u(int.from_bytes(raw[:2],"big"),2)+blob(raw[2:])


def output(value):
    assert value["covenant"] is None
    return u(value["value"],8)+spk(value["scriptPublicKey"])+b"\0"


def transaction_bytes(tx, *, v1_rest=False):
    assert tx["version"] == 1
    raw=u(1,2)+u(len(tx["inputs"]),8)
    for inp in tx["inputs"]:
        raw+=point(inp["previousOutpoint"])
        raw+=blob(b"" if v1_rest else bytes.fromhex(inp["signatureScript"]))
        raw+=u(inp["sequence"],8)
        if not v1_rest:
            raw+=u(inp["computeBudget"],2)
    raw+=u(len(tx["outputs"]),8)+b"".join(output(o) for o in tx["outputs"])
    raw+=u(tx["lockTime"],8)+bytes.fromhex(tx["subnetworkId"])+u(tx["gas"],8)
    raw+=blob(b"" if v1_rest else bytes.fromhex(tx["payload"]))
    if not v1_rest:
        raw+=u(tx["storageMass"],8)
    return raw


def sighashes(tx, entries):
    previous=h("TransactionSigningHash", b"".join(point(i["previousOutpoint"]) for i in tx["inputs"]))
    sequences=h("TransactionSigningHash", b"".join(u(i["sequence"],8) for i in tx["inputs"]))
    outputs=h("TransactionSigningHash", b"".join(output(o) for o in tx["outputs"]))
    payload=bytes.fromhex(tx["payload"])
    payload_digest=(bytes(32) if bytes.fromhex(tx["subnetworkId"])==bytes(20) and not payload
                    else h("TransactionSigningHash",blob(payload)))
    result=[]
    for inp,entry in zip(tx["inputs"],entries):
        raw=(u(1,2)+previous+sequences+point(inp["previousOutpoint"])+spk(entry["scriptPublicKey"])
             +u(entry["value"],8)+u(inp["sequence"],8)+outputs+u(tx["lockTime"],8)
             +bytes.fromhex(tx["subnetworkId"])+u(tx["gas"],8)+payload_digest+b"\1")
        result.append(h("TransactionSigningHash",raw).hex())
    return result


def main(directory):
    directory=Path(directory).resolve(strict=True)
    selected=(directory/"selected-public-input.json").read_bytes()
    assert sha256(selected).hexdigest()=="7fd8bd70774872a1748fb52d32754556e578f8abf89c76100e28e1fd315b02a1"
    data=json.loads(selected)
    report=json.loads((directory/"native.stdout.json").read_bytes())
    known={t["id"]:t for t in data["parents"]+data["lineage"]}
    cases=report["baselines"]+report["candidate1600"]+report["focused_boundaries"]
    checked=[]
    for row in cases:
        original=data["lineage"][row["ordinal"]+1]
        entries=[known[i["previousOutpoint"]["transactionId"]]["outputs"][i["previousOutpoint"]["index"]]
                 for i in original["inputs"]]
        changed=deepcopy(original)
        changed["inputs"][0]["computeBudget"]=row["reserve_budget"]
        original_hash=h("TransactionHash",transaction_bytes(original)).hex()
        changed_hash=h("TransactionHash",transaction_bytes(changed)).hex()
        assert original_hash==row["original_full_hash"]
        assert changed_hash==row["candidate_full_hash"]
        assert transaction_bytes(original,v1_rest=True)==transaction_bytes(changed,v1_rest=True)
        assert sighashes(original,entries)==sighashes(changed,entries)
        # The source is checked separately for actual full native validation.
        # Here the independent arithmetic derives the budget-only mass delta.
        baseline=report["baselines"][row["ordinal"]]["metrics"]
        expected_compute=baseline["compute_mass"]+(row["reserve_budget"]-3000)*100
        metrics=row["metrics"]
        assert metrics["compute_mass"]==expected_compute
        assert metrics["transient_mass"]==baseline["transient_mass"]
        assert metrics["storage_mass"]==baseline["storage_mass"]==int(original["storageMass"])
        assert metrics["estimated_bytes"]==baseline["estimated_bytes"]
        relay=max(expected_compute,(metrics["transient_mass"]+1)//2)
        mining=max(relay,metrics["storage_mass"])
        assert metrics["relay_mass"]==relay and metrics["mining_mass"]==mining
        assert row["allowed_reserve_units"]==row["reserve_budget"]*10000+9999
        if row["expected_pass"]:
            assert row["reserve_input"]["used_units"]<=row["allowed_reserve_units"]
            assert row["full_native"]["fee_sompi"]=="40000000"
        else:
            error=row["reserve_input"]["error"]
            assert error["limit_units"]==row["allowed_reserve_units"]
            assert error["attempted_used_units"]>error["limit_units"]
        for quote in row["fee_quotes"]:
            rate=quote["sompi_per_gram"]
            assert rate in (100,200,500)
            assert quote["necessary_fee_sompi"]==str(mining*rate)
            assert quote["relay_only_fee_sompi"]==str(relay*rate)
        checked.append({"ordinal":row["ordinal"],"budget":row["reserve_budget"],
                        "independent_full_hash":changed_hash,
                        "v1_rest_preimage_unchanged":True,"sighash_all_unchanged":True,
                        "independent_mining_mass":mining})
    assert len(cases)==35
    maximum=max(r["metrics"]["mining_mass"] for r in report["candidate1600"])
    assert maximum==191628 and maximum*200==38325600<40000000
    assert maximum*500==95814000 and maximum*500+10000000==105814000
    print(json.dumps({"scope":"independent public byte/hash and arithmetic recount; no native rerun",
        "selected_input_sha256":sha256(selected).hexdigest(),"native_cases_recounted":len(cases),
        "fee_quotes_recounted":sum(len(r["fee_quotes"]) for r in cases),
        "maximum_candidate_mining_mass":maximum,"maximum_2x_fee_sompi":str(maximum*200),
        "original_fee_margin_sompi":str(40000000-maximum*200),
        "maximum_5x_fee_sompi":str(maximum*500),"minimum_5x_claim_for_payout_floor_sompi":str(maximum*500+10000000),
        "all_original_full_hashes_match":True,"all_candidate_full_hashes_match":True,
        "all_v1_rest_preimages_unchanged":True,"all_sighash_all_unchanged":True,
        "storage_mass_unchanged":True,"cases":checked},indent=2))


if __name__=="__main__":
    if len(sys.argv)!=2:
        raise SystemExit("usage: native_budget_recount.py PUBLIC_BUDGET_ATTEMPT_DIRECTORY")
    main(sys.argv[1])
