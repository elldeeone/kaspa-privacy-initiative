"""Materialize three native cases from two separately verified genuine proofs.

Preparation only. Reuses an explicitly selected retained assembler snapshot;
does not generate keys/proofs or execute a native engine.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
from pathlib import Path
import sys
import prepare_controls as c


def prepare(args):
    if args.output.exists():raise ValueError("fresh fork preparation required")
    args.output.mkdir(parents=True)
    spec=importlib.util.spec_from_file_location("selected_retained_fork_assembler",args.assembler_snapshot)
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    # The retained source has a different physical directory; its constructors
    # still operate against the actual repository and already selected modules.
    module.REPO=c.REPO
    c.a=module
    a=module
    producer=c.Producer(args)
    case_directories={}
    for letter,label,proofdir,expected in (
        ("A","A-private-before-reveal",args.proof_a,"ACCEPT"),
        ("B","B-private-after-reveal",args.proof_b,"VerifyError")):
        directory=args.forks/label
        vector=c.load(directory/"private-native-vector-placeholder.json")
        proof=(proofdir/"proof128.bin").read_bytes()
        report=c.load(proofdir/"report.json")
        if (len(proof)!=128 or not any(proof)
            or report.get("genuine_Groth16_verified") is not True
            or report["proof_hex128"]!=proof.hex()
            or report["vk_hex328"]!=vector["vk_hex"]
            or report["fixture_sha256"]!=c.pin(directory/"private-fixture.json")["sha256"]):
            raise ValueError("genuine fork proof/source/VK mismatch: "+letter)
        vector["proof_hex"]=proof.hex()
        _,bodydir=producer.construct("genuine-"+label,"private-freeze",vector)
        description=c.load(directory/"CASE.json")
        actual_prior=Path(description["prior_actual_native_body"])
        a.verify_link(actual_prior,bodydir)
        producer.record("genuine-"+label,bodydir,[expected],
            "genuine valid private ownership proof; "+("current NF absent" if letter=="A" else "CURRENT authenticated spent original Bob NF must reject before Groth16"))
        case_directories[letter]=bodydir
    snapshot=a.parse_snapshot(c.load(args.forks/"A-private-before-reveal/snapshots.json")["prospective"])
    backup=c.load(args.prepared/"PUBLIC-SYNTHETIC-backups.json")
    crypto=a.Crypto(args.crypto)
    bob=a.Receiver(bytes.fromhex(backup["backups"]["Bob"]["seed32"]),a.DOMAIN,crypto)
    vector_a=c.load(args.forks/"A-private-before-reveal/private-native-vector-placeholder.json")
    auth=bytes.fromhex(vector_a["auth_hex"])
    reserve=int.from_bytes(auth[476:484],"little")
    vector,_=c.reveal_vector(bob,2,snapshot,a.outpoint(case_directories["A"]),reserve,
        10_000_000,vector_a["vk_hex"],spent=True)
    _,directory=producer.construct("genuine-private-then-old-Bob-reveal","reveal-freeze",vector)
    a.verify_link(case_directories["A"],directory)
    producer.record("genuine-private-then-old-Bob-reveal",directory,["VerifyError"],
        "same old positioned CM/NF, current CM path and exact authenticated occupied NF equality; correct original native signer")
    order={"genuine-A-private-before-reveal":0,"genuine-private-then-old-Bob-reveal":1,
           "genuine-B-private-after-reveal":2}
    producer.cases.sort(key=lambda case:order[case["case_id"]])
    files=[Path(__file__),Path(c.__file__),args.assembler_snapshot,args.native,
        args.proof_a/"proof128.bin",args.proof_a/"report.json",
        args.proof_b/"proof128.bin",args.proof_b/"report.json"]
    c.save(args.output/"EXPECTED.json",{"classification":c.CLASS,
        "native_VM_or_Full_executed":False,"case_count":3,"cases":producer.cases,
        "source_pins":[c.pin(f) for f in files],
        "scope":"two genuinely verified private R1CS proofs; CURRENT native NF exclusivity both orders",
        "primary_mainline_modified":False})
    print("Prepared three genuine competing-path cases; no native execution")


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    for name in ("forks","prepared","proof-a","proof-b","assembler-snapshot","native","crypto","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    prepare(parser.parse_args())
