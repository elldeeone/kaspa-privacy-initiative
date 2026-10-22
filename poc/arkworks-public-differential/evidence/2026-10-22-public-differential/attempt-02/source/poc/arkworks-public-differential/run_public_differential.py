#!/usr/bin/env python3
"""Finite, public-only Arkworks/native decoder and verifier comparison.

No setup/proving/secret material. The three positive statements are selected
from named hash-pinned public development fixtures; all other cases are bounded
serialization controls of those same statements or standard public curve points.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
POOL = HERE.parent / "shared-pool"
sys.path.insert(0, str(POOL))
import public_native_observation as public
FRESH = Path("/home/luke/projects/kpi-intensive-2026-10-22/observer/artifacts/public-v6-fixture-production-20261022T124051Z/public")
FRESH_PINS = {
    "verification-key.bin": "2a9acd1639fb7b454384c65fb317a139695f5a2cbb3ebd941dd13b5f6045a2f4",
    "bundle-0.bin": "3f8f0a13f4ce7a73b61fd093c5aad01fc2cb2ea0ca3db65ed4f0d44de72019a9",
    "bundle-1.bin": "1cc3094a335dfa94897929fde258d05da2a3270314738919b972838e61e2d7b8",
}
HISTORICAL_VK = "9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef"
HISTORICAL_PROOF = "01b2cdc52131f4a612fb354fb5f86e0ad7c5c5f4a2e4146d18484514180a6b9b"
SOURCE_FILES = [HERE / "Cargo.toml", HERE / "Cargo.lock", HERE / "src/main.rs", Path(__file__),
                POOL / "src/bin/kpi-native-arkworks-differential.rs", POOL / "Cargo.toml", POOL / "Cargo.lock",
                POOL / "public_native_observation.py"]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def save(path, value):
    path.write_bytes(public.canonical(value) + b"\n")

def checked(path, expected):
    public.require(path.is_file() and not path.is_symlink(), "public regular file")
    data = path.read_bytes()
    public.require(sha(data) == expected, "public source pin: " + str(path))
    return data

def statement(name, vk, proof, auth):
    public.require(len(vk) == 328 and len(proof) == 128 and len(auth) == 377, "positive framing")
    digest = hashlib.sha256(auth).digest()
    return dict(id=name, vk_hex=vk.hex(), proof_hex=proof.hex(),
                inputs_hex=[(digest[:16] + bytes(16)).hex(), (digest[16:] + bytes(16)).hex()])

def inputs(fixtures):
    public.require(fixtures["ark05"] == fixtures["ark06"], "standard fixture semantics differ")
    f = fixtures["ark05"]
    raw = public.load_public_rehearsal()
    tx = raw["lineage"][5]
    vk = bytes.fromhex(raw["vk_hex"])
    proof = bytes.fromhex(tx["inputs"][0]["signatureScript"])[2:130]
    auth = bytes.fromhex(tx["payload"])[8:385]
    public.require(sha(vk) == HISTORICAL_VK and sha(proof) == HISTORICAL_PROOF, "historical selection pin")
    positives = [statement("historical-ordinary-spend", vk, proof, auth)]
    fresh = {name: checked(FRESH / name, digest) for name, digest in FRESH_PINS.items()}
    for i in range(2):
        bundle = fresh[f"bundle-{i}.bin"]
        public.require(len(bundle) == 875, "fresh bundle framing")
        positives.append(statement(f"fresh-pair-{i}", fresh["verification-key.bin"], bundle[377:505], bundle[:377]))
    vectors = []
    def vec(name, kind, data):
        vectors.append(dict(id=name, kind=kind, hex=data if type(data) is str else data.hex()))
    for s in positives:
        vec(s["id"] + "/vk", "vk", s["vk_hex"])
        vec(s["id"] + "/proof", "proof", s["proof_hex"])
        for i, value in enumerate(s["inputs_hex"]):
            vec(s["id"] + f"/input-{i}", "fr", value)
    for kind in ("fq", "fr"):
        modulus = int.from_bytes(bytes.fromhex(f[kind + "_modulus_le"]), "little")
        for name, n in [("zero", 0), ("one", 1), ("modulus-minus-one", modulus-1), ("modulus", modulus),
                        ("modulus-plus-one", modulus+1), ("all-ff", 2**256-1), ("high-flag-80", 2**255)]:
            vec(kind + "/" + name, kind, n.to_bytes(32,"little"))
        vec(kind + "/truncated", kind, bytes(31))
        vec(kind + "/trailing", kind, bytes(33))
    for kind, size in (("g1",32), ("g2",64)):
        gen = bytes.fromhex(f[kind + "_generator"])
        identity = bytes.fromhex(f[kind + "_identity"])
        vec(kind + "/generator", kind, gen)
        vec(kind + "/identity", kind, identity)
        for flag in (0, 0x40, 0x80, 0xc0):
            x = bytearray(gen); x[-1] = (x[-1] & 0x3f) | flag
            vec(kind + f"/generator-flags-{flag:02x}", kind, bytes(x))
        x = bytearray(identity); x[0] = 1
        vec(kind + "/nonzero-infinity-payload", kind, bytes(x))
        vec(kind + "/truncated", kind, gen[:-1])
        vec(kind + "/trailing", kind, gen+b"\x00")
        x = bytearray(gen); x[:32] = bytes.fromhex(f["fq_modulus_le"])
        vec(kind + "/coordinate-modulus", kind, bytes(x))
    nonsub = f["bounded_non_subgroup_g2"]
    public.require(nonsub is not None and nonsub["on_curve"] is True and nonsub["in_prime_subgroup"] is False,
                   "bounded public subgroup fixture not found")
    vec("g2/on-curve-off-subgroup", "g2", nonsub["hex"])
    base = positives[0]
    proof = bytes.fromhex(base["proof_hex"])
    vk = bytes.fromhex(base["vk_hex"])
    for name, kind, data in [("proof/a","g1",proof[:32]),("proof/b","g2",proof[32:96]),("proof/c","g1",proof[96:])]:
        vec(name,kind,data)
    for name, kind, data in [("vk/trailing","vk",vk+b"\x00"),("proof/trailing","proof",proof+b"\x00"),
                             ("vk/truncated","vk",vk[:-1]),("proof/truncated","proof",proof[:-1])]:
        vec(name,kind,data)
    vk0 = vk[:224] + bytes(8)
    vk4 = vk[:224] + (4).to_bytes(8,"little") + vk[232:] + bytes.fromhex(f["g1_generator"])
    vk_huge = vk[:224] + (2**64-1).to_bytes(8,"little") + vk[232:]
    for name, data in [("vk/count-zero",vk0),("vk/count-four",vk4),("vk/count-u64max",vk_huge)]:
        vec(name,"vk",data)
    vec("hex/uppercase", "g2", f["g2_generator"].upper())
    vec("hex/malformed", "g1", "zz")
    vec("size/oversize-g1", "g1", bytes(41))
    statements = copy.deepcopy(positives)
    expectations = {s["id"]:"positive" for s in positives}
    def case(name, *, key=None, prf=None, inp=None, expected="negative"):
        s = copy.deepcopy(base); s["id"] = name
        if key is not None: s["vk_hex"] = key.hex()
        if prf is not None: s["proof_hex"] = prf.hex()
        if inp is not None: s["inputs_hex"] = [x.hex() for x in inp]
        statements.append(s); expectations[name] = expected
    for s in positives:
        q = copy.deepcopy(s); q["id"] += "/changed-input"
        q["inputs_hex"][0] = (int.from_bytes(bytes.fromhex(q["inputs_hex"][0]),"little")+1).to_bytes(32,"little").hex()
        statements.append(q); expectations[q["id"]] = "negative"
    for name, start, end, kind in [("a",0,32,"g1"),("b",32,96,"g2"),("c",96,128,"g1")]:
        case("proof-identity-"+name, prf=proof[:start]+bytes.fromhex(f[kind+"_identity"])+proof[end:])
    p = bytearray(proof); p[31] ^= 0x80
    case("proof-a-sign-flip", prf=bytes(p))
    p = bytearray(bytes.fromhex(f["g1_identity"])); p[0] = 1
    case("proof-noncanonical-infinity-a", prf=bytes(p)+proof[32:])
    case("proof-off-subgroup-b", prf=proof[:32]+bytes.fromhex(nonsub["hex"])+proof[96:])
    case("vk-identity-alpha", key=bytes.fromhex(f["g1_identity"])+vk[32:])
    case("vk-off-subgroup-beta", key=vk[:32]+bytes.fromhex(nonsub["hex"])+vk[96:])
    case("vk-count-zero", key=vk0)
    case("vk-count-four", key=vk4, expected="raw-arity-difference")
    case("vk-count-u64max", key=vk_huge, expected="guard")
    case("proof-trailing", prf=proof+b"\x00", expected="generic-prefix-only")
    case("vk-trailing", key=vk+b"\x00", expected="generic-prefix-only")
    case("proof-truncated", prf=proof[:-1])
    case("vk-truncated", key=vk[:-1])
    original_inputs = [bytes.fromhex(x) for x in base["inputs_hex"]]
    case("input-trailing", inp=[original_inputs[0]+b"\x00", original_inputs[1]], expected="generic-prefix-only")
    case("input-modulus", inp=[bytes.fromhex(f["fr_modulus_le"]), original_inputs[1]])
    case("input-missing", inp=original_inputs[:1])
    case("input-extra", inp=original_inputs+[bytes(32)], expected="raw-arity-difference")
    public.require(len(vectors) <= 200 and len(statements) <= 50, "case bounds")
    provenance = dict(historical_source_files={k:dict(path=str(POOL/p),sha256=h) for k,(p,h) in public.FIXTURE_PINS.items()},
                      historical_selected_transaction=tx["id"], historical_vk_sha256=HISTORICAL_VK,
                      historical_proof_sha256=HISTORICAL_PROOF,
                      fresh_source_files={k:dict(path=str(FRESH/k),sha256=h) for k,h in FRESH_PINS.items()},
                      field_derivation="SHA256(public authorization)[0:16] || zero16, then [16:32] || zero16, little endian",
                      no_new_proof_or_setup=True, no_private_material=True, fresh_synthetic_fixture=True,
                      historical_chain_acceptance_revalidated=False)
    return dict(schema="kpi-arkworks-public-differential-input-v1",vectors=vectors,statements=statements), expectations, provenance

def sandbox(binary, argument=None):
    cmd = ["/usr/bin/bwrap","--unshare-all","--die-with-parent","--new-session","--clearenv",
           "--ro-bind","/usr","/usr","--symlink","usr/bin","/bin","--symlink","usr/lib","/lib",
           "--symlink","usr/lib64","/lib64","--proc","/proc","--dev","/dev","--tmpfs","/tmp",
           "--ro-bind",str(binary),"/check"]
    if argument == "--fixtures":
        return cmd + ["--chdir","/tmp","/check","--fixtures"]
    return cmd + ["--ro-bind",str(argument),"/input.json","--chdir","/tmp","/check","/input.json"]

def execute(binary, argument, output, label):
    result = subprocess.run(sandbox(binary,argument),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300,check=False)
    (output/(label+".stdout.json")).write_bytes(result.stdout)
    (output/(label+".stderr.txt")).write_bytes(result.stderr)
    public.require(result.returncode == 0 and not result.stderr, label+" process failed")
    return public.unique_json(result.stdout)

def semantic(value):
    if type(value) is dict:
        return {k:semantic(v) for k,v in value.items() if k != "error"}
    if type(value) is list: return [semantic(x) for x in value]
    return value

def verify(inp, expected, ark, native):
    digest = sha(public.canonical(inp)+b"\n")
    public.require(ark["input_sha256"] == native["input_sha256"] == digest,"executed input identity")
    public.require([r["id"] for r in ark["vectors"]] == [v["id"] for v in inp["vectors"]], "vector alignment")
    public.require([r["id"] for r in ark["statements"]] == [r["id"] for r in native["statements"]] == [s["id"] for s in inp["statements"]], "statement alignment")
    differences=[]
    for r in ark["vectors"]:
        if semantic(r["ark05"]) != semantic(r["ark06"]): differences.append(dict(kind="vector",id=r["id"]))
    for r,n in zip(ark["statements"],native["statements"]):
        if semantic(r["ark05"]) != semantic(r["ark06"]): differences.append(dict(kind="statement",id=r["id"]))
        mode=expected[r["id"]]
        accepted=[r[b].get("raw_verifier",{}).get("returned") is True for b in ("ark05","ark06")]
        if mode == "positive":
            public.require(all(accepted) and all(r[b]["strict_profile_accepted"] is True for b in ("ark05","ark06")) and n["native"]["status"] == "verified", "positive did not verify: "+r["id"])
        elif mode == "generic-prefix-only":
            public.require(all(accepted) and all(r[b]["strict_profile_accepted"] is False for b in ("ark05","ark06")) and n["native"]["status"] == "native_rejected", "trailing policy control: "+r["id"])
        elif mode == "raw-arity-difference":
            public.require(accepted == [False,True] and all(r[b]["strict_profile_accepted"] is False for b in ("ark05","ark06")) and n["native"]["status"] == "native_rejected", "raw arity control: "+r["id"])
        else:
            public.require(not any(accepted) and n["native"]["status"] in ("native_rejected","guard_rejected"), "negative accepted: "+r["id"])
            if mode == "guard": public.require(n["native"]["status"] == "guard_rejected", "allocation guard control")
    byid={r["id"]:r for r in ark["vectors"]}
    for b in ("ark05","ark06"):
        public.require(byid["g2/on-curve-off-subgroup"][b]["status"] == "decode_rejected", "subgroup check")
        public.require(byid["vk/count-u64max"][b]["status"] == "guard_rejected", "preallocation VK count guard")
        for kind in ("fq","fr"):
            public.require(byid[kind+"/modulus"][b]["status"] == "decode_rejected", "field canonical modulus")
        for kind in ("g1","g2"):
            p=byid[kind+"/nonzero-infinity-payload"][b]
            public.require(p["status"] == "accepted" and p["identity"] is True and p["roundtrip_equal"] is False, "infinity canonicality control")
    return dict(schema="kpi-arkworks-public-differential-validation-v1",vector_count=len(inp["vectors"]),
                statement_count=len(inp["statements"]), positive_statements=3, generic_prefix_only_controls=3, raw_arity_difference_controls=2,
                native_verified=sum(x["native"]["status"] == "verified" for x in native["statements"]),
                semantic_differences_excluding_error_wording=differences,
                finite_case_semantics_equal=not differences,
                exact_accepted_compressed_and_uncompressed_bytes_compared=True,
                expected_case_outcomes_checked=True, general_encoding_equivalence_claim=False,
                covenant_or_chain_validation=False)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ark-binary",type=Path,required=True)
    p.add_argument("--native-binary",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args(); output=a.output.resolve(); output.mkdir(parents=True,exist_ok=False)
    sources={str(x.relative_to(HERE.parent.parent)):dict(sha256=sha(x.read_bytes()),bytes=x.stat().st_size) for x in SOURCE_FILES}
    for x in SOURCE_FILES:
        dest=output/"source"/x.relative_to(HERE.parent.parent);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(x.read_bytes())
    source_receipt=dict(sources=sources,binaries={str(x):dict(sha256=sha(x.read_bytes()),bytes=x.stat().st_size) for x in (a.ark_binary,a.native_binary)},
                        native_dependency="01b532e8b553523216471682649693af92f0fd16", arkworks_versions=["0.5.0","0.6.0"])
    save(output/"SOURCE.json",source_receipt)
    fixtures=execute(a.ark_binary,"--fixtures",output,"standard-fixtures")
    inp,expected,provenance=inputs(fixtures)
    save(output/"input.json",inp);save(output/"EXPECTATIONS.json",expected);save(output/"PROVENANCE.json",provenance)
    ark=execute(a.ark_binary,output/"input.json",output,"arkworks")
    native=execute(a.native_binary,output/"input.json",output,"native")
    validation=verify(inp,expected,ark,native)
    public.require(sources == {str(x.relative_to(HERE.parent.parent)):dict(sha256=sha(x.read_bytes()),bytes=x.stat().st_size) for x in SOURCE_FILES},"source changed during run")
    public.require(source_receipt["binaries"] == {str(x):dict(sha256=sha(x.read_bytes()),bytes=x.stat().st_size) for x in (a.ark_binary,a.native_binary)},"binary changed during run")
    save(output/"VALIDATION.json",validation)
    artifacts={str(x.relative_to(output)):dict(sha256=sha(x.read_bytes()),bytes=x.stat().st_size) for x in sorted(output.rglob("*")) if x.is_file()}
    save(output/"MANIFEST.json",dict(schema="kpi-arkworks-public-differential-manifest-v1",artifacts=artifacts,validation=validation))
    print(json.dumps(validation,sort_keys=True))

if __name__ == "__main__":
    main()
