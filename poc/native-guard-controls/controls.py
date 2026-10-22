"""Finite public-fixture controls. Existing native validator is the acceptance oracle.

Canonical v1 txid adapter follows pinned SDK hashing/tx.rs. A matched ID for
all seven untouched fixture transactions is required before any mutation.
Negative cases are native-VM rejection evidence only: their unchanged genuine
proof is known from the accepted baseline but VM guards precede proof execution.
"""
import copy, hashlib, json, os, resource, struct, subprocess, sys, time
from pathlib import Path

def sha(b): return hashlib.sha256(b).hexdigest()
def save(p, value):
    with p.open("x") as f: json.dump(value, f, indent=2); f.write("\n")
def number(v, bits=64): return int(v).to_bytes(bits//8, "little")
def vb(b): return number(len(b))+b

def run(lane, phase):
    output=lane/"outputs"
    root=lane/"worktree"
    source=root/"poc/shared-pool/evidence/2026-10-20-wallet-lifecycle/positive"
    txs=json.loads((source/"lineage.json").read_text())
    parents=json.loads((source/"parents.json").read_text())
    vk=(source/"vk.bin").read_bytes()
    deadline=json.loads((output/"deadline.json").read_text())["epoch_seconds"]
    helper=lane/"adapter-target/release/kpi-native-guard-id"
    binary=lane/"bin/kpi-two-input-lifecycle"
    pins=json.loads((output/"input-pins.json").read_text())
    assert sha(binary.read_bytes()) == pins["validator_sha256"]
    for rel, expected in pins["fixtures"].items(): assert sha((root/rel).read_bytes()) == expected, rel
    def b3(tag,b):
        p=subprocess.run([str(helper),tag],input=b,capture_output=True,check=True,timeout=10)
        return bytes.fromhex(p.stdout.decode().strip())
    def txid(t):
        assert t["version"]==1 and t["subnetworkId"]=="00"*20 and all(o["covenant"] is None for o in t["outputs"])
        rest=number(1,16)+number(len(t["inputs"]))
        for i in t["inputs"]:
            out=i["previousOutpoint"]
            rest+=bytes.fromhex(out["transactionId"])+number(out["index"],32)+vb(b"")+number(i["sequence"])
        rest+=number(len(t["outputs"]))
        for o in t["outputs"]:
            spk=bytes.fromhex(o["scriptPublicKey"])
            rest+=number(o["value"])+int.from_bytes(spk[:2],"big").to_bytes(2,"little")+vb(spk[2:])+b"\0"
        rest+=number(t["lockTime"])+bytes.fromhex(t["subnetworkId"])+number(t["gas"])+vb(b"")
        return b3("TransactionV1Id",b3("PayloadDigest",bytes.fromhex(t["payload"]))+b3("TransactionRest",rest)).hex()
    assert all(txid(t)==t["id"] for t in txs), "public fixture ID parity failed"
    byid={t["id"]:t for t in txs+parents}
    continuing=[i for i,t in enumerate(txs) if len(t["inputs"])==1 and len(t["outputs"])==2 and t["payload"] and int.from_bytes(bytes.fromhex(t["payload"])[213:221],"little")>0]
    terminal=[i for i,t in enumerate(txs) if len(t["inputs"])==1 and len(t["outputs"])==1 and t["payload"] and int.from_bytes(bytes.fromhex(t["payload"])[213:221],"little")>0]
    assert continuing==[5] and terminal==[6]
    base=txs[5]
    payload=bytes.fromhex(base["payload"])
    sig=bytes.fromhex(base["inputs"][0]["signatureScript"])
    assert len(sig)==24709 and sig[:2]==b"\x4c\x80" and sig[130:133]==b"\x4d\x00\x60"
    redeem=sig[133:]
    assert len(redeem)==24576 and len(vk)==328 and redeem.count(vk)==1
    successor=redeem[:36]+payload[755:860]+b"\x75"+redeem[142:]
    def spk(script): return (b"\0\0\xaa\x20"+hashlib.blake2b(script,digest_size=32).digest()+b"\x87").hex()
    assert spk(successor)==base["outputs"][0]["scriptPublicKey"], "successor reconstruction parity"
    assert spk(redeem)==byid[base["inputs"][0]["previousOutpoint"]["transactionId"]]["outputs"][0]["scriptPublicKey"]
    vk_at=successor.index(vk)
    assert vk[224:232]==number(3) and vk[264:296]!=vk[296:328]
    changed_vk=vk[:264]+vk[296:328]+vk[264:296]
    vk_script=successor[:vk_at]+changed_vk+successor[vk_at+len(vk):]
    domain_script=bytearray(successor); domain_script[1]^=1
    assert successor[-2:]==b"\x61\x61"
    code_script=successor[:-2]+b"\x00\x75"  # OpFalse/OpDrop: balanced replacement of two NOPs.
    alt_spk=txs[0]["outputs"][1]["scriptPublicKey"]
    assert alt_spk!=base["outputs"][1]["scriptPublicKey"] and len(bytes.fromhex(alt_spk))==36
    def output_spk(index, value): return lambda t: t["outputs"][index].__setitem__("scriptPublicKey",value)
    def amount(t): t["outputs"][1]["value"]=str(int(t["outputs"][1]["value"])-1)
    def old_domain(t):
        s=bytearray.fromhex(t["inputs"][0]["signatureScript"]); s[134]^=1
        t["inputs"][0]["signatureScript"]=s.hex()
    rows=[
      ("baseline-continuing",5,None,"accept","genuine proof plus full native validation"),
      ("payout-amount",5,amount,"verify","actual continuing output1 amount; reserve output0 unchanged"),
      ("payout-script",5,output_spk(1,alt_spk),"verify","actual continuing output1 destination"),
      ("successor-vk",5,output_spk(0,spk(vk_script)),"verify","output0 script hash of successor with existing canonical IC points1/2 exchanged"),
      ("successor-domain",5,output_spk(0,spk(domain_script)),"verify","output0 script hash of successor with one domain byte changed"),
      ("successor-code",5,output_spk(0,spk(code_script)),"verify","output0 script hash of successor with balanced NOP replacement"),
      ("current-redeem-domain",5,old_domain,"p2sh","changed current redeem domain against unchanged real prior output SPK"),
      ("baseline-terminal",6,None,"accept","terminal genuine proof plus full native validation"),
      ("terminal-payout-script",6,output_spk(0,alt_spk),"verify","actual terminal output0 destination"),
    ]
    chosen=rows[:1] if phase=="baseline" else rows[1:]
    if phase=="controls":
        prior=json.loads((output/"baseline/results.json").read_text()); assert prior["complete"] and prior["passed"]
    folder=output/phase; folder.mkdir()
    results=[]
    for name, step, mutate, expected, target in chosen:
        assert time.time()<deadline-65, "20-minute deadline leaves no case budget"
        assert not (lane/"QUIET").exists(), "root quiet window; stop at case boundary"
        t=copy.deepcopy(txs[step]); original=copy.deepcopy(t)
        if mutate: mutate(t); t["id"]=txid(t)
        original_sig=bytes.fromhex(original["inputs"][0]["signatureScript"])
        candidate_sig=bytes.fromhex(t["inputs"][0]["signatureScript"])
        assert t["payload"]==original["payload"] and candidate_sig[2:130]==original_sig[2:130]
        inputs=[]
        for inp in t["inputs"]:
            point=inp["previousOutpoint"]; parent=byid[point["transactionId"]]; o=parent["outputs"][point["index"]]
            inputs.append(dict(txid=point["transactionId"],index=point["index"],amount=o["value"],spk=o["scriptPublicKey"],daa="0",is_coinbase=False))
        txfile=folder/(name+"-tx.json"); inputfile=folder/(name+"-utxos.json")
        save(txfile,t); save(inputfile,inputs)
        start=time.monotonic()
        p=subprocess.run([str(binary),"check-native",str(txfile),str(inputfile)],capture_output=True,text=True,timeout=60)
        elapsed=time.monotonic()-start
        (folder/(name+".stdout")).write_text(p.stdout); (folder/(name+".stderr")).write_text(p.stderr)
        if expected=="accept":
            accepted=json.loads(p.stdout) if p.returncode==0 else {}
            passed=p.returncode==0 and accepted.get("native_validation_passed") is True and accepted.get("chain_acceptance_verified") is False
            evidence="full-native-with-genuine-proof" if passed else "unexpected-failure"
        else:
            suffix="script ran, but verification failed" if expected=="verify" else "false stack entry at end of script execution"
            passed=p.returncode==1 and "failed to verify the signature script: "+suffix in p.stderr
            evidence="native-vm-guard-rejection" if passed else "unqualified-rejection-or-acceptance"
        result=dict(name=name,fixture_step=step,target=target,expected=expected,returncode=p.returncode,passed=passed,evidence=evidence,elapsed_seconds=elapsed,
          transaction_sha256=sha(txfile.read_bytes()),utxo_file_sha256=sha(inputfile.read_bytes()),payload_unchanged=True,proof_unchanged=True,
          proof_sha256=sha(candidate_sig[2:130]),authorization_sha256=sha(bytes.fromhex(t["payload"])[8:385]),
          child_maxrss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,stderr=p.stderr.strip(),stdout=p.stdout.strip())
        results.append(result)
        print(json.dumps({"case":name,"passed":passed,"evidence":evidence,"seconds":elapsed}),flush=True)
        if not passed: break
    passed=len(results)==len(chosen) and all(x["passed"] for x in results)
    save(folder/"results.json",dict(schema="kpi-native-guard-controls-v1",phase=phase,complete=len(results)==len(chosen),passed=passed,planned_native_case_count=9,
      proof_generation_count=0,chain_acceptance_verified=False,canonical_id_positive_parity_count=len(txs),successor_script_positive_parity=True,validator_sha256=sha(binary.read_bytes()),adapter_sha256=sha(helper.read_bytes()),cases=results))
    assert passed, "control result incomplete/unqualified; no automatic retries"
if __name__=="__main__":
    assert len(sys.argv)==3 and sys.argv[2] in ("baseline","controls")
    run(Path(sys.argv[1]).resolve(),sys.argv[2])
