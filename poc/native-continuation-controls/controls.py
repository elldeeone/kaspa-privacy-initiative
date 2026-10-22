"""Eight predeclared slots: two genuine native baselines, four mode-1 guards,
and two explicitly unexecuted admission guards lacking per-input isolation.
No new proof, parser-error credit, hidden retry, network or private inputs.
"""
import copy,hashlib,json,resource,subprocess,sys,time
from pathlib import Path

def sha(b):return hashlib.sha256(b).hexdigest()
def n(v,bits=64):return int(v).to_bytes(bits//8,"little")
def vb(b):return n(len(b))+b
def save(p,value):
    with p.open("x") as f:json.dump(value,f,indent=2);f.write("\n")

def run(lane,phase):
    root=lane/"worktree"; output=lane/"outputs"
    pins=json.loads((output/"input-pins.json").read_text())
    for rel,expected in pins["fixtures"].items():assert sha((root/rel).read_bytes())==expected,rel
    for name,expected in pins["binary_sha256"].items():assert sha((lane/"bin"/name).read_bytes())==expected,name
    sdk=root/"poc/shared-pool"
    chain=json.loads((sdk/"evidence/2026-10-20-two-input-tn10/rehearsal/chain-confirmed.json").read_text())["transactions"]
    public=[r["transaction"] for r in chain]
    old=sdk/"evidence/2026-10-20-wallet-lifecycle/positive"
    life=json.loads((old/"lineage.json").read_text()); parents=json.loads((old/"parents.json").read_text())
    vk=bytes.fromhex(json.loads((sdk/"evidence/2026-10-20-two-input-tn10/verification-key.json").read_text())["hex"])
    deadline=json.loads((output/"deadline.json").read_text())["epoch_seconds"]
    partial=public[7]; admission=life[2]
    pdata=bytes.fromhex(partial["payload"]); adata=bytes.fromhex(admission["payload"])
    assert len(partial["inputs"])==1 and len(partial["outputs"])==2 and pdata[212]==1 and int.from_bytes(pdata[213:221],"little")==211000000
    assert len(admission["inputs"])==2 and adata[212]==0
    sig=bytes.fromhex(partial["inputs"][0]["signatureScript"])
    assert len(sig)==24709 and sig[:2]==b"\x4c\x80" and sig[130:133]==b"\x4d\x00\x60"
    redeem=sig[133:]; oldstate=redeem[36:141]; newstate=pdata[755:860]
    assert oldstate[0]==newstate[0]==6
    assert int.from_bytes(newstate[1:5],"little")==int.from_bytes(oldstate[1:5],"little")+2
    assert int.from_bytes(newstate[5:9],"little")==int.from_bytes(oldstate[5:9],"little")+2
    successor=redeem[:36]+newstate+b"\x75"+redeem[142:]
    def spk(b):return(b"\0\0\xaa\x20"+hashlib.blake2b(b,digest_size=32).digest()+b"\x87").hex()
    assert spk(successor)==partial["outputs"][0]["scriptPublicKey"]
    helper=lane/"bin/kpi-native-guard-id"; validator=lane/"bin/kpi-two-input-lifecycle"
    def b3(tag,b):return bytes.fromhex(subprocess.run([str(helper),tag],input=b,capture_output=True,check=True,timeout=10).stdout.decode().strip())
    def txid(t):
        assert t["version"]==1 and t["subnetworkId"]=="00"*20 and all(o["covenant"] is None for o in t["outputs"])
        rest=n(1,16)+n(len(t["inputs"]))
        for i in t["inputs"]:
            point=i["previousOutpoint"];rest+=bytes.fromhex(point["transactionId"])+n(point["index"],32)+vb(b"")+n(i["sequence"])
        rest+=n(len(t["outputs"]))
        for o in t["outputs"]:
            s=bytes.fromhex(o["scriptPublicKey"]);rest+=n(o["value"])+int.from_bytes(s[:2],"big").to_bytes(2,"little")+vb(s[2:])+b"\0"
        rest+=n(t["lockTime"])+bytes.fromhex(t["subnetworkId"])+n(t["gas"])+vb(b"")
        return b3("TransactionV1Id",b3("PayloadDigest",bytes.fromhex(t["payload"]))+b3("TransactionRest",rest)).hex()
    assert txid(partial)==partial["id"] and txid(admission)==admission["id"]
    pmap={t["id"]:t for t in public}; amap={t["id"]:t for t in life+parents}
    vk_at=successor.index(vk)
    assert len(vk)==328 and successor.count(vk)==1 and vk[224:232]==n(3) and vk[264:296]!=vk[296:328]
    changed_vk=vk[:264]+vk[296:328]+vk[264:296]
    vk_script=successor[:vk_at]+changed_vk+successor[vk_at+len(vk):]
    assert successor[-2:]==b"\x61\x61"
    code_script=successor[:-2]+b"\0\x75"
    alternate=public[1]["outputs"][1]["scriptPublicKey"]
    assert len(bytes.fromhex(alternate))==36 and alternate!=partial["outputs"][1]["scriptPublicKey"]
    def change_spk(index,value):return lambda t:t["outputs"][index].__setitem__("scriptPublicKey",value)
    def change_amount(t):t["outputs"][1]["value"]=str(int(t["outputs"][1]["value"])-1)
    cases=[
        ("mode1-baseline",partial,pmap,None,"accept","full native valid partial payout with two CM appends"),
        ("admission-baseline",admission,amap,None,"accept","full native valid two-input admission"),
        ("mode1-payout-amount",partial,pmap,change_amount,"verify","actual payout output1 amount; CM/state/auth unchanged"),
        ("mode1-payout-script",partial,pmap,change_spk(1,alternate),"verify","actual payout output1 script; CM/state/auth unchanged"),
        ("mode1-successor-vk",partial,pmap,change_spk(0,spk(vk_script)),"verify","successor commitment retains new CM state but changes embedded VK IC order"),
        ("mode1-successor-code",partial,pmap,change_spk(0,spk(code_script)),"verify","successor commitment retains new CM state but replaces two NOPs with OpFalse/OpDrop"),
    ]
    skipped=[dict(name="admission-successor-vk",status="NOT_EXECUTED",reason="No existing verified per-input native adapter. Output mutation also invalidates depositor signature; direct full validator uses parallel multi-input verification."),dict(name="admission-successor-code",status="NOT_EXECUTED",reason="Same admission attribution blocker. No broad native helper build or fresh proof was attempted.")]
    if phase=="baselines":
        save(output/"PLAN.json",dict(planned_slots=8,planned_native_executions=6,slots=[dict(name=c[0],expected=c[4],target=c[5]) for c in cases]+skipped,admission_isolation_decision="baseline only; two mutations not executed",proof_generation_count=0))
        selected=cases[:2]
    else:
        prior=json.loads((output/"baselines/results.json").read_text());assert prior["complete"] and prior["passed"]
        selected=cases[2:]
    folder=output/phase;folder.mkdir();results=[]
    for name,original,parents_by_id,mutate,expected,target in selected:
        assert time.time()<deadline-65,"absolute20min deadline"
        assert not(lane/"QUIET").exists(),"root quiet window; stop at case boundary"
        t=copy.deepcopy(original)
        if mutate:mutate(t);t["id"]=txid(t)
        proof=bytes.fromhex(t["inputs"][0]["signatureScript"])[2:130]
        assert t["payload"]==original["payload"] and t["inputs"]==original["inputs"] and t["storageMass"]==original["storageMass"]
        entries=[]
        for i in t["inputs"]:
            point=i["previousOutpoint"];parent=parents_by_id[point["transactionId"]];o=parent["outputs"][point["index"]]
            entries.append(dict(txid=point["transactionId"],index=point["index"],amount=o["value"],spk=o["scriptPublicKey"],daa="0",is_coinbase=False))
        txfile=folder/(name+"-tx.json");ufile=folder/(name+"-utxos.json");save(txfile,t);save(ufile,entries)
        start=time.monotonic();p=subprocess.run([str(validator),"check-native",str(txfile),str(ufile)],capture_output=True,text=True,timeout=60);elapsed=time.monotonic()-start
        (folder/(name+".stdout")).write_text(p.stdout);(folder/(name+".stderr")).write_text(p.stderr)
        if expected=="accept":
            value=json.loads(p.stdout) if p.returncode==0 else {}
            passed=p.returncode==0 and value.get("native_validation_passed") is True and value.get("chain_acceptance_verified") is False
            evidence="full-native-with-genuine-proof" if passed else "unexpected-baseline-failure"
        else:
            passed=p.returncode==1 and "failed to verify the signature script: script ran, but verification failed" in p.stderr
            evidence="native-vm-guard-rejection" if passed else "unqualified-rejection-or-acceptance"
        result=dict(name=name,target=target,expected=expected,passed=passed,evidence=evidence,returncode=p.returncode,elapsed_seconds=elapsed,
          transaction_sha256=sha(txfile.read_bytes()),utxo_file_sha256=sha(ufile.read_bytes()),proof_sha256=sha(proof),authorization_sha256=sha(bytes.fromhex(t["payload"])[8:385]),
          inputs_and_proof_unchanged=True,payload_and_state_witness_unchanged=True,storage_mass_unchanged=True,child_maxrss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,stdout=p.stdout.strip(),stderr=p.stderr.strip())
        results.append(result);print(json.dumps({"case":name,"passed":passed,"evidence":evidence,"seconds":elapsed}),flush=True)
        if not passed:break
    passed=len(results)==len(selected) and all(r["passed"] for r in results)
    save(folder/"results.json",dict(schema="kpi-continuation-admission-v1",phase=phase,planned_slots=8,planned_native_executions=6,executed_in_phase=len(results),complete=len(results)==len(selected),passed=passed,cases=results,not_executed=skipped,proofs_generated=0,chain_acceptance_verified=False,positive_id_parity_count=2,mode1_appends_two_cms=True))
    assert passed,"unqualified case or incomplete execution; no retries"
if __name__=="__main__":
    assert len(sys.argv)==3 and sys.argv[2] in("baselines","controls")
    run(Path(sys.argv[1]).resolve(),sys.argv[2])
