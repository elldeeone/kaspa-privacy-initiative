"""Finite signed new-union controls; preparation only, NEVER native execution.

Imports the selected NEW lifecycle fixture constructors and receive-V2 model.
Those are producers, not independent oracles. Inputs/secrets are deliberately
public DO_NOT_FUND. No node, wallet state, old artifact or network interface.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "poc/future-lifecycle"))
import assemble as a

MAX = 2_870_000_000_000_000_000
CLASS = "PUBLIC_SYNTHETIC_DO_NOT_FUND"


def save(path, value):
    path = Path(path)
    if path.exists():
        raise ValueError("refuse overwrite: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def load(path):
    return json.loads(Path(path).read_text())


def pin(path):
    path = Path(path).resolve()
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def replace_hex(value, offset, data):
    raw = bytearray.fromhex(value)
    raw[offset:offset + len(data)] = data
    return raw.hex()


def flip_hex(value, offset):
    raw = bytearray.fromhex(value)
    raw[offset] ^= 1
    return raw.hex()


def p2sh(redeem):
    return "0000aa20" + hashlib.blake2b(redeem, digest_size=32).hexdigest() + "87"


def current_state(case, replacement):
    """Replace supplied current policy's state; explicitly no lineage claim."""
    witness = bytearray.fromhex(case["transaction"]["inputs"][0]["signatureScript"])
    witness[201:313] = replacement
    case["transaction"]["inputs"][0]["signatureScript"] = witness.hex()
    case["entries"][0]["scriptPublicKey"] = p2sh(witness[199:])


def counterfactual_equality(snapshot, nf):
    """Current authenticated occupied equality, not an old insertion witness.

    Remaining update/append bytes are computed against the same path, although
    strict pred.value < NF MUST reject before they could be applied.
    """
    matches = [(i, e) for i, e in enumerate(snapshot.nullifiers) if e.value == nf]
    if len(matches) != 1:
        raise ValueError("expected one currently spent NF")
    i, pred = matches[0]
    _, tree = snapshot.roots()
    m = len(snapshot.nullifiers)
    changed = a.NFEntry(pred.value, nf, m)
    intermediate = tree.with_leaf(i, changed.leaf())
    witness = (a.u32(i) + pred.value + pred.next_value + a.u32(pred.next_index)
               + b"".join(tree.path(i)) + b"".join(intermediate.path(m)))
    entries = list(snapshot.nullifiers)
    entries[i] = changed
    entries.append(a.NFEntry(nf, pred.next_value, pred.next_index))
    after = a.Snapshot(list(snapshot.deliveries), entries)
    return witness, intermediate.root, after


def counterfactual_following_insert(snapshot, nf):
    """Compute slot1 after the impossible slot0 equality, for diagnostics only.

    The duplicate equality history is already invalid and will be rejected.
    Choose the remaining genuine strict interval rather than a duplicate's
    self-link; authenticate its actual physical index and both paths.
    """
    value = int.from_bytes(nf,"little")
    options=[(i,e) for i,e in enumerate(snapshot.nullifiers)
        if int.from_bytes(e.value,"little")<value
        and (e.next_value==a.ZERO or value<int.from_bytes(e.next_value,"little"))]
    i,pred=max(options,key=lambda pair:int.from_bytes(pair[1].value,"little"))
    _,tree=snapshot.roots();m=len(snapshot.nullifiers)
    middle=tree.with_leaf(i,a.NFEntry(pred.value,nf,m).leaf())
    witness=(a.u32(i)+pred.value+pred.next_value+a.u32(pred.next_index)
        +b"".join(tree.path(i))+b"".join(middle.path(m)))
    entries=list(snapshot.nullifiers);entries[i]=a.NFEntry(pred.value,nf,m)
    entries.append(a.NFEntry(nf,pred.next_value,pred.next_index))
    return a.Snapshot(list(snapshot.deliveries),entries),witness


def reveal_vector(receiver, position, snapshot, previous, reserve, fee, vk, spent=False):
    note = receiver.open(snapshot.deliveries[position].ciphertext)
    nf = receiver.nullifier(note, position)
    cm, _ = snapshot.roots()
    if spent:
        witness, middle, after = counterfactual_equality(snapshot, nf)
        new_root = after.roots()[1].root
    else:
        after, witness = a.insert(snapshot, nf)
        pred_index = int.from_bytes(witness[:4], "little")
        pred = snapshot.nullifiers[pred_index]
        middle = snapshot.roots()[1].with_leaf(pred_index,
            a.NFEntry(pred.value, nf, len(snapshot.nullifiers)).leaf()).root
        new_root = after.roots()[1].root
    payload = (b"KPX2RV01\x01" + note.owner + note.incoming
        + a.u64(note.value_sompi) + note.rho + receiver.keys(note.index).nf_secret
        + note.native_pk + a.u32(position) + note.key_commitment + note.commitment()
        + b"".join(cm.path(position)) + witness + nf + middle + new_root
        + a.u64(fee) + a.u64(note.value_sompi - fee))
    if len(payload) != 2029:
        raise ValueError("reveal payload width")
    return {"state_hex": a.state(snapshot).hex(),
        "previous_txid_raw_hex": previous[:32].hex(),
        "previous_index": int.from_bytes(previous[32:], "little"),
        "reserve_sompi": reserve, "payload_hex": payload.hex(),
        "native_secret_hex": receiver.keys(note.index).native_secret.hex(), "vk_hex": vk}, after


class Producer:
    def __init__(self, args):
        self.args = args
        self.out = args.output
        self.cases = []

    def construct(self, name, mode, vector):
        directory = self.out / "bodies" / name
        inp = self.out / "vectors" / (name + ".json")
        save(inp, vector)
        result = subprocess.run([str(self.args.native), mode, str(inp), str(directory)],
            text=True, capture_output=True, check=False)
        save(directory / "preparation-command.json", {"mode": mode,
            "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
            "native_VM_or_Full_executed": False})
        if result.returncode:
            raise ValueError("preparation failed, preserved: " + name)
        return load(directory / "validation-case.json"), directory

    def control(self, name, base, mutate, expected, cause, signer=None,
                supplied=False, common=False, sighash=1):
        case = copy.deepcopy(base)
        mutate(case)
        if signer:
            vector = {"case": case, "input_index": 0 if common else 1,
                "public_development_secret_hex": signer, "sighash_type": sighash,
                "common_reveal_witness": common}
            _, directory = self.construct(name, "control-resign-freeze", vector)
        else:
            _, directory = self.construct(name, "control-normalize-freeze", case)
        self.record(name, directory, expected, cause, supplied)

    def record(self, name, directory, expected, cause, supplied=False):
        self.cases.append({"case_id": name, "classification": CLASS,
            "validation_case": pin(directory / "validation-case.json"),
            "transaction": pin(directory / "transaction.json"),
            "supplied_context": pin(directory / "supplied-context.json"),
            "expected_per_input": expected, "expected_Full_accepted": all(x == "ACCEPT" for x in expected),
            "intended_cause": cause, "supplied_context_only": supplied,
            "no_changed_Auth_proof_validity_claim": True})


def prepare(args):
    if args.output.exists():
        raise ValueError("fresh control identity required")
    if not (args.prepared / "MATERIALIZED.json").is_file():
        raise ValueError("materialization is not sealed")
    args.output.mkdir(parents=True)
    p = Producer(args)
    private = load(args.prepared / "private-native-vector.json")
    proof = (args.proof / "proof128.bin").read_bytes()
    if len(proof) != 128 or not any(proof):
        raise ValueError("genuine nonzero proof128 required")
    report = load(args.proof / "report.json")
    if (report.get("genuine_Groth16_verified") is not True
            or report["proof_hex128"] != proof.hex()
            or report["vk_hex328"] != private["vk_hex"]
            or report["fixture_sha256"] != pin(args.prepared / "private-fixture.json")["sha256"]):
        raise ValueError("genuine proof report mismatch")
    private["proof_hex"] = proof.hex()
    base_private, private_dir = p.construct("base-private-genuine", "private-freeze", private)
    admit = load(args.prepared / "admit-native-vector.json")
    base_admit = load(args.prepared / "admit-final/validation-case.json")
    funder = admit["funding_secret_hex"]
    wrong = a.public_seed("CONTROL_WRONG_SIGNER_DO_NOT_FUND").hex()
    def pl(c, o, data):
        c["transaction"]["payload"] = replace_hex(c["transaction"]["payload"], o, data)
    def pf(c, o):
        c["transaction"]["payload"] = flip_hex(c["transaction"]["payload"], o)
    def af(name, mutate, cause, base=base_admit, supplied=False):
        p.control(name, base, mutate, ["VerifyError", "ACCEPT"], cause, funder, supplied)

    p.control("admit-valid-NONE2-funding", base_admit, lambda c: None,
        ["VerifyError", "ACCEPT"], "actual NONE2 signature; exact ALL guard", funder, sighash=2)
    def corrupt(c):
        c["transaction"]["inputs"][1]["signatureScript"] = flip_hex(
            c["transaction"]["inputs"][1]["signatureScript"], 10)
    p.control("admit-corrupt-funding-signature", base_admit, corrupt,
        ["ACCEPT", "NullFail"], "pool checks cannot authorize the other input")
    p.control("admit-wrong-funding-key", base_admit, lambda c: None,
        ["ACCEPT", "NullFail"], "valid signature under wrong secret with original SPK", wrong)
    af("admit-declared-fee-plus1", lambda c: pl(c,1160,a.u64(int.from_bytes(bytes.fromhex(c["transaction"]["payload"])[1160:1168],"little")+1)), "exact E=V+fee+C")
    af("admit-reserve-output-minus1", lambda c: c["transaction"]["outputs"][0].update(value=c["transaction"]["outputs"][0]["value"]-1), "exact Rprime=R+V")
    for name, offset in [("note-rho",112),("note-nativePK",176),("CM",208),
                         ("ciphertext",240),("CM-append-path",536),("next-CMroot",1088),
                         ("next-NFroot",1124),("singleton-G-rho",1248)]:
        af("admit-"+name, lambda c,o=offset: pf(c,o), "specific admission "+name+" binding")
    af("admit-singleton-G-missing", lambda c: pl(c,1176,bytes(168)), "n1/m1 singleton opening mandatory")
    af("admit-singleton-G-wrong-value", lambda c: pl(c,1240,a.u64(60_000_001)), "singleton G.V equals actual R")
    for name, offset, value in [("V-zero",104,0),("V-below-floor",104,59_999_999),
        ("V-above-MAX",104,MAX+1),("fee-zero",1160,0),("change-above-MAX",1168,MAX+1)]:
        af("admit-range-"+name, lambda c,o=offset,v=value: pl(c,o,a.u64(v)), "declared bounded integer "+name)
    af("admit-actual-R-above-MAX", lambda c: c["entries"][0].update(amount=MAX+1), "actual reserve bound before equations", supplied=True)
    af("admit-actual-R-plus-E-above-MAX", lambda c: c["entries"][1].update(amount=MAX), "combined actual inputs bounded before equations", supplied=True)

    # Positive admission change branch, independent of the selected C0 route.
    changed = copy.deepcopy(admit)
    payload = bytearray.fromhex(changed["payload_hex"])
    changed["funding_amount_sompi"] += 100_000_000
    payload[1168:1176] = a.u64(100_000_000)
    changed["payload_hex"] = payload.hex()
    base_change, directory = p.construct("admit-positive-change", "admit-freeze", changed)
    p.record("admit-positive-change",directory,["ACCEPT","ACCEPT"],"same-key positive change path",True)
    af("admit-change-value-minus1",lambda c:c["transaction"]["outputs"][1].update(value=99_999_999),"declared exact change amount",base_change,True)
    # Redirect to the founding key, known distinct from the admission key.
    otherpk = load(args.prepared/"founding-final/transaction.json")["outputs"][1]["scriptPublicKey"]
    af("admit-change-wrong-key",lambda c:c["transaction"]["outputs"][1].update(scriptPublicKey=otherpk),"change exact original funding SPK",base_change,True)

    backups = load(args.prepared / "PUBLIC-SYNTHETIC-backups.json")
    crypto = a.Crypto(args.crypto)
    wallets = {label:a.Receiver(bytes.fromhex(backups["backups"][label]["seed32"]),a.DOMAIN,crypto)
               for label in ("Alice","Bob","Charlie")}
    records = load(args.prepared / "records.json")
    before = a.parse_snapshot(records["before-private"])
    after = a.parse_snapshot(records["after-private"])
    previous = a.outpoint(private_dir)
    rv, after_bob = reveal_vector(wallets["Bob"],2,after,previous,2_000_000_000,10_000_000,private["vk_hex"])
    base_reveal, reveal_dir = p.construct("base-reveal-Bob-continuing", "reveal-freeze",rv)
    rvterminal,_ = reveal_vector(wallets["Charlie"],3,after_bob,a.outpoint(reveal_dir),1_000_000_000,10_000_000,private["vk_hex"])
    _,directory = p.construct("reveal-Charlie-terminal", "reveal-freeze",rvterminal)
    p.record("reveal-Charlie-terminal",directory,["ACCEPT"],"conditional R=V full consumption")
    # Reversed recipient exit order, same genuine private output.
    reverse, after_charlie = reveal_vector(wallets["Charlie"],3,after,previous,2_000_000_000,10_000_000,private["vk_hex"])
    _,revdir=p.construct("reveal-Charlie-first", "reveal-freeze",reverse)
    p.record("reveal-Charlie-first",revdir,["ACCEPT"],"reversed independent recipient order")
    reverse2,_=reveal_vector(wallets["Bob"],2,after_charlie,a.outpoint(revdir),1_000_000_000,10_000_000,private["vk_hex"])
    _,revdir2=p.construct("reveal-Bob-terminal", "reveal-freeze",reverse2)
    p.record("reveal-Bob-terminal",revdir2,["ACCEPT"],"reversed terminal recipient")
    bobkey=rv["native_secret_hex"]
    def rf(name,mutate,cause,expected="VerifyError",base=base_reveal,supplied=False):
        p.control(name,base,mutate,[expected],cause,bobkey,supplied,True)
    p.control("reveal-valid-NONE2",base_reveal,lambda c:None,["VerifyError"],"actual NONE2 exact-ALL guard",bobkey,common=True,sighash=2)
    p.control("reveal-wrong-signer",base_reveal,lambda c:None,["NullFail"],"wrong signing secret; original CM/nativePK",wrong,common=True)
    rf("reveal-wrong-payout-key",lambda c:c["transaction"]["outputs"][1].update(scriptPublicKey=otherpk),"canonical CM-bound payout key")
    rf("reveal-actual-payout-minus1",lambda c:c["transaction"]["outputs"][1].update(value=c["transaction"]["outputs"][1]["value"]-1),"actual payout equals declared P")
    rf("reveal-declared-fee-plus1",lambda c:pl(c,2013,a.u64(10_000_001)),"whole note V=P+fee")
    rf("reveal-actual-R-above-MAX",lambda c:c["entries"][0].update(amount=MAX+1),"actual R upper range",supplied=True)
    def small_remainder(c):
        c["entries"][0]["amount"]=1_059_999_999
        c["transaction"]["outputs"][0]["value"]=59_999_999
    rf("reveal-remainder-below-floor",small_remainder,"continuing R-V>=60M",supplied=True)

    def priv(name,mutate,cause,supplied=False):
        p.control(name,base_private,mutate,["VerifyError"],cause,supplied=supplied)
    priv("private-actual-outpoint",lambda c:c["transaction"]["inputs"][0]["previousOutpoint"].update(index=1),"actual outpoint binds Auth")
    priv("private-actual-R",lambda c:c["entries"][0].update(amount=c["entries"][0]["amount"]+1),"actual R binds Auth",True)
    for name,offset in [("NF-predpath",1084),("NF-append-path",1628),("CM-append-path",3332),("ciphertext",484)]:
        priv("private-"+name,lambda c,o=offset:pf(c,o),"native "+name+" before Groth16")
    priv("private-next-CMroot",lambda c:pf(c,404),"proposed CMroot bound to actual append")
    def wrong_successor(c,vk=False):
        witness=bytes.fromhex(c["transaction"]["inputs"][0]["signatureScript"])
        redeem=bytearray(witness[199:])
        redeem[2:114]=bytes.fromhex(c["transaction"]["payload"])[364:476]
        at=redeem.find(bytes.fromhex(private["vk_hex"])) if vk else len(redeem)-1
        if at<114:raise ValueError("cannot find immutable VK")
        redeem[at]^=1
        c["transaction"]["outputs"][0]["scriptPublicKey"]=p2sh(redeem)
    priv("private-successor-VK-change",lambda c:wrong_successor(c,True),"immutable VK in successor policy")
    priv("private-successor-code-change",wrong_successor,"immutable code suffix in successor policy")
    def changed_statement(c):
        pf(c,484)
        raw=bytes.fromhex(c["transaction"]["payload"])
        pl(c,332,a.h(raw[484:1012]))
    p.control("private-genuine-proof-wrong-transcript",base_private,changed_statement,
        ['ZkIntegrity("Groth16 verification failed")'],"genuine valid-curve proof, native-consistent changed cipher transcript")

    for name,n,m in [("n-zero",0,1),("n-over-cap",65536,1),("m-zero",2,0),
        ("m-over-cap",65535,131072),("m-over-profile",2,6),("private-CM-full",65534,1)]:
        def mutate(c,n=n,m=m):
            old=bytearray.fromhex(private["auth_hex"])[76:188]
            old[72:76]=a.u32(n);old[108:112]=a.u32(m)
            current_state(c,old);pl(c,76,old)
        priv("count-"+name,mutate,"explicit current/private successor count guard",True)
    def admitfull(c):
        old=bytearray.fromhex(admit["state_hex"]);old[72:76]=a.u32(65535)
        current_state(c,old)
    af("count-admit-CM-full",admitfull,"n+1 cap before append",supplied=True)
    def revealmax(c):
        old=bytearray.fromhex(rv["state_hex"]);old[108:112]=a.u32(9)
        current_state(c,old)
    rf("count-reveal-profile-full",revealmax,"m+1<=2n+1 before NF path",supplied=True)

    # Later admission must use Gzero; construct a genuinely coherent public
    # later state and correct current empty path, then vary only G.
    invoice=wallets["Alice"].invoice(2)
    note=a.Receipt.for_invoice(invoice,60_000_000,a.h(b"PUBLIC_CONTROL_LATER_ADMIT"))
    record=a.Delivery(4,note.commitment(),crypto.seal(invoice.delivery_pk,note.encode()))
    later=a.Snapshot(list(after.deliveries)+[record],list(after.nullifiers))
    payload=a.admit_payload(wallets["Alice"].open(before.deliveries[0].ciphertext),note,record,after,later,10_000_000,0)
    payload=payload[:1176]+bytes(168)
    later_vector={**admit,"state_hex":a.state(after).hex(),"previous_txid_raw_hex":previous[:32].hex(),
        "reserve_sompi":2_000_000_000,"payload_hex":payload.hex(),"funding_amount_sompi":70_000_000}
    later_case,directory=p.construct("admit-later-Gzero-positive","admit-freeze",later_vector)
    p.record("admit-later-Gzero-positive",directory,["ACCEPT","ACCEPT"],"later current path and Gzero",True)
    af("admit-later-G-nonzero",lambda c:pl(c,1176,bytes.fromhex(admit["payload_hex"])[1176:1344]),"later G must be zero",later_case,True)

    # Exact CURRENT spent equality with current CM membership, both directions.
    spent,_=reveal_vector(wallets["Alice"],0,after,previous,2_000_000_000,10_000_000,private["vk_hex"],spent=True)
    spent_case,directory=p.construct("private-then-reveal-current-equality","reveal-freeze",spent)
    p.record("private-then-reveal-current-equality",directory,["VerifyError"],"authenticated current spent NF: pred.value==NF")
    alicekey=spent["native_secret_hex"]
    p.control("private-then-reveal-current-path-corrupt",spent_case,lambda c:pf(c,829),["VerifyError"],"current predecessor authentication",alicekey,common=True)
    # Companion old insertion path against actual current NF root.
    original_nf=bytes.fromhex(private["public_witness_hex"])[:1160]
    p.control("private-then-reveal-stale-NF-path",spent_case,lambda c:pl(c,757,original_nf),["VerifyError"],"old predecessor root is stale",alicekey,common=True)
    first,first_after=reveal_vector(wallets["Alice"],0,before,a.outpoint(args.prepared/"admit-final"),
        int.from_bytes(bytes.fromhex(private["auth_hex"])[188:196],"little"),10_000_000,private["vk_hex"])
    first_case,first_dir=p.construct("base-Alice-reveal-before-private","reveal-freeze",first)
    p.record("base-Alice-reveal-before-private",first_dir,["ACCEPT"],"alternative valid first spend")
    nf=bytes.fromhex(private["auth_hex"])[204:236]
    equality,_,fake_after=counterfactual_equality(first_after,nf)
    # The equality is the sole impossible operation; still derive subsequent
    # path/root bytes on that counterfactual intermediate tree for diagnosis.
    nf1=bytes.fromhex(private["auth_hex"])[236:268]
    final_nf,second=counterfactual_following_insert(fake_after,nf1)
    losing=copy.deepcopy(private)
    raw=bytearray.fromhex(losing["auth_hex"])
    raw[40:76]=a.outpoint(first_dir)
    raw[76:188]=a.state(first_after)
    reserve=int.from_bytes(raw[188:196],"little")-60_000_000
    fee=int.from_bytes(raw[196:204],"little")
    raw[188:196]=a.u64(reserve)
    next_state=bytearray(raw[364:476]);next_state[76:108]=final_nf.roots()[1].root
    next_state[108:112]=a.u32(len(final_nf.nullifiers))
    raw[364:476]=next_state;raw[476:484]=a.u64(reserve-fee)
    losing["auth_hex"]=raw.hex()
    losing["public_witness_hex"]=(equality+second+bytes.fromhex(private["public_witness_hex"])[2320:]).hex()
    losing_case,directory=p.construct("reveal-then-private-current-equality","private-freeze",losing)
    p.record("reveal-then-private-current-equality",directory,["VerifyError"],"current occupied original NF before Groth16; changed Auth has no valid-proof claim")
    p.control("reveal-then-private-current-path-corrupt",losing_case,lambda c:pf(c,1084),["VerifyError"],"current occupied predecessor authentication")

    source_files=[Path(__file__),REPO/"poc/future-lifecycle/assemble.py",
        REPO/"poc/future-recipient/v2/recipient.py",args.native,
        args.prepared/"MATERIALIZED.json",args.proof/"proof128.bin",args.proof/"report.json"]
    save(args.output/"EXPECTED.json",{"classification":CLASS,"native_VM_or_Full_executed":False,
        "case_count":len(p.cases),"source_pins":[pin(f) for f in source_files],"cases":p.cases,
        "proof_control_plan_addendum":"Original planned A-point negation replaced prospectively by byte-identical genuine proof against altered cipher+rehashed Auth, all native public checks consistent. Exact expected Groth16 verification failure unchanged.",
        "limitations":["All state/UTXOs synthetic; no chain acceptance","All current-state count mutations explicitly supplied-only","Alternate positive admission controls do not enter primary fee denominator","No private proof is claimed valid for altered Auth in early native controls"]})
    print(json.dumps({"cases":len(p.cases),"output":str(args.output),"native_executed":False}))


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    for name in ("prepared","proof","native","crypto","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    prepare(parser.parse_args())
