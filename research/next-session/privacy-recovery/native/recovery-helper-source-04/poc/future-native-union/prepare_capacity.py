"""Construct one 17th-bit NF append context, not a historical proof/VM run.

21845 one-real/one-dummy splits create a positive spine and60M leaf each;
21845 later leaf reveals leave one60M spine. n43691,m65536,U1.
Every CM, real/dummy NF and physical insertion index is derived, not random.
The history is algebraic synthetic construction; no accepted transactions,
historical proofs, relay fees or archive availability are claimed.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import hmac
import json
from pathlib import Path
import prepare_controls as c

a = c.a
SPLITS = 21845
FLOOR = 60_000_000


def prepare(args):
    if args.output.exists():
        raise ValueError("fresh output required")
    args.output.mkdir(parents=True)
    producer = c.Producer(args)
    crypto = a.Crypto(args.crypto)
    backups = c.load(args.prepared / "PUBLIC-SYNTHETIC-backups.json")
    receiver = a.Receiver(bytes.fromhex(backups["backups"]["Bob"]["seed32"]),a.DOMAIN,crypto)
    invoice = receiver.invoice(0)
    initial = (SPLITS+1)*FLOOR+SPLITS
    dummy_key = a.public_seed("CAPACITY_PUBLIC_DUMMY_KEY_DO_NOT_FUND")
    notes=[]
    deliveries=[]
    def append(value):
        pos=len(notes)
        rho=a.h(b"PUBLIC_CAPACITY_NOTE_DO_NOT_FUND",a.u32(pos))
        note=a.Receipt.for_invoice(invoice,value,rho)
        notes.append(note)
        deliveries.append(a.Delivery(pos,note.commitment(),bytes(264)))
        return pos
    append(initial)
    sources=[]
    values=[a.ZERO]
    spine=0
    for j in range(SPLITS):
        real=receiver.nullifier(notes[spine],spine)
        seed=a.h(b"PUBLIC_CAPACITY_DUMMY_SEED_DO_NOT_FUND",a.u32(j))
        dummy=hmac.new(dummy_key,b"KPX2DMY\0"+a.DOMAIN+seed+b"\x01",hashlib.sha256).digest()
        values.extend((real,dummy))
        sources.extend(({"kind":"private-real","split":j,"position":spine},
                        {"kind":"private-dummy-slot1","split":j,"dummy_seed":seed.hex()}))
        remaining=notes[spine].value_sompi-FLOOR-1
        spine=append(remaining)
        append(FLOOR)
    for j in range(SPLITS):
        position=2*j+2
        values.append(receiver.nullifier(notes[position],position))
        sources.append({"kind":"revealed-leaf","position":position})
    if len(values)!=65536 or len(notes)!=43691 or notes[spine].value_sompi!=FLOOR:
        raise ValueError("capacity construction arithmetic")
    if len(set(values))!=len(values) or values.count(a.ZERO)!=1:
        raise ValueError("unexpected NF collision/zero")
    # Physical indices equal actual append order above. Final linked successors
    # are derived by value ordering, never by reassigning physical leaf indices.
    ordered=sorted(range(len(values)),key=lambda i:int.from_bytes(values[i],"little"))
    successor={ordered[j]:ordered[j+1] for j in range(len(ordered)-1)}
    entries=[a.NFEntry(value,values[successor[i]] if i in successor else a.ZERO,
                       successor.get(i,0)) for i,value in enumerate(values)]
    # Only the remaining note needs a real recoverable current receipt for this
    # single actual native exit. Historical cipher bytes are explicitly fixtures.
    deliveries[spine]=a.Delivery(spine,notes[spine].commitment(),crypto.seal(invoice.delivery_pk,notes[spine].encode()))
    snapshot=a.Snapshot(deliveries,entries)
    cm,nf=snapshot.roots()
    current_nf=receiver.nullifier(notes[spine],spine)
    if current_nf in values:
        raise ValueError("remaining spine already spent")
    reserve=initial-SPLITS-SPLITS*FLOOR
    if reserve!=FLOOR:
        raise ValueError("complete remaining liability arithmetic")
    history={"classification":c.CLASS,"historical_proofs_or_chain_acceptance":False,
        "note_template_hex168":notes[spine].note_bytes().hex(),
        "notes":[{"position":i,"value_sompi":n.value_sompi,"rho":n.rho.hex(),"CM":n.commitment().hex()}
                  for i,n in enumerate(notes)],
        "NF_physical_records":[{"index":i,"value":e.value.hex(),"next_value":e.next_value.hex(),
            "next_index":e.next_index,"source":{"kind":"sentinel"} if i==0 else sources[i-1]}
            for i,e in enumerate(entries)]}
    raw=(json.dumps(history,separators=(",",":"),sort_keys=True)+"\n").encode()
    (args.output/"derived-history.json.gz").write_bytes(gzip.compress(raw,mtime=0))
    keys=receiver.keys(0)
    c.save(args.output/"CAPACITY-PLAN-AND-PROVENANCE.json",{
        "classification":c.CLASS,"private_splits":SPLITS,"later_leaf_reveals":SPLITS,
        "n":len(notes),"m":len(values),"unspent_positive_notes":1,
        "remaining_position":spine,"next_NF_append_index":65536,
        "initial_reserve":initial,"historical_private_fee_each":1,
        "historical_reveal_fee_each":1,"final_reserve_and_liability":reserve,
        "ghost_C":len(notes),"ghost_U":1,
        "ghost_inequality_m_minus1_le_2C_minus2U":len(values)-1<=2*(len(notes)-1),
        "complete_value_algebra":"initial -21845 private fees -21845 full60M leaves =60M",
        "current_CMroot":cm.root.hex(),"current_NFroot":nf.root.hex(),
        "public_development_s":keys.owner_secret.hex(),"public_development_k":keys.nf_secret.hex(),
        "dummy_key":dummy_key.hex(),"derived_history":c.pin(args.output/"derived-history.json.gz"),
        "historical_proofs_or_native_execution":False,
        "limitations":["Algebraically constructible synthetic history, no historical proofs/accepted lineage",
            "Historical one-sompi fees are consensus-conservation examples, not relay-affordable transactions",
            "Historical ciphertexts are zero placeholders; independent archive/recovery not established",
            "Descriptor reused for all notes; no privacy qualification"]})
    vk=c.load(args.prepared/"private-native-vector.json")["vk_hex"]
    previous=a.public_seed("CAPACITY_CURRENT_SUPPLIED_OUTPOINT_DO_NOT_FUND")+a.u32(0)
    fee=1
    quotes=[]
    for attempt in range(256):
        vector,_=c.reveal_vector(receiver,spine,snapshot,previous,reserve,fee,vk)
        case,directory=producer.construct(f"capacity-quote-{attempt:03d}","reveal-freeze",vector)
        metrics=c.load(directory/"metrics.json")
        required=500*metrics["mining_mass"]
        quotes.append({"fee":fee,"required500":required,"mining_mass":metrics["mining_mass"]})
        if fee>=required:
            break
        fee=max(fee,required)
        if fee>50_000_000:
            raise ValueError("frozen60M/10M affordability target failed")
    else:
        raise ValueError("capacity fee iteration incomplete")
    producer.record("capacity-append65536-terminal",directory,["ACCEPT"],
                    "conditional sole60M liability, actual17th-bit indexed NF append",True)
    producer.control("capacity-append-top-sibling-corrupt",case,
        lambda x:x["transaction"].update(payload=c.flip_hex(x["transaction"]["payload"],1373+16*32)),
        ["VerifyError"],"17th-level append authentication after valid current predecessor",
        vector["native_secret_hex"],True,True)
    c.save(args.output/"EXPECTED.json",{"classification":c.CLASS,"native_VM_or_Full_executed":False,
        "cases":producer.cases,"case_count":len(producer.cases),"fee500_fixedpoint":quotes,
        "source_pins":[c.pin(Path(__file__)),c.pin(Path(c.__file__)),c.pin(args.native),
            c.pin(Path(a.__file__)),c.pin(REPO/"poc/future-recipient/v2/recipient.py")],
        "historical_native_runs":0})
    print(json.dumps({"cases":len(producer.cases),"fee500":fee,"payout":FLOOR-fee,
                      "n":len(notes),"m":len(values),"native_executed":False}))


REPO=a.REPO
if __name__=="__main__":
    parser=argparse.ArgumentParser()
    for name in ("prepared","native","crypto","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    prepare(parser.parse_args())
