#!/usr/bin/env python3
"""One isolated seed-only owner approves its exact GN3 funding input."""
import argparse
import os
from pathlib import Path
import stat

from gn3 import approval_digest, record, validate_genesis
from gn3_common import (digest, encoded, fields, hx, need, parse, public_bytes,
                        reference, regular, uint, uuid_text, write_new)
from gn3_entry import APPROVAL_NAMES
from gn3_runtime import Runtime, SDK_PINS
from gn3_selection import load

INITIAL_FIELDS={'schema','domain_hex32','output_hex520','admission_sompi','funding_spk_hex36'}
BACKUP_FIELDS={'schema','domain_hex32','seed_hex32'}


def private_read(path):
    path, info = regular(path)
    need(stat.S_IMODE(info.st_mode) in (0o400,0o600) and info.st_nlink == 1,
         'single-original-private-file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
        expected=tuple(getattr(info,key) for key in keys)
        need(tuple(getattr(os.fstat(fd),key) for key in keys)==expected,'original-swapped-before-read')
        with os.fdopen(os.dup(fd),'rb') as source:raw=source.read()
        need(tuple(getattr(os.fstat(fd),key) for key in keys)==expected and len(raw)==info.st_size,
             'original-mutated-during-read')
        return raw
    finally:os.close(fd)


def run(a):
    uuid_text(a.trial_id)
    backup, info = regular(a.owner / 'BACKUP.json')
    need(stat.S_IMODE(info.st_mode) in (0o400,0o600) and info.st_nlink == 1,
         'original-seed-backup-metadata')
    forbidden = ((info.st_dev, info.st_ino),)
    for file in (a.selection,a.case,a.owner_public,a.crypto,a.node,a.native,
                 *(a.sdk_dir/name for name in SDK_PINS)):
        regular(file, forbidden)
    selection = load(a.selection,a.selection_sha256,forbidden)
    raw = public_bytes(a.case,forbidden)
    need(digest(raw) == a.case_sha256,'externally-selected-GN3-case')
    case = parse(raw)
    raw_initial = public_bytes(a.owner_public,forbidden)
    need(digest(raw_initial) == a.owner_public_sha256,'externally-selected-own-public-record')
    original = parse(private_read(a.owner / 'INITIAL-PUBLIC.json'))
    need(parse(raw_initial) == original,'original-public-initial-record')
    fields(original,INITIAL_FIELDS,'initial-owner-fields')
    need(original['schema']=='kpxa-initial-public/v1'
         and original['domain_hex32']==selection.domain.hex(),'own-initial-domain')
    own_row=hx(original['output_hex520'],520)
    record(own_row,selection)
    rows=[hx(case['transaction']['payload'])[88+520*i:88+520*(i+1)] for i in range(3)]
    need(rows.count(own_row)==1,'own-initial-record-occurs-once')
    index=rows.index(own_row)
    validate_genesis(case,selection,a.trial_id)
    actual = hx(case['transaction']['payload'])[88+520*index:88+520*(index+1)]
    need(actual==own_row and original['admission_sompi']==2_000_000_000,
         'own-exact-initial-record-and-admission')
    runtime=Runtime(paths={'crypto':a.crypto,'node':a.node,'native-validator':a.native},
                    sdk_dir=a.sdk_dir,forbidden=forbidden)
    a.work.mkdir(parents=True,exist_ok=False,mode=0o700)
    normalized,metrics=runtime.normalize(case,a.work/'quote')
    need(normalized==case,'own-exact-native-body-ID-mass')
    need(type(a.fee_rate) is int and a.fee_rate>0,'own-positive-fee-rate')
    required=a.fee_rate*metrics['mining_mass']
    derived=validate_genesis(case,selection,a.trial_id,required_fee=required)
    runtime.roundtrip(case)
    # The seed is read only after every public body/record/fee/context check.
    owner=parse(private_read(backup));fields(owner,BACKUP_FIELDS,'seed-only-original-backup')
    need(owner['schema']=='kpxa-original-seed-backup/v1'
         and owner['domain_hex32']==selection.domain.hex(),
         'own-original-backup-identity')
    wallet=reference('recipient').Receiver(hx(owner['seed_hex32'],32),selection.domain,runtime.crypto)
    opened=wallet.open(own_row[96:360])
    need(opened.index==0 and opened.commitment()==own_row[:32]
         and opened.value_sompi==2_000_000_000,'own-seed-rederives-admitted-note')
    funding=wallet.keys(0xffffffff)
    spk='000020'+funding.invoice.native_pk.hex()+'ac'
    need(original['funding_spk_hex36']==spk
         and case['entries'][index]['scriptPublicKey']==spk,'designated-own-funding-input')
    signature=runtime.signature(case,index,funding.native_secret)
    result={'schema':'kpxa-GN3-owner-approval/v1',
        'financial_profile_sha256':selection.profile_sha256,'trial_id':a.trial_id,
        'input_index':index,'signature_script_hex66':signature.hex(),
        'unsigned_case_approval_sha256':approval_digest(case,selection,a.trial_id,a.fee_rate),
        'own_initial_public_record_sha256':digest(own_row),'own_receipt_rederived':True,
        'quote':{'fee_rate_sompi_per_mass':a.fee_rate,'mining_mass':metrics['mining_mass'],
            'storage_mass':metrics['storage_mass'],'total_entry_fee_sompi':required,
            'owner_entry_fee_sompi':derived['contributions'][index]['entry_fee_sompi']}}
    fields(result,APPROVAL_NAMES,'signature-only-export')
    write_new(a.output/'APPROVAL.json',encoded(result)+b'\n',0o400)
    return {'status':'OWN_GN3_APPROVAL_EXPORTED','input_index':index,
            'private_material_emitted':False,'network_or_broadcast':False}


if __name__=='__main__':
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('owner','selection','case','owner-public','work','output','crypto','node','native','sdk-dir'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('selection-sha256','case-sha256','owner-public-sha256','trial-id'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--fee-rate',type=int,default=100)
    try: print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,TypeError,KeyError): p.exit(1,'own GN3 approval refused\n')
