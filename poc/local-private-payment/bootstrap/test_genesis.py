#!/usr/bin/env python3
"""Adversarial controls on genuine, explicitly synthetic public genesis fixtures."""
import argparse
import concurrent.futures
import copy
from dataclasses import replace
from pathlib import Path
from gn3 import validate_genesis
from gn3_common import digest,encoded,need,parse,write_new
from gn3_selection import decode
from paths import HostPolicy


def run(a):
    guard=HostPolicy();raw=guard.read(a.selection,a.selection_sha256);selected=decode(raw,a.selection_sha256)
    original=parse(guard.read(a.case,a.case_sha256));valid=validate_genesis(original,selected,a.trial_id)
    need(valid['reserve_sompi']==6_000_000_000 and len(valid['outputs_hex520'])==3,'positive-genuine60KAS-genesis')
    tests=[]
    def case_test(name,change):
        value=copy.deepcopy(original);change(value);tests.append((name,lambda:validate_genesis(value,selected,a.trial_id)))
    def payload_byte(at):
        def change(case):
            raw=bytearray.fromhex(case['transaction']['payload']);raw[at]^=1;case['transaction']['payload']=raw.hex()
        return change
    case_test('old-or-wrong-domain',payload_byte(40))
    case_test('changed-trial-identity',payload_byte(72))
    case_test('ciphertext-CFH-mismatch',payload_byte(88+96))
    case_test('changed-proof',payload_byte(88+519))
    case_test('changed-public-deposit-CV',payload_byte(88+32))
    def duplicate(case):
        raw=bytearray.fromhex(case['transaction']['payload']);raw[88+520:88+1040]=raw[88:88+520];case['transaction']['payload']=raw.hex()
    case_test('duplicate-initial-output',duplicate)
    def empty(case):
        raw=bytearray.fromhex(case['transaction']['payload']);raw[88:120]=bytes(32);case['transaction']['payload']=raw.hex()
    case_test('zero-output-CM',empty)
    case_test('inflated-reserve-output',lambda c:c['transaction']['outputs'][0].__setitem__('value',6_000_000_001))
    def split(case):
        case['transaction']['outputs'][1]['value']+=1;case['transaction']['outputs'][2]['value']-=1
    case_test('changed-per-owner-fee-allocation',split)
    case_test('boolean-input-sompi',lambda c:c['entries'][0].__setitem__('amount',True))
    case_test('missing-three-inputs',lambda c:c['transaction']['inputs'].pop())
    case_test('stale-wrong-initial-state-policy',lambda c:c['transaction']['outputs'][0].__setitem__('scriptPublicKey','0000aa20'+'00'*32+'87'))
    case_test('unsigned-budget-change',lambda c:c['transaction']['inputs'][0].__setitem__('computeBudget',11))
    case_test('non-ALL-proposal-signature',lambda c:c['transaction']['inputs'][0].__setitem__('signatureScript','41'+'00'*64+'02'))
    def execute(item):
        name,call=item
        try:call()
        except (ValueError,OSError,KeyError,TypeError):return {'control':name,'rejected':True}
        raise ValueError('negative-genesis-control-accepted')
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(execute,tests))
    result={'schema':'kpxa-genuine-genesis-controls/v1','classification':'SYNTHETIC_UNFUNDED_PUBLIC_CONTEXT_NOT_ACCEPTED_BACKING',
        'positive_genuine_genesis_passed':True,'negative_controls':results,'negative_controls_rejected':len(results),
        'reserve_sompi':valid['reserve_sompi'],'selection_sha256':a.selection_sha256,'case_sha256':a.case_sha256,
        'network_funding_or_broadcast_performed':False,'private_seed_contents_or_hashes_read':False}
    write_new(a.output,encoded(result)+b'\n',0o400);return {'negative_controls_rejected':len(results),'output':str(a.output)}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('selection','case','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('selection-sha256','case-sha256','trial-id'):p.add_argument('--'+name,required=True)
    a=p.parse_args()
    try:print(encoded(run(a)).decode())
    except (ValueError,OSError,KeyError,TypeError):p.exit(1,'genuine public genesis controls incomplete\n')
