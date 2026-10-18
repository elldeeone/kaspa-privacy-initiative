#!/usr/bin/env python3
"""Check review-fix Rust/Python byte agreement and substitution controls."""
import copy
import json
from pathlib import Path
import sys
import public_binding as binding
import wire_format as wire


def main():
    golden, rust_path, output = map(Path, sys.argv[1:])
    if output.exists(): raise FileExistsError(output)
    frozen={v['label']:v for v in json.loads(golden.read_text())['vectors']}
    intents={label:v['intent'] for label,v in frozen.items()}
    rust=json.loads(rust_path.read_text());rejections=mutations=0
    for row in rust['vectors']:
        intent=intents[row['label']];kind=intent['operation_kind'];auth=bytes.fromhex(row['authorizationHex'])
        if wire.encode(intent).hex()!=frozen[row['label']]['encodedHex']:
            raise RuntimeError('original intent bytes changed')
        if binding.authorization_digest(kind,auth).hex()!=row['authorizationDigest']:
            raise RuntimeError('authorization digest differs')
        expected=binding.expected_journal(intent,auth)
        if expected.hex()!=row['journalHex']: raise RuntimeError('wallet journal differs')
        for bad in [auth[:n] for n in range(len(auth))]+[auth+b'\0',auth+b'\1',auth+b'\xff']:
            try:binding.parse_authorization(kind,bad)
            except ValueError:rejections+=1
            else:raise RuntimeError('malformed auth accepted')
        for flag in [2,255]:
            try:binding.parse_authorization(kind,bytes([flag])+auth[1:])
            except ValueError:rejections+=1
            else:raise RuntimeError('unknown auth flag accepted')
        for field in ['G_hash','D','network_genesis','pool_id','lane_id','statement_id','proof_suite_id','wallet_program_or_vk_hash','anchor']:
            changed=copy.deepcopy(intent);raw=bytearray.fromhex(changed[field]);raw[0]^=1;changed[field]=raw.hex()
            if binding.expected_journal(changed,auth)==expected:raise RuntimeError('context substitution not bound')
            mutations+=1
        if kind==0:
            for offset in range(1,65):
                changed=bytearray(auth);changed[offset]^=1
                if binding.expected_journal(intent,bytes(changed))==expected:raise RuntimeError('auth substitution not bound')
                mutations+=1
        for wrong in ([b'\0'] if kind==0 else [b'\1'+b'\0'*64]):
            try:binding.parse_authorization(kind,wrong)
            except ValueError:rejections+=1
            else:raise RuntimeError('wrong auth kind accepted')
    report={'scope':'PUBLIC_EXPECTED_JOURNAL_INTEROP_NOT_WALLET_PROOF_OR_POOL_ADMISSION',
        'rustPythonVectors':len(rust['vectors']),'pythonAuthFramingRejections':rejections,
        'rustAuthFramingRejections':rust['authFramingRejections'],'contextAndAuthSubstitutionsBound':mutations,
        'originalIntentBytesUnchanged':True,'walletProofImplemented':False,'nativeTransactions':0}
    with output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(report))


if __name__=='__main__':main()
