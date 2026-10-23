"""One public whole-program zero-proof batch; no financial acceptance case."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import time
import fixture
import trusted_runtime

HERE=Path(__file__).resolve().parent
NATIVE_SHA='077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'
NODE_SHA='d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c'
G16='ZkIntegrity("ARK serialization error: the input buffer contained invalid data")'
COMMON=('none','array-digest','cipher-digest','alignment','count','reserved','mode','NF-path',
        'NF-duplicate','state-root','conservation','wrong-outpoint','truncated','trailing')
def specs():
    return [(mode,fault) for mode in (0,2,32) for fault in COMMON+(
        ('payout','terminal-carry','terminal-cipher-sentinel') if mode==0 else
        ('successor','occupied-target','duplicate-CM-proof-obligation','occupied-skipped-gap','compact-P0','payout') if mode==2 else
        ('successor','occupied-target','duplicate-CM-proof-obligation','occupied-skipped-gap'))]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x') as file:json.dump(value,file,indent=2,sort_keys=True);file.write('\n')
def run(output,emitter,node_path,native_path,public_keys,emitter_sha):
    if output.exists():raise ValueError('fresh-public-whole-output-required')
    output.mkdir(parents=True);keydata=json.loads(public_keys.read_bytes())
    compact=bytes.fromhex(keydata['compact_vk_hex328']);wide=bytes.fromhex(keydata['wide_vk_hex328'])
    expected={
        'compact':'a82c94918d93008160ea9af4b709b05ce41ed5fe6e4b85d66d0fb310b02d94f5',
        'wide':'5e7177177485bb58d9f4f475092fa8212fe83b29bed10806b6f550b37c84cfe2'}
    if sha(compact)!=expected['compact'] or sha(wide)!=expected['wide'] or sha(emitter.read_bytes())!=emitter_sha:
        raise ValueError('selected-public-emitter-and-placeholder-identities')
    rows=[];cases=[];started=time.monotonic()
    for mode,fault in specs():
        case,row=fixture.fixture(emitter,compact,wide,mode,fault);cases.append(case);rows.append(row)
    with trusted_runtime.TrustedExecutable(node_path,NODE_SHA) as node:
        original=json.loads(json.dumps(cases));result=node.run([HERE/'sdk.mjs'],input_text=json.dumps(cases))
        if result.returncode:raise ValueError('public-SDK-preparation-failed')
        cases=json.loads(result.stdout)
        if type(cases) is not list or len(cases)!=len(specs()):raise ValueError('exact-full-SDK-batch')
        for before,after in zip(original,cases):
            ident=after['transaction']['id'];before['transaction']['id']=ident
            if before!=after or type(ident) is not str or len(ident)!=64 or any(c not in '0123456789abcdef' for c in ident):
                raise ValueError('SDK-only-recomputed-id-mutation')
        write(output/'NODE-RUNTIME.json',node.receipt())
    for index,(case,row) in enumerate(zip(cases,rows)):
        case['transaction']['inputs'][0]['sequence']=int(case['transaction']['inputs'][0]['sequence'])
        target=output/f'case-{index:03d}';write(target/'case.json',case);write(target/'fixture.json',row)
    with trusted_runtime.TrustedExecutable(native_path,NATIVE_SHA) as native:
        write(output/'NATIVE-RUNTIME.json',native.receipt())
        def evaluate(index):
            target=output/f'case-{index:03d}';answer=native.run(['validate-transaction',target/'case.json',target/'native'])
            if answer.returncode:raise ValueError('native-process-failure')
            report=json.loads((target/'native/native-validation.json').read_bytes())
            metrics=json.loads((target/'native/metrics.json').read_bytes());engines=report['per_input_ScriptEngine']
            if len(engines)!=1 or engines[0]['input_index']!=0:raise ValueError('exact-input-engine-coverage')
            engine=engines[0];expected_error=G16 if rows[index]['expected_final_G16_seam'] else 'VerifyError'
            verdict=(report['isolation']=='PASS' and report['Full']['accepted'] is False
                and report['Full']['typed_error']=='SignatureInvalid('+expected_error+')'
                and report['all_input_engines_accepted'] is False and engine['accepted'] is False
                and engine['typed_error']==expected_error
                and (engine['units']>=14_750_000 if rows[index]['expected_final_G16_seam'] else engine['units']<14_000_000))
            return {**rows[index],'expected_typed_verdict_matches':verdict,'native_units':engine['units'],
                'engine_typed_error':engine['typed_error'],'isolation':report['isolation'],'Full':report['Full'],
                'metrics':metrics,'case_sha256':sha((target/'case.json').read_bytes()),
                'native_report_sha256':sha((target/'native/native-validation.json').read_bytes())}
        with ThreadPoolExecutor(max_workers=4) as executor:results=list(executor.map(evaluate,range(len(cases))))
    summary={'classification':'WHOLE_NATIVE_PUBLIC_BINDING_SCREEN_ZERO_PROOFS_NO_FINANCIAL_POSITIVES',
        'case_count':len(results),'all_expected_typed_verdicts_match':all(r['expected_typed_verdict_matches'] for r in results),
        'final_G16_seams':sum(r['expected_final_G16_seam'] for r in results),'financial_acceptances':0,
        'all_native_calls':len(results),'same_profile_all_cases':True,'native_wall_seconds':time.monotonic()-started,
        'results':results,'matched_circuit':False,'new_setup_PK_seed_key_funds_RPC':0}
    write(output/'RESULTS.json',summary)
    if not summary['all_expected_typed_verdicts_match']:raise ValueError('whole-native-typed-verdict-mismatch')
    return summary
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);parser.add_argument('--emitter',type=Path,required=True)
    parser.add_argument('--node',type=Path,required=True);parser.add_argument('--native',type=Path,required=True)
    parser.add_argument('--public-keys',type=Path,required=True);parser.add_argument('--emitter-sha',required=True)
    args=parser.parse_args();r=run(args.output,args.emitter,args.node,args.native,args.public_keys,args.emitter_sha)
    print(json.dumps({key:value for key,value in r.items() if key!='results'},sort_keys=True))
