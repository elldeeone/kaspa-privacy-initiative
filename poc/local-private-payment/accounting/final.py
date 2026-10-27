#!/usr/bin/env python3
"""Independent public-only accounting after the actual 6-payment/9-exit trial.

Consumes retained Full pages and externally pinned public handoffs. No original
backup, invoice, private request, witness, schedule or log is an input. The
21-KAS denominator is the frozen owner-directed workload, not a value decrypted
from the confidential ledger. A selected validating node remains an assumption.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import sys

ROOT=Path(__file__).absolute().parents[3]
BASE=ROOT/'poc/local-private-payment'
MAX=2_870_000_000_000_000_000
USEFUL=2_100_000_000
EXPECTED_GENESIS_FEE=676_100
EXPECTED_ORDINARY_FEE=3_762_200


def need(value,category):
    if not value:raise ValueError(category)


def read(path,expected=None):
    return runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](str(Path(path).absolute()),expected)


def parse(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate-public-JSON-key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:need(False,'nonfinite-public-JSON'))


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()


def integer(value,maximum=MAX):
    need(type(value) is int and 0<=value<=maximum,'integer-sompi-range');return value


def point(body,index=0):
    need(type(index) is int and 0<=index<1<<32,'outpoint-index')
    return body['id']+index.to_bytes(4,'little').hex()


def fee(case):
    value=sum(integer(e['amount']) for e in case['entries'])-sum(integer(o['value']) for o in case['transaction']['outputs'])
    need(0<value<=MAX,'positive-actual-native-fee');return value


def require_terminal(handoff,history,context):
    need(handoff['accepted_transactions']==16 and handoff['terminal'] is True,'six-payments-nine-exits-not-yet-confirmed')
    checkpoint=context['checkpoint']
    need(checkpoint==handoff['checkpoint']==history['head'],'same-final-public-checkpoint')
    need(checkpoint['reserve_sompi']==0 and checkpoint['outpoint_hex36'] is None,'terminal-zero-reserve')
    transitions=history['transitions']
    need(type(transitions) is list and len(transitions)==15,'exact-fifteen-actions')
    need([t['kind'] for t in transitions]==['payment']*6+['exit']*9,'six-payments-followed-by-nine-exits')
    need(len(handoff['native_payouts_observed'])==9,'nine-native-payout-observations')
    return checkpoint


def run(a):
    checker=parse(read(a.checker_selection,a.checker_selection_sha256))
    need(checker['schema']=='kpxa-public-final-accounting-review-candidate/v1','external-accounting-source-selection')
    selected_paths=set()
    for row in checker['source_members']:
        read(row['path'],row['sha256']);selected_paths.add(str(Path(row['path']).absolute()))
    need(all(str((BASE/'accounting'/name).absolute()) in selected_paths
             for name in ('final.py','extract_accepted.mjs','test_final.py')),'complete-new-accounting-source-closure')
    raw_activation=read(a.activation_handoff,a.activation_handoff_sha256);activation=parse(raw_activation)
    final_raw=read(a.final_handoff,a.final_handoff_sha256);final=parse(final_raw)
    need(activation['schema']=='kpxa-activation-handoff/v1' and final['schema']=='kpxa-confirmed-transition-handoff/v1',
         'selected-public-handoff-schemas')
    need(activation['trial_id']==final['trial_id'],'same-actual-trial')
    raw_history=read(**{'path':final['selectors']['HISTORY.json']['path'],'expected':final['selectors']['HISTORY.json']['sha256']})
    raw_context=read(final['selectors']['CONTEXT.json']['path'],final['selectors']['CONTEXT.json']['sha256'])
    history,context=parse(raw_history),parse(raw_context)
    checkpoint=require_terminal(final,history,context)
    need(context['schema']=='kpxa-selected-history-context/v1' and context['domain_hex32']==history['domain_hex32'],
         'canonical-final-context-domain')
    source=parse(read(a.sources,a.sources_sha256))
    for row in source['source_members']:read(ROOT/row['path'],row['sha256'])
    # Only after authenticating the fixed public source closure may its codecs run.
    sys.path[:0]=[str(BASE/'bootstrap'),str(BASE/'chain')]
    import gn3_common as common
    import gn3_selection
    import gn3
    import replay
    from gn3_runtime import Runtime
    from paths import HostPolicy
    guard=HostPolicy();runtime=Runtime()
    selected_raw=read(activation['selection']['path'],activation['selection']['sha256'])
    selected=gn3_selection.decode(selected_raw,activation['selection']['sha256'])
    profile_path=Path(activation['selection']['path']).with_name('PROFILE.json')
    profile=parse(read(profile_path,selected.profile_sha256))
    need(profile['source_closure_sha256']==a.sources_sha256,'source-closure-profile-binding')
    output=Path(a.output).absolute();need(not output.exists(),'fresh-public-accounting-output');output.mkdir(parents=True,mode=0o700)
    fetch_row=final['selectors']['fetch.json'];fetch_path=Path(fetch_row['path']);fetch=parse(read(fetch_path,fetch_row['sha256']))
    extracted_path=output/'ACCEPTED-CASES.json'
    runtime.executables['node'].run(['--use-openssl-ca',BASE/'accounting/extract_accepted.mjs',
        activation['selection']['path'],activation['selection']['sha256'],activation['descriptor']['path'],
        activation['descriptor']['sha256'],fetch_path,fetch_row['sha256'],fetch_path.parent,extracted_path,runtime.sdk_dir])
    extracted=parse(read(extracted_path));need(extracted['sdk_verification']['status']=='PUBLIC_EVIDENCE_CONSISTENCY_PASS','retained-full-page-consistency')
    pool_rows=extracted['pool_transactions'];ordinary_rows=extracted['ordinary_transactions']
    need(len(pool_rows)==16 and len(ordinary_rows)==3,'actual-sixteen-pool-and-three-ordinary-cases')
    pool=[replay.native_case(row) for row in pool_rows];ordinary=[replay.native_case(row) for row in ordinary_rows]
    all_cases=[*ordinary,*pool]
    ids=[case['transaction']['id'] for case in all_cases];need(len(set(ids))==19,'nineteen-distinct-actual-transactions')
    native_reports=[]
    for index,case in enumerate(all_cases):
        group='ordinary' if index<3 else 'pool';number=index if index<3 else index-3
        raw=encoded(case)+b'\n';case_path=output/(group+'-'+str(number).zfill(2)+'-CASE.json');common.write_new(case_path,raw,0o400)
        normalized,metrics=runtime.normalize(case,output/('normalize-'+str(index)))
        need(normalized==case,'actual-whole-CASE-ID-storage-mass')
        _,full_metrics=runtime.validate(case,output/('Full-'+str(index)))
        actual_fee=fee(case)
        need(metrics==full_metrics and metrics['actual_fee_sompi']==actual_fee,'actual-Full-and-integer-fee-agreement')
        need(actual_fee==100*metrics['mining_mass'],'frozen-reference-rate100-actual-accepted-case')
        native_reports.append({'kind':group,'index':number,'transaction_id':case['transaction']['id'],
            'case_path':str(case_path),'case_sha256':digest(raw),'fee_sompi':actual_fee,'metrics':metrics})
    first=gn3.validate_accepted_genesis(pool[0],selected,activation['trial_id'])
    need(first['reserve_sompi']==6_000_000_000,'actual-sixty-KAS-genesis')
    need(fee(pool[0])==EXPECTED_GENESIS_FEE==activation['genesis_paid_fee_sompi'],'genesis-fee-counted-once')
    ordinary_fee=sum(fee(case) for case in ordinary)
    need(ordinary_fee==EXPECTED_ORDINARY_FEE==activation['ordinary_pre_genesis_paid_fee_sompi'],'actual-ordinary-fees-once')
    for i,(case,row) in enumerate(zip(ordinary,pool[0]['transaction']['inputs'])):
        body=case['transaction'];need(len(body['outputs'])==1 and row['previousOutpoint']=={'transactionId':body['id'],'index':0},'actual-ordinary-to-genesis-lineage')
        e=pool[0]['entries'][i];o=body['outputs'][0]
        need(e['amount']==o['value'] and e['scriptPublicKey']==o['scriptPublicKey'] and e['isCoinbase'] is False
            and e['covenantId'] is None,'actual-genesis-populated-ordinary-source')
    support,history_module,codec_module=replay.modules(guard)
    assets=support.Assets(read(activation['assets']['path'],activation['assets']['sha256']),activation['assets']['sha256'])
    parameters=parse(read(activation['parameters']['path'],activation['parameters']['sha256']))
    codec=codec_module.NativeCodec(Path(activation['codec']['path']),activation['codec']['sha256'])
    old_history=parse(read(activation['selectors']['HISTORY.json']['path'],activation['selectors']['HISTORY.json']['sha256']))
    need(history['genesis']==old_history['genesis'],'same-original-accepted-genesis')
    need(context['genesis_sha256']==digest(encoded(history['genesis'])),'canonical-public-genesis-digest')
    loaded=history_module.load(raw_history,checkpoint,context['genesis_sha256'],assets)
    actions,nfs=set(),set();current_state=bytes.fromhex(first['state_hex112']);current_point=first['outpoint_hex36'];current_reserve=first['reserve_sompi']
    payouts=[];payment_fees=0;exit_fees=0;queries={q['outpoint']['transactionId']+q['outpoint']['index'].to_bytes(4,'little').hex():q for q in fetch['current_view']['queries']}
    for index,(case,transition) in enumerate(zip(pool[1:],history['transitions']),1):
        unchanged,projection,_,decoded=codec_module.project(codec,case,bytes.fromhex(parameters['outer_image_hex32']),
            bytes.fromhex(parameters['component_profile_sha256']),bytes.fromhex(parameters['exit_vk_hex328']))
        need(unchanged==case and projection.hex()==transition['projection_hex'],'actual-native-effects-equal-public-history')
        payment=decoded['mode']=='mixed';parsed=assets.wire.parse_projection(projection) if payment else assets.wire.parse_exit_projection(projection);body=parsed.body
        need(transition['kind']==('payment' if payment else 'exit'),'actual-payment-exit-classification')
        need(body.point.hex()==current_point and body.old_state.raw==current_state and body.old_reserve==current_reserve,
             'unbroken-actual-current-reserve-lineage')
        need(body.action_id not in actions,'unique-actual-action-ID');actions.add(body.action_id)
        nf=body.spends[0].nf if payment else body.nf
        need(nf not in nfs and nf!=bytes(32),'unique-nonzero-original-NF');nfs.add(nf)
        native_fee=fee(case);need(native_fee==body.fee,'actual-advertised-fee')
        native_input=case['entries'][0]
        need(native_input['amount']==current_reserve and native_input['scriptPublicKey']==assets.wire.state_spk(current_state,assets.tail).hex(),
             'actual-input-amount-and-policy')
        if payment:
            need(body.payout==0 and len(case['transaction']['outputs'])==1,'payment-no-native-payout')
            payment_fees+=native_fee
        else:
            exit_fees+=native_fee
            need(bytes.fromhex(case['transaction']['inputs'][0]['signatureScript'])[2:130].hex()==transition['proof_hex128'],
                 'actual-direct-exit-proof-equals-history')
            out_index=len(case['transaction']['outputs'])-1;paid=case['transaction']['outputs'][out_index];at=point(case['transaction'],out_index)
            need(paid['value']==body.payout and paid['scriptPublicKey']==body.payout_spk.hex(),'actual-native-payout-effect')
            query=queries.get(at);need(query is not None and query['entry'] is not None,'actual-terminal-payout-UTXO-observed')
            observed=query['entry']
            need(replay.integer_boundary(observed['amount_sompi'])==body.payout and observed['script_public_key']==paid['scriptPublicKey'],
                 'exact-observed-native-payout-value-and-destination')
            payouts.append({'outpoint_hex36':at,'payout_sompi':body.payout,'script_public_key':paid['scriptPublicKey'],'fee_sompi':native_fee})
        current_reserve=body.new_reserve;current_state=body.new_state.raw
        current_point=point(case['transaction']) if current_reserve else None
        need(current_point==transition['successor_outpoint_hex36'],'actual-successor-outpoint')
        if current_reserve:
            out=case['transaction']['outputs'][0]
            need(out['value']==current_reserve and out['scriptPublicKey']==assets.wire.state_spk(current_state,assets.tail).hex(),
                 'actual-continuing-reserve-output')
    need(len(actions)==15 and len(nfs)==15 and len(payouts)==9,'fifteen-unique-confirmed-actions-nine-payouts')
    end=assets.wire.parse_state(current_state)
    need(current_reserve==0 and current_point is None and end.cm_count==15 and end.nf_count==16,
         'terminal-CM15-NF16-zero-reserve')
    payout_sum=sum(p['payout_sompi'] for p in payouts)
    need(payout_sum+payment_fees+exit_fees==6_000_000_000,'complete-native-pool-sompi-conservation')
    prefix_fee=sum(fee(case) for case in pool)
    need(prefix_fee==EXPECTED_GENESIS_FEE+payment_fees+exit_fees==final['observed_total_fee_sompi'],'actual-accepted-prefix-fee-total')
    all_in=ordinary_fee+prefix_fee;fee_pass=all_in*100<=USEFUL*2
    result={'schema':'kpxa-independent-public-final-accounting/v1','status':'ACTUAL_TERMINAL_NATIVE_ACCOUNTING_PASS',
        'trial_id':activation['trial_id'],'accepted_pool_transactions':16,'ordinary_funding_transactions':3,
        'unique_confirmed_actions':15,'private_payments':6,'direct_exit152_actions':9,'native_payouts':payouts,
        'terminal_reserve_sompi':0,'terminal_cm_count':15,'terminal_nf_count':16,'native_payout_sum_sompi':payout_sum,
        'private_payment_fee_sompi':payment_fees,'direct_exit_fee_sompi':exit_fees,'genesis_fee_sompi':EXPECTED_GENESIS_FEE,
        'accepted_pool_prefix_fee_sompi':prefix_fee,'ordinary_pre_genesis_fee_sompi':ordinary_fee,
        'all_in_actual_fee_sompi':all_in,'fixed_useful_transfer_denominator_sompi':USEFUL,
        'denominator_basis':'OWNER_DIRECTED_FROZEN_21_KAS_WORKLOAD_NOT_DECRYPTED_FROM_PUBLIC_LEDGER',
        'all_in_fee_ratio_exact':{'numerator_sompi':all_in,'denominator_sompi':USEFUL},
        'two_percent_actual_all_in_fee_verdict':'PASS' if fee_pass else 'FAIL','previous_failed_fee_verdict_redefined':False,
        'genesis_fee_counted_once':True,'ordinary_pre_genesis_fee_added_once':True,'actual_native_Full_reports':native_reports,
        'activation_handoff_sha256':a.activation_handoff_sha256,'final_handoff_sha256':a.final_handoff_sha256,
        'source_closure_sha256':a.sources_sha256,
        'accounting_checker_selection_sha256':a.checker_selection_sha256,
        'accounting_checker_source_members':checker['source_members'],'history_sha256':digest(raw_history),'context_sha256':digest(raw_context),
        'trust_scope':'SELECTED_VALIDATING_NODE_AND_RETAINED_FINITE_CONFIRMED_FULL_PREFIX',
        'cold_recovery_original_seed_or_download_provenance_established_by_public_accounting':False,
        'off_host_recovery_or_independent_retention_proved':False,
        'independent_consensus_continuous_currentness_general_privacy_or_cryptographic_correctness_proved':False,
        'private_original_seed_request_invoice_plan_or_log_read_or_hashed':False,'funding_or_submission_performed':False}
    common.write_new(output/'RESULTS.json',encoded(result)+b'\n',0o400)
    return {'status':result['status'],'results':str(output/'RESULTS.json'),'sha256':digest(encoded(result)+b'\n'),
        'all_in_actual_fee_sompi':all_in,'two_percent_verdict':result['two_percent_actual_all_in_fee_verdict']}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('activation-handoff','final-handoff','sources','checker-selection','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('activation-handoff-sha256','final-handoff-sha256','sources-sha256','checker-selection-sha256'):p.add_argument('--'+name,required=True)
    try:print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,KeyError,TypeError):p.exit(2,'independent actual terminal public accounting incomplete\n')
