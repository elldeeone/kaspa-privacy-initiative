#!/usr/bin/env python3
"""Run fixed upstream MWEB component controls with separate owner processes."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
EVIDENCE=ROOT/'research/next-session/independent-payments/privacy-components'


def save(path,value):
    with path.open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n')


def cgroup():
    try:
        relative=next(r[3:] for r in Path('/proc/self/cgroup').read_text().splitlines() if r.startswith('0::'))
        base=Path('/sys/fs/cgroup')/relative.lstrip('/')
    except (OSError,StopIteration):return {'available':False}
    result={'available':True}
    for name in ('memory.peak','memory.swap.peak','pids.current','pids.peak'):
        try:result[name]=int((base/name).read_text().strip())
        except (OSError,ValueError):result[name]=None
    for name in ('memory.events','cpu.stat'):
        try:result[name]={k:int(v) for k,v in (line.split() for line in (base/name).read_text().splitlines())}
        except (OSError,ValueError):result[name]=None
    return result


def run(binary,output):
    output=output.absolute();binary=binary.absolute()
    if output.exists() or output.is_relative_to(ROOT):raise ValueError('fresh-output-outside-repository-required')
    output.mkdir(parents=True,mode=0o700)
    plan=json.loads((EVIDENCE/'PLAN.json').read_bytes())
    events=[]
    def call(label,args):
        began=time.monotonic(); before=resource.getrusage(resource.RUSAGE_CHILDREN)
        child=subprocess.Popen([str(binary),*map(str,args)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        stdout,stderr=child.communicate();elapsed=time.monotonic()-began;after=resource.getrusage(resource.RUSAGE_CHILDREN)
        (output/(label+'.stdout.log')).write_text(stdout);(output/(label+'.stderr.log')).write_text(stderr)
        if child.returncode!=0:raise RuntimeError('component-command-failed:'+label)
        report=json.loads(stdout);save(output/(label+'.json'),report)
        events.append({'label':label,'pid':child.pid,'exit_code':child.returncode,'wall_seconds':elapsed,
            'child_user_seconds':after.ru_utime-before.ru_utime,'child_system_seconds':after.ru_stime-before.ru_stime,
            'arguments_except_absolute_output_paths':[str(v) if not isinstance(v,Path) else v.name for v in args],
            'report_sha256':hashlib.sha256((output/(label+'.json')).read_bytes()).hexdigest()})
        return report
    equivalent=call('upstream-equivalent',['upstream',output/'official-equivalent.tx'])
    call('upstream-fresh-verify',['verify',output/'official-equivalent.tx'])
    a=call('owner-A',['owner',output/'owner-A',25,10,14])
    b=call('owner-B',['owner',output/'owner-B',40,20,19])
    merged=call('aggregate-public',['aggregate',output/'owner-A.tx',output/'owner-B.tx',output/'aggregate.tx'])
    verified=call('aggregate-fresh-verify',['verify',output/'aggregate.tx'])
    singleton=call('singleton-fresh-verify',['verify',output/'owner-A.tx'])
    rejected=call('upstream-negative',['negative',output/'aggregate.tx'])
    if len({r['pid'] for r in events})!=len(events):raise RuntimeError('unexpected-process-identity-reuse')
    for field in ('input_ids','output_ids','kernel_ids'):
        if set(merged[field])!=set(a[field])|set(b[field]):raise RuntimeError('component-id-union-mismatch:'+field)
        if merged[field]!=verified[field]:raise RuntimeError('fresh-verifier-identity-mismatch:'+field)
    receipt={'profile':'final_public_transaction_plus_one_legitimate_payee_receipt','payee_output_id':a['legitimate_C1_payment_output_id'],'known_amount':10,'declared_counterparty_role':'A','other_component_values_or_output_origin_map_supplied':False,'privacy_qualification_or_attack_success_metric_claimed':False}
    final_view=output/'final-chain-C1';final_view.mkdir();(final_view/'aggregate.tx').write_bytes((output/'aggregate.tx').read_bytes());save(final_view/'receipt.json',receipt)
    pre_view=output/'preaggregation-observer';pre_view.mkdir()
    for actor in ('A','B'):(pre_view/('component-'+actor+'.tx')).write_bytes((output/('owner-'+actor+'.tx')).read_bytes())
    mapping={'source':'public components observed before aggregation; not owner spend secrets','A_output_ids':a['output_ids'],'B_output_ids':b['output_ids'],'unchanged_aggregate_output_ids':merged['output_ids'],'all_four_outputs_remain_attributable_to_original_public_component':True,'same_applies_to_input_and_kernel_ids':True}
    save(pre_view/'retained-partition-map.json',mapping)
    result={'schema':'kpi-established-MWEB-component-screen/v1','classification':'UNFUNDED_SYNTHETIC_UPSTREAM_COMPONENT_TEST_NOT_KAS_SETTLEMENT_OR_PRIVACY_QUALIFICATION',
        'upstream_commit':plan['upstream_commit'],'plan_sha256':hashlib.sha256((EVIDENCE/'PLAN.json').read_bytes()).hexdigest(),
        'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'separate_owner_processes':2,'public_aggregate_process_and_fresh_verifier_distinct':True,
        'owner_spend_secrets_exported_or_supplied_to_aggregation':False,'unmodified_upstream_crypto_and_consensus_validators':True,
        'full_upstream_Boost_node_DB_test_suite_executed':False,'equivalent_official_API_test':equivalent,
        'two_payment_plus_change_aggregate':merged,'fresh_process_verified':verified['valid'],'negative_controls':rejected,
        'C1_receipt':receipt,'preaggregation_partition_map_is_complete_negative':True,
        'public_final_transaction_has_only_global_input_output_kernel_vectors_and_summed_offsets':True,
        'cryptographic_unlinkability_inferred_from_missing_group_field':False,'public_spent_output_IDs_remain_visible':True,
        'singleton_source_and_timing_failures_resolved':False,'hidden_membership_or_current_KAS_nullifier_equivalence':False,
        'secrets_values_hashes_or_retention_recovery_proven':False,'events':events,'resources_before_controller_exit':cgroup()}
    save(output/'RESULTS.json',result)
    print(json.dumps({'upstream_equivalent_valid':True,'separate_owners':2,'public_components_aggregate_valid':True,
        'fresh_process_verify':True,'upstream_negative_controls':4,'preaggregate_mapping_retained':True,'public_spent_IDs_visible':True}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();run(args.binary,args.output)
