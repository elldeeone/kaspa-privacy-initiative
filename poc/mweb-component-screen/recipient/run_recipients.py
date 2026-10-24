#!/usr/bin/env python3
"""Fresh independent-recipient MWEB component experiment; keys stay resident."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[3]
BASE=ROOT/'research/next-session/independent-payments/privacy-components/recipient-extension'


def save(path,value):
    with path.open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n')


def resources():
    try:
        relative=next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
        directory=Path('/sys/fs/cgroup')/relative.lstrip('/')
    except (OSError,StopIteration):return {'available':False}
    out={'available':True}
    for name in ('memory.peak','memory.swap.peak','pids.current','pids.peak'):
        try:out[name]=int((directory/name).read_text())
        except (OSError,ValueError):out[name]=None
    for name in ('cpu.stat','memory.events'):
        try:out[name]={a:int(b) for a,b in (line.split() for line in (directory/name).read_text().splitlines())}
        except (OSError,ValueError):out[name]=None
    return out


def run(binary,public_binary,output):
    output=output.absolute();binary=binary.absolute();public_binary=public_binary.absolute()
    if output.exists() or output.is_relative_to(ROOT):raise ValueError('fresh-output-outside-Git-required')
    output.mkdir(parents=True,mode=0o700);active=[];events=[]
    def call(label,executable,args):
        start=time.monotonic();child=subprocess.Popen([str(executable),*map(str,args)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        stdout,stderr=child.communicate();(output/(label+'.stdout.log')).write_text(stdout);(output/(label+'.stderr.log')).write_text(stderr)
        if child.returncode:raise RuntimeError('command-failed:'+label)
        value=json.loads(stdout);save(output/(label+'.json'),value)
        events.append({'phase':label,'pid':child.pid,'returncode':child.returncode,'wall_seconds':time.monotonic()-start})
        return value
    try:
        for label in ('R1','R2'):
            child=subprocess.Popen([str(binary),'recipient',str(output/(label+'.public-address'))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            active.append((label,child));ready=child.stdout.readline();value=json.loads(ready)
            if value.get('event')!='recipient_public_address_ready' or value.get('secret_keys_exported') is not False:
                raise RuntimeError('recipient-not-ready:'+label)
            (output/(label+'.ready.json')).write_text(ready)
            if len((output/(label+'.public-address')).read_bytes())!=66:raise RuntimeError('invoice-width')
        a=call('sender-A',binary,['sender',output/'sender-A',output/'R1.public-address',25,10,14])
        b=call('sender-B',binary,['sender',output/'sender-B',output/'R2.public-address',40,20,19])
        agg=call('aggregate',public_binary,['aggregate',output/'sender-A.tx',output/'sender-B.tx',output/'aggregate.tx'])
        verified=call('aggregate-fresh-verify',public_binary,['verify',output/'aggregate.tx'])
        for label,child in active:
            amount=10 if label=='R1' else 20
            child.stdin.write(str(output/'aggregate.tx')+' '+str(output/(label+'.spend.tx'))+' '+str(amount)+'\n');child.stdin.flush();child.stdin.close()
        receipts=[]
        for label,child in active:
            stdout=child.stdout.read();stderr=child.stderr.read();child.wait()
            (output/(label+'.receipt.stdout.log')).write_text(stdout);(output/(label+'.stderr.log')).write_text(stderr)
            if child.returncode:raise RuntimeError('recipient-failed:'+label)
            receipt=json.loads(stdout)
            expected=a if label=='R1' else b
            if receipt['received_output_id']!=expected['expected_payment_output_id']:
                raise RuntimeError('recipient-recovered-different-output:'+label)
            if receipt['owned_outputs_recovered']!=1 or receipt['scanned_outputs']!=4 or receipt['other_outputs_accepted']!=0:
                raise RuntimeError('recipient-discovery-count:'+label)
            save(output/(label+'.receipt.json'),receipt);receipts.append({'actor':label,'pid':child.pid,**receipt})
            events.append({'phase':'recipient-'+label,'pid':child.pid,'returncode':child.returncode})
        spends=[]
        for label in ('R1','R2'):
            value=call(label+'-spend-fresh-verify',public_binary,['verify',output/(label+'.spend.tx')])
            receipt=next(r for r in receipts if r['actor']==label)
            if value['input_ids']!=[receipt['received_output_id']] or value['input_count']!=1 or value['output_count']!=1:
                raise RuntimeError('fresh-recipient-spend-input-shape')
            spends.append({'actor':label,**value})
        if len({r['pid'] for r in events})!=len(events):raise RuntimeError('process-identities-not-distinct')
        result={'schema':'kpi-MWEB-independent-recipient-component/v1','classification':'UNFUNDED_LOCAL_COMPONENT_ONLY_NO_ACCEPTED_CHAIN_OR_KAS_PRIVACY_QUALIFICATION',
            'new_recipient_processes':2,'sender_processes':2,'recipient_private_keys_exported_or_written':False,
            'senders_receive_only_public_66byte_stealth_addresses':True,'production_wallet_builder_used':True,
            'known_address_recovery_adapter_not_wallet_DB':True,'recipient_receipts':receipts,'aggregate':agg,
            'aggregate_fresh_verifier':verified,'recipient_spends_fresh_verified':spends,
            'received_output_IDs_distinct':receipts[0]['received_output_id']!=receipts[1]['received_output_id'],
            'all_private_actor_processes_ended':True,'private_keys_coin_openings_or_hashes_emitted':False,
            'public_spent_output_ID_coordinator_grouping_singleton_timing_failures_resolved':False,
            'C1_or_financial_privacy_thresholds_measured':False,'process_events':events,
            'recipient_binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
            'aggregate_verifier_binary_sha256':hashlib.sha256(public_binary.read_bytes()).hexdigest(),
            'source_freeze_sha256':hashlib.sha256((BASE/'SOURCE-FREEZE.json').read_bytes()).hexdigest(),
            'resources_before_controller_exit':resources()}
        save(output/'RESULTS.json',result)
        print(json.dumps({'independent_recipients':2,'real_public_invoices':True,'each_recovers_one_of_four':True,
            'each_spends_received_output_with_own_derived_key':True,'fresh_public_spend_verifiers':2,'exported_private_keys':False}))
    finally:
        for _,child in active:
            if child.poll() is None:child.terminate();child.wait()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','public-binary','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();run(args.binary,args.public_binary,args.output)
