#!/usr/bin/env python3
"""Root-released TN10 bootstrap through confirmed genuine3-owner entry, never payments."""
import argparse
from pathlib import Path
from types import SimpleNamespace
import os
import re
import subprocess
import time
import sys
from gn3_common import CLEAN,ROOT,digest,encoded,fields,hx,need,parse,uuid_text,write_new
from gn3_runtime import Runtime,GENERIC
from gn3_selection import decode
from paths import HostPolicy,checked

HERE=Path(__file__).absolute().parent
PRIVATE=Path('/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01')
CHAIN=HERE.parent/'chain'


def run(a):
    guard=HostPolicy();trial=parse(guard.read(a.trial,a.trial_sha256));activation=checked(a.activation)
    selected=decode(guard.read(activation/'SELECTION.json',a.selection_sha256),a.selection_sha256)
    profile=parse(guard.read(activation/'PROFILE.json',selected.profile_sha256))
    source=parse(guard.read(activation/'SOURCES.json',a.sources_sha256))
    need(profile['source_closure_sha256']==a.sources_sha256 and source['mining_workers']==2
        and source['direct_network_fallback'] is False,'exact-Tor-only-two-worker-source-selection')
    for row in source['source_members']:guard.read(ROOT/row['path'],row['sha256'])
    need(trial['schema']=='kpxa-fresh-unfunded-trial/v1' and trial['domain_hex32']==selected.domain.hex()
         and re.fullmatch('[a-z][a-z0-9-]{0,63}',trial['label']) and len(trial['owners'])==3,'selected-fresh-actual-three-owner-trial')
    uuid_text(trial['trial_id'])
    funding=a.trial.parent/'FUNDING.json';identity=parse(guard.read(funding,a.funding_sha256))
    need(identity['trial_id']==trial['trial_id'] and identity['domain_hex32']==selected.domain.hex(),'fresh-public-funding-identity')
    parameters=activation/'PARAMETERS.json';guard.read(parameters,profile['parameters_sha256'])
    assets=profile['wallet_assets'];guard.read(assets['path'],assets['sha256'])
    if not a.execute:return {'status':'ROOT_RELEASE_REQUIRED_NO_NETWORK','trial_id':trial['trial_id'],
        'mining_workers':2,'through':'GENESIS_CONFIRMED','funding_or_broadcast_performed':False}
    public=checked(a.output);private=checked(a.private_output)
    need(private.is_relative_to(PRIVATE/trial['label']/'controller') and not private.exists(),'fresh-declared-private-activation-controller')
    need(not public.exists() and not public.is_relative_to(PRIVATE),'fresh-public-activation-results')
    private.mkdir(parents=True,mode=0o700);public.mkdir(parents=True,mode=0o700)
    runtime=Runtime();node=runtime.paths['node'];step='initialization';ordinal=0
    def read(path):return parse(guard.read(path))
    def sha(path):return digest(guard.read(path))
    def milestone(name,**extra):print(encoded({'step':name,**extra}).decode(),flush=True)
    def call(command,name,allow_failure=False):
        nonlocal ordinal,step
        ordinal+=1;step=name
        result=subprocess.run(list(map(str,command)),env=CLEAN,capture_output=True)
        write_new(private/('step-'+str(ordinal)+'.stdout'),result.stdout)
        write_new(private/('step-'+str(ordinal)+'.stderr'),result.stderr)
        need(allow_failure or result.returncode==0,'activation-stage-incomplete-'+name)
        return result.returncode
    def python(script,args,name,allow_failure=False):return call(['/usr/bin/python3','-B',script,*args],name,allow_failure)
    def js(script,args,name,allow_failure=False):return call([node,'--use-openssl-ca',script,*args],name,allow_failure)
    def submit(mode,stage,case):
        target=public/('submit-'+stage)
        rc=js(CHAIN/'submit.mjs',['--mode',mode,'--stage',stage,'--trial-id',trial['trial_id'],
            '--selection',activation/'SELECTION.json','--selection-sha256',a.selection_sha256,
            '--case',case,'--case-sha256',sha(case),'--output',target,'--journal',private/'controller','--execute'],
            'single-submit-'+stage,True)
        need((target/'RESULTS.json').exists(),'single-submission-not-reconcilable-'+stage)
        result=read(target/'RESULTS.json');need(result['submission_attempted'] is True,'submission-not-attempted-'+stage)
        milestone('submission-consumed-query-only',stage=stage,status=result['status'])
        return target/'preflight/SDK-CANDIDATE.json'
    # Recheck exact source bytes immediately before the first network request.
    for row in source['source_members']:guard.read(ROOT/row['path'],row['sha256'])
    anchor=public/'BIRTH-ANCHOR.json'
    js(CHAIN/'anchor.mjs',[activation/'SELECTION.json',a.selection_sha256,anchor],'birth-anchor')
    milestone('birth-anchor-recorded')
    for i in range(3):
        python(HERE/'run_miner.py',['--identity',funding,'--identity-sha256',a.funding_sha256,
            '--party',i,'--workers',2,'--private-output',private/('miner-'+str(i)),
            '--output',public/('miner-'+str(i)),'--execute-mining'],'mine-source-'+str(i))
        milestone('free-testnet-source-mined',funding_input=i)
    index=0;waiting=False
    while True:
        observed=public/('maturity-'+str(index));rc=js(HERE/'collect_funding.mjs',[funding,a.funding_sha256,observed],'read-only-maturity',True)
        if rc==0 and read(observed/'RESULTS.json')['status']=='MATURE_SOURCES_OBSERVED_PENDING_CONSOLIDATION':break
        if not waiting:milestone('waiting-for-free-reward-maturity');waiting=True
        index+=1;time.sleep(5)
    milestone('all-three-mature-sources-observed')
    ordinary=[];ordinary_fees=0
    for i,owner in enumerate(trial['owners']):
        observation=observed/('OWNER-'+str(i)+'.json');consolidated=public/('consolidate-'+str(i))
        python(HERE/'run_consolidation.py',['--owner',PRIVATE/trial['label']/('party-'+str(i))/'owner',
            '--observation',observation,'--observation-sha256',sha(observation),
            '--owner-public',owner['public_file'],'--owner-public-sha256',owner['sha256'],
            '--private-output',private/('consolidation-'+str(i)),'--output',consolidated,
            '--trial-id',trial['trial_id'],'--execute'],'own-consolidation-'+str(i))
        candidate=submit('consolidate','source-'+str(i),consolidated/'selected-case.json')
        index=0
        while True:
            output=public/('ordinary-'+str(i)+'-'+str(index));rc=js(HERE/'reconcile_ordinary.mjs',
                [candidate,sha(candidate),output],'read-only-ordinary-'+str(i),True)
            if rc==0 and read(output/'RESULTS.json')['status']=='EXACT_ORDINARY_OUTPUT_OBSERVED_DAA_DEPTH20':break
            index+=1;time.sleep(5)
        ordinary.append(output/'RESULTS.json');ordinary_fees+=read(consolidated/'RESULTS.json')['fee_sompi'];milestone('ordinary-source-confirmed',funding_input=i)
    sources=public/'SOURCES.json'
    python(HERE/'ordinary_sources.py',['--observations',*ordinary,'--observation-sha256',*[sha(p) for p in ordinary],
        '--trial-id',trial['trial_id'],'--output',sources],'canonical-ordinary-sources')
    outputs=[read(owner['public_file'])['output_hex520'] for owner in trial['owners']]
    records=public/'OUTPUTS.json';write_new(records,encoded(outputs)+b'\n',0o400)
    proposal=public/'genesis-proposal'
    common=['--selection',activation/'SELECTION.json','--selection-sha256',a.selection_sha256,'--trial-id',trial['trial_id']]
    python(HERE/'entry_cli.py',['prepare',*common,'--records',records,'--sources',sources,'--output',proposal],'genuine-genesis-proposal')
    approvals=[];case=proposal/'proposed-case.json'
    for i,owner in enumerate(trial['owners']):
        output=public/('genesis-approval-'+str(i))
        python(HERE/'run_signer.py',[*common,'--owner',PRIVATE/trial['label']/('party-'+str(i))/'owner',
            '--case',case,'--case-sha256',sha(case),'--owner-public',owner['public_file'],
            '--owner-public-sha256',owner['sha256'],'--private-output',private/('genesis-signer-'+str(i)),
            '--output',output,'--execute'],'own-genesis-approval-'+str(i));approvals.append(output/'APPROVAL.json')
    combined=public/'genesis-combined'
    python(HERE/'entry_cli.py',['combine',*common,'--case',case,'--approvals',*approvals,'--output',combined],'genesis-all-signatures-Full')
    case=combined/'selected-case.json';descriptor=public/'DESCRIPTOR.json'
    python(HERE/'descriptor.py',[*common,'--case',case,'--case-sha256',sha(case),'--anchor',anchor,
        '--anchor-sha256',sha(anchor),'--output',descriptor],'genesis-descriptor')
    submit('genesis','genesis',case);index=0
    while True:
        confirmed=public/('confirm-genesis-'+str(index))
        rc=python(CHAIN/'confirm.py',[*common[:-2], '--descriptor',descriptor,'--descriptor-sha256',sha(descriptor),
            '--assets',assets['path'],'--assets-sha256',assets['sha256'],'--parameters',parameters,
            '--parameters-sha256',profile['parameters_sha256'],'--codec',profile['native_codec']['path'],
            '--codec-sha256',profile['native_codec']['sha256'],'--expected-transaction-id',read(case)['transaction']['id'],
            '--expected-case',case,'--expected-case-sha256',sha(case),'--output',confirmed],'read-only-genesis-confirmation',True)
        if rc==0:break
        index+=1;time.sleep(5)
    handoff=read(confirmed/'HANDOFF.json')
    need(handoff['checkpoint']['reserve_sompi']==6_000_000_000 and handoff['accepted_transactions']==1,'exact-confirmed-GEN3-60KAS')
    activation_handoff={'schema':'kpxa-activation-handoff/v1','status':handoff['status'],'trial_id':trial['trial_id'],
        'checkpoint':handoff['checkpoint'],'selectors':handoff['selectors'],
        'selection':{'path':str(activation/'SELECTION.json'),'sha256':a.selection_sha256},
        'descriptor':{'path':str(descriptor),'sha256':sha(descriptor)},'assets':assets,
        'parameters':{'path':str(parameters),'sha256':profile['parameters_sha256']},'codec':profile['native_codec'],
        'ordinary_pre_genesis_paid_fee_sompi':ordinary_fees,'genesis_paid_fee_sompi':handoff['observed_total_fee_sompi'],
        'confirmed_history_observed_total_fee_includes_genesis':True,'private_payments_or_exits_performed':False}
    write_new(public/'ACTIVATE-HANDOFF.json',encoded(activation_handoff)+b'\n',0o400)
    result={'schema':'kpxa-research-genesis-activation/v1','status':'GENESIS_CONFIRMED_NO_PRIVATE_PAYMENTS_OR_EXITS_YET',
        'trial_id':trial['trial_id'],'genesis_case':str(case),'genesis_case_sha256':sha(case),
        'descriptor':str(descriptor),'descriptor_sha256':sha(descriptor),'handoff':str(confirmed/'HANDOFF.json'),
        'handoff_sha256':sha(confirmed/'HANDOFF.json'),'selection_sha256':a.selection_sha256,
        'source_closure_sha256':a.sources_sha256,'activation_handoff':str(public/'ACTIVATE-HANDOFF.json'),
        'ordinary_pre_genesis_paid_fee_sompi':ordinary_fees,'actual_terminal_payout_rehearsal_still_required':True,
        'independent_consensus_or_trial_readiness_claimed':False}
    write_new(public/'RESULTS.json',encoded(result)+b'\n',0o400);milestone('genesis-confirmed',handoff=result['handoff']);return result

if __name__=='__main__':
    os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
    for name in ('trial','activation','output','private-output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('trial-sha256','selection-sha256','sources-sha256','funding-sha256'):p.add_argument('--'+name,required=True)
    p.add_argument('--execute',action='store_true')
    try:print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,KeyError,TypeError):p.exit(2,'research activation incomplete; reconcile read-only, never resubmit\n')
