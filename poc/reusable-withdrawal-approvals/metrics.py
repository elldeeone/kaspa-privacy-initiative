#!/usr/bin/env python3
"""Integer accounting and measured work; no rental or commercial price claim."""
import importlib.util
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('old_costs',ROOT/'poc/batched-payment-costs/costs.py')
old_costs=importlib.util.module_from_spec(spec);spec.loader.exec_module(old_costs)
read=old_costs.read
run,out=map(Path,sys.argv[1:3]);r=read(run/'RESULT.json')
assert r['hostOnlyPreflight'] is False
assert r['approvalBytesSha256Before']==r['approvalBytesSha256After']
assert r['newCohortApprovalsAfterUnrelatedUpdates']==0
records=r['records'];principal=3_000_000_000;remaining=principal;source=3_300_000_000;current=source
fees=payout=refund=0
for index,record in enumerate(records):
    tx=record['transaction'];fee=current-sum(o['value'] for o in tx['outputs'])
    assert fee==record['report']['feeSompi']
    assert record['report']['nativeFullValidation']
    fees+=fee;payout+=record.get('payoutPrincipalSompi',0);refund+=record.get('refundedFeeSompi',0)
    if index:remaining-=record['payoutPrincipalSompi']
    current=tx['outputs'][0]['value'] if remaining else 0
change=records[0]['transaction']['outputs'][1]['value']
assert fees==r['mainNativeFeeSompi'] and fees+payout+refund+change==source
assert payout==principal and remaining==0
old=read(ROOT/'research/withdrawal-request-and-busy-pool-2026-11-06/run/busy/RESULT.json')
names=('initial','unrelated-payment','alice-solo-first','alice-solo-last','terminal-intent')
phases=[];outer=0
for name in names:
    p=run/name;report=read(p/'proof-report.json');outer+=report['totalProofSeconds']
    phases.append(old_costs.resource_phase(run.with_name(run.name+'-monitor'),[((p/'input.bin').stat().st_mtime,(p/'proof-report.json').stat().st_mtime)]))
value={'schema':'reusable-withdrawal-approval-metrics-v1','newCohortApprovalsAfterThreeUnrelatedUpdates':0,'cohortApprovalsCreatedOnce':2,'unchangedApprovalBytesSha256':r['approvalBytesSha256Before'],'oneTimeWalletApprovalSeconds':r['walletApprovalSeconds'],'previousTwoWastedWalletApprovalsSeconds':old['wastedApprovalSeconds'],'unrelatedCurrentStateUpdates':3,'mainCompleteOuterReceipts':5,'allDistinctCompleteReceiptsIncludingCounterfactuals':7,'mainOuterProofSeconds':outer,'mainNativeFeeSompi':fees,'mainNativeFeeKas':fees/1e8,'previousStressRouteNativeFeeSompi':old['totalNativeFeeSompi'],'stressRouteNativeFeeDifferenceSompi':fees-old['totalNativeFeeSompi'],'comparisonScope':'same original payments, Alice self-split and two solo exits; cohort withdrawal order differs; not a new fully priced service comparison','sourceSompi':source,'principalPayoutSompi':payout,'ordinaryFundingChangeSompi':change,'unusedAllowanceRefundSompi':refund,'finalReserveSompi':r['mainFinalReserveSompi'],'finalLiabilitySompi':r['mainFinalLiabilitySompi'],'finalActiveBankOutputs':r['mainFinalActiveBankOutputs'],'mainProofGpuEnergyWh':sum(p['sampledDeviceGpuEnergyWhDuringProofs'] for p in phases),'mainProofResources':phases,'actualProviderInvoiceUsd':0,'completeEconomicCostQualified':False,'outerCurrentStateReprovingStillRequired':True,'limits':'local supplied-source native Full; no live chain, independent client or sustained contention qualification; GPU energy excludes CPU/whole-host/depreciation, and no operator/transport/availability price'}
with out.open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps({k:value[k] for k in ('newCohortApprovalsAfterThreeUnrelatedUpdates','mainNativeFeeKas','stressRouteNativeFeeDifferenceSompi','mainOuterProofSeconds')}))
