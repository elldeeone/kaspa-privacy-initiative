#!/usr/bin/env python3
"""Measured proof/native results and a clearly conditional old-tariff subtotal."""
import importlib.util
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('previous_costs',ROOT/'poc/batched-payment-costs/costs.py')
previous=importlib.util.module_from_spec(spec);spec.loader.exec_module(previous)
read=previous.read
busy,quiet,out=map(Path,sys.argv[1:4])
b=read(busy/'RESULT.json');q=read(quiet/'RESULT.json')
old=read(ROOT/'research/batched-payment-costs-2026-11-06/run/costs/COSTS.json')
old30=old['worlds']['30-kas/batched'];price=old['snapshotKasUsd']
dynamic=b['exactInputDynamicControl'];pinned=b['exactInputPinned']
assert dynamic['sourceInputSha256']==pinned['sourceInputSha256']
assert (busy/'dynamic-control/input.bin').read_bytes()==(busy/'pinned-initial/input.bin').read_bytes()
assert (busy/'dynamic-control/expected-journal.bin').read_bytes()==(busy/'pinned-initial/expected-journal.bin').read_bytes()
outer=q['initialProof']['totalProofSeconds']+q['terminalProof']['totalProofSeconds']
overhead=old30['measuredSequentialWorkSeconds']-old30['outerProofSeconds']-old30['walletExitPreparationSeconds']+q['terminalWalletPreparationSeconds']
work=outer+overhead
rates=[.10,.13,.25,1.0];storage_per_hour=20*.1/730
models=[]
for useful in (30,75):
    for rate in rates:
        usd=q['totalNativeFeeSompi']/1e8*price+work*(rate+storage_per_hour)/3600
        models.append({'usefulKas':useful,'assumedUsdPerHour':rate,'networkPlusProverAndActiveDiskUsd':usd,'subtotalCostPercent':usd/(useful*price)*100,'largerPaymentMeasuredWithPinnedGuest':False if useful==75 else True,'scope':'old tariff/snapshot and prior non-outer overhead held fixed; no Tor/operator/availability/idle/cold allocation cost; not complete commercial price'})
def physical(case):
    if (case/'REUSED.json').exists():return physical(Path(read(case/'REUSED.json')['exactSource']))
    monitor=case.parent.with_name(case.parent.name+'-monitor')
    return previous.resource_phase(monitor,[((case/'input.bin').stat().st_mtime,(case/'proof-report.json').stat().st_mtime)])
phases=[physical(busy/'pinned-initial'),physical(quiet/'quiet-terminal')]
native=q['totalNativeFeeSompi'];assert native==old30['nativeFeesSompi']
records=q['records'];source=3_300_000_000
payouts=sum(r.get('payoutPrincipalSompi',0) for r in records)
refund=sum(r.get('refundedFeeSompi',0) for r in records)
change=records[0]['transaction']['outputs'][1]['value']
assert native+payouts+refund+change==source
value={'schema':'withdrawal-followup-metrics-v1','matchedInputSha256':pinned['sourceInputSha256'],'dynamicSeconds':dynamic['totalProofSeconds'],'pinnedSeconds':pinned['totalProofSeconds'],'matchedWallSecondsReductionPercent':(1-pinned['totalProofSeconds']/dynamic['totalProofSeconds'])*100,'matchedTotalCyclesReductionPercent':(1-pinned['stats']['total_cycles']/dynamic['stats']['total_cycles'])*100,'quietOuterProofSeconds':outer,'previousQuietOuterProofSeconds':old30['outerProofSeconds'],'quietOuterWallSecondsReductionPercent':(1-outer/old30['outerProofSeconds'])*100,'quietNativeFeesKas':native/1e8,'quietNativeFeePercentOf30Kas':native/30e8*100,'quietNativeFeeChangeSompi':native-old30['nativeFeesSompi'],'additionalRecipientKeySpendControlFeesSompi':sum(c['report']['feeSompi'] for c in q['nativePayoutKeyRecoveryControls']),'quietSourceSompi':source,'quietPrincipalPayoutSompi':payouts,'quietRefundSompi':refund,'quietOrdinaryChangeSompi':change,'sampledGpuWhDuringQuietProofs':sum(p['sampledDeviceGpuEnergyWhDuringProofs'] for p in phases),'quietProofResourcePhases':phases,'busyNativeFeesKas':b['totalNativeFeeSompi']/1e8,'busyWastedApprovalSeconds':b['wastedApprovalSeconds'],'busyWastedApprovalNativeFeesSompi':0,'busyFeesCoverAdditionalPaymentAndTwoSoloExits':True,'reusedPriorNonOuterOverheadSeconds':overhead,'conditionalWarmSubtotalWorkSeconds':work,'oldSnapshotKasUsd':price,'economicSubtotals':models,'unpriced':old['unmeasuredCosts']+['actual onion coordinator/client service cost and transport latency','new pinned 75-KAS complete run'],'completeEconomicCostQualified':False,'actualProviderInvoiceUsd':0,'timingLimits':'one matched pair and one quiet counterfactual; some concurrent CPU work, no parallel GPU prover; no general latency or rented-hardware throughput promise'}
with out.open('x') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
print(json.dumps({k:value[k] for k in ('matchedWallSecondsReductionPercent','quietOuterProofSeconds','quietNativeFeesKas','busyNativeFeesKas','busyWastedApprovalSeconds')}))
