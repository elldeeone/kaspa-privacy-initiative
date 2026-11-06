#!/usr/bin/env python3
"""Exact native quotes plus explicitly priced proof-work sensitivities."""
from datetime import datetime
from pathlib import Path
import hashlib
import json
import sys

def read(p):return json.loads(p.read_text())
def write(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2,sort_keys=True);f.write('\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def resource_phase(monitor,intervals):
    anchor=monitor/'TIMING-ANCHOR.json'
    if anchor.exists():origin=read(anchor)['hostProcessCreatedUnixSeconds']
    else:origin=datetime.fromisoformat(read(monitor/'INVOCATION.json')['launchedAtUtc']).timestamp()
    samples=[json.loads(line) for line in (monitor/'resource-samples.jsonl').read_text().splitlines()]
    energy=0;rss=0;vram=0;seconds=0
    for prev,cur in zip(samples,samples[1:]):
        t1=origin+prev['seconds'];t2=origin+cur['seconds']
        overlap=sum(max(0,min(t2,end)-max(t1,start)) for start,end in intervals)
        if overlap:
            if all('gpuGlobalTelemetry'in x for x in (prev,cur)):
                power=sum(float(x['gpuGlobalTelemetry'].split(',')[0]) for x in (prev,cur))/2
                energy+=overlap*power/3600
            seconds+=overlap;rss=max(rss,prev['summedRssBytes'],cur['summedRssBytes']);vram=max(vram,prev.get('matchingGpuMemoryMiB',0),cur.get('matchingGpuMemoryMiB',0))
    return {'samplingOriginUnixSeconds':origin,'proofIntervalsUnixSeconds':intervals,'sampledDeviceGpuEnergyWhDuringProofs':energy,'sampledProofIntervalSeconds':seconds,'peakSummedOwnedRssBytesDuringProofs':rss,'peakMatchingGpuMemoryMiBDuringProofs':vram,'limits':'device-wide GPU energy including idle/display; one-second/clock uncertainty; no CPU or whole-host energy/depreciation; shared RSS may double-count; samples can miss peaks'}
def proof_work(dir):
    if (dir/'REUSED.json').exists():return proof_work(Path(read(dir/'REUSED.json')['exactSource']))
    p=dir/'proof-report.json';r=read(p)
    origin=next(parent for parent in dir.parents if parent.parent.name=='batched-payment-costs')
    monitor=origin.with_name(origin.name+'-monitor')
    return r,(dir/'input.bin').stat().st_mtime,p.stat().st_mtime,monitor

def main():
    run=Path(sys.argv[1]);extras=Path(sys.argv[2]);out=Path(sys.argv[3]);out.mkdir()
    root=Path(__file__).resolve().parents[2];assumptions=read(root/'research/batched-payment-costs-2026-11-06/VALUATION-ASSUMPTIONS.json')
    price=float(assumptions['quote']['result']['KASUSD']['c'][0]);rates=assumptions['modelProverUsdPerHour'];tariffs=assumptions['modelElectricityUsdPerKwh']
    reference=read(root/'research/batched-payment-costs-2026-11-06/PROVIDER-REFERENCE.json')
    reference_rate=reference['response']['data']['gpuTypes'][0]['communityPrice'];rates=sorted(set(rates+[reference_rate]))
    monitor=run.with_name(run.name+'-monitor');extra_monitor=extras.with_name(extras.name+'-monitor')
    result={};all_transactions=0
    for name in ['30-kas/named','30-kas/named-batched','30-kas/batched','75-kas/batched']:
        dir=run/name;world=read(dir/'world.json');txs=world['transactions'];intervals={};proofs=[];exit_proof_work=0
        for record in txs[1:]:
            fee=record['report']['feeSompi'];assert fee==record['report']['minimumDefaultRelayFeeSompi']
            # Derive fee independently from the actual linked effects (all outputs).
            assert record['report']['nativeFullValidation']
        paths=sorted([*dir.glob('payment-*/proof-report.json'),*dir.glob('withdraw-*/proof-report.json')])
        for path in paths:
            pr,t1,t2,physical_monitor=proof_work(path.parent);intervals.setdefault(physical_monitor,[]).append((t1,t2));proofs.append(pr)
        assert len(proofs)==len(txs)-1
        parts=[resource_phase(m,windows) for m,windows in intervals.items()]
        resource={'sampledDeviceGpuEnergyWhDuringProofs':sum(r['sampledDeviceGpuEnergyWhDuringProofs'] for r in parts),'sampledProofIntervalSeconds':sum(r['sampledProofIntervalSeconds'] for r in parts),'peakSummedOwnedRssBytesDuringProofs':max(r['peakSummedOwnedRssBytesDuringProofs'] for r in parts),'peakMatchingGpuMemoryMiBDuringProofs':max(r['peakMatchingGpuMemoryMiBDuringProofs'] for r in parts),'physicalMonitorContributions':{m.name:r for m,r in zip(intervals,parts)},'limits':parts[0]['limits']}
        fees=sum(r['report']['feeSompi'] for r in txs);assert fees==world['totalNativeFeeSompi']
        useful=world['usefulPaymentSompi'];payout=sum(r.get('payoutPrincipalSompi',0) for r in txs)
        fee_refund=sum(r.get('refundedFeeSompi',0) for r in txs);change=txs[0]['transaction']['outputs'][1]['value']
        source=useful+300_000_000
        current_value=source;remaining=useful
        for i,record in enumerate(txs):
            tx=record['transaction'];actual_fee=current_value-sum(o['value'] for o in tx['outputs'])
            assert actual_fee==record['report']['feeSompi'],'independent actual input/output fee'
            if i:remaining-=record['payoutPrincipalSompi']
            current_value=tx['outputs'][0]['value'] if remaining else 0
        assert fees+payout+fee_refund+change==source
        assert payout==useful
        payment_fees=sum(r['report']['feeSompi'] for r in txs[1:] if r.get('payoutPrincipalSompi',0)==0)
        withdrawal_fees=fees-payment_fees-txs[0]['report']['feeSompi']
        registration=read(dir/'registration-resources.json') if (dir/'registration-resources.json').exists() else {'seconds':0,'genuineEligibilityProofs':0}
        wallet_prepare=sum(r['report']['walletPreparationSeconds'] for r in txs[1:])
        outer=sum(p['totalProofSeconds'] for p in proofs)
        measured_work=world['walletSetupSeconds']+world['walletPaymentProofSeconds']+wallet_prepare+outer+registration['seconds']
        storage_rate=20*.10/730 # Assumed active 20GB container; not an invoice.
        economic=[]
        for rate in rates:
            prover=measured_work*rate/3600;storage=measured_work*storage_rate/3600;network=fees/1e8*price;total=network+prover+storage
            economic.append({'assumedWholeProverUsdPerHour':rate,'rateSource':'public catalogue reference with null live capacity, not a quote' if rate==reference_rate else 'explicit hypothetical sensitivity','networkUsdAtSnapshot':network,'modeledProverUsd':prover,'modeledActive20GbDiskUsd':storage,'networkPlusProverAndActiveDiskUsd':total,'equivalentKasAtSnapshot':total/price,'costPercent':total/(useful/1e8*price)*100,'minimumUsefulKasFor2PercentAtSameMeasuredWork':total/price/.02,'minimumUsefulKasFor3PercentAtSameMeasuredWork':total/price/.03,'scope':'conditional warm-work model, not invoice or fully priced anonymous service; excludes unmeasured cold setup, operator, retained storage, transport and margin; no different-GPU speed claim'})
        result[name]={'nativeTransactions':len(txs),'outerReceipts':len(proofs),'proofOperations':sum(p['operations'] for p in proofs),'nativeFeesSompi':fees,'nativeFeesKas':fees/1e8,'nativeFeePercent':fees/useful*100,'depositFeeSompi':txs[0]['report']['feeSompi'],'paymentSettlementFeeSompi':payment_fees,'withdrawalFeeSompi':withdrawal_fees,'unusedFeeAllowanceRefundSompi':fee_refund,'ordinaryFundingChangeSompi':change,'explicitPrepaidFeeAllowanceSompi':200_000_000,'initialSourceSompi':source,'usefulPaymentSompi':useful,'principalPayoutSompi':payout,'nativeBudgetUnitsPerInput':1600,'outerProofSeconds':outer,'walletSetupSeconds':world['walletSetupSeconds'],'walletCreditAndPaymentProofSeconds':world['walletPaymentProofSeconds'],'walletExitPreparationSeconds':wallet_prepare,'registration':registration,'measuredSequentialWorkSeconds':measured_work,'resourceSamples':resource,'gpuOnlyElectricitySensitivities':[{'assumedUsdPerKwh':t,'deviceGpuEnergyUsd':resource['sampledDeviceGpuEnergyWhDuringProofs']/1000*t,'wholeHostCost':False} for t in tariffs],'economicSensitivity':economic,'proofs':proofs,'nativeFeeTarget2Percent':fees*100<=useful*2,'finalPrincipalSompi':world['finalPrincipalSompi'],'feesWerePaidOnChain':False}
        all_transactions+=len(txs)
    assert result['30-kas/named-batched']['nativeFeesSompi']==result['30-kas/batched']['nativeFeesSompi'],'matched batching native fee premium'
    abort=read(extras/'abort.json');retry=read(extras/'retry.json');solo=read(extras/'solo.json');refund=read(extras/'refund.json')
    fallback=[]
    for p in sorted(extras.glob('solo-*-native.json')):
        r=read(p);fallback.append({'feeSompi':r['report']['feeSompi'],'walletPreparationSeconds':r['report']['walletPreparationSeconds'],'proving':r['report']['proving']})
    cases=read(extras/'negative-controls.json')
    failure={'abortedRound':abort,'retry':{k:v for k,v in retry.items() if k!='record'},'retryNativeFeeSompi':retry['record']['report']['feeSompi'],'restoredSoloExits':fallback,'soloFullNativeFeesIncludingDepositAndPaymentSompi':sum(r['report']['feeSompi'] for r in solo['records']),'pendingDepositRefundNativeFeesSompi':sum(r['report']['feeSompi'] for r in refund['records']),'pendingDepositPrincipalRefundSompi':refund['principalRefundedSompi'],'negativeControls':len(cases),'finalPrincipalAfterIndependentDrainSompi':solo['finalPrincipalSompi']}
    # Failure proof work is charged separately, never hidden in successful fees.
    failure['abortedRoundProverSensitivity']=[{'assumedUsdPerHour':r,'measuredWorkUsd':abort['seconds']*r/3600,'equivalentKasAtSnapshot':abort['seconds']*r/3600/price,'nativeFeeSompi':0} for r in rates]
    write(out/'COSTS.json',{'schema':'complete-offline-batched-payment-costs-v1','coreRun':run.name,'extraRun':extras.name,'image':read(monitor/'FREEZE.json')['image'],'valuationSnapshotSha256':sha(root/'research/batched-payment-costs-2026-11-06/VALUATION-ASSUMPTIONS.json'),'snapshotKasUsd':price,'providerCatalogueReferenceSha256':sha(root/'research/batched-payment-costs-2026-11-06/PROVIDER-REFERENCE.json'),'catalogueRateIsNotAvailabilityOrMeasuredRemotePerformance':True,'worlds':result,'recoveryAndFailure':failure,'actualResearchCampaignResources':{'core':read(monitor/'RESOURCES.json'),'extras':read(extra_monitor/'RESOURCES.json')},'actualProviderInvoiceUsd':0,'noClaimOfZeroHardwareCost':True,'completeEconomicCostQualified':False,'unmeasuredCosts':assumptions['unpriced'],'counterfactualWorldsAreSeparate':True})
    print(json.dumps({n:{k:r[k] for k in ['nativeFeesKas','nativeFeePercent','outerProofSeconds','measuredSequentialWorkSeconds','nativeFeeTarget2Percent']} for n,r in result.items()},indent=2))
if __name__=='__main__':main()
