#!/usr/bin/env python3
"""Recheck the retained public cost/privacy packet without secrets or a prover."""
from pathlib import Path
import hashlib
import json
import sys
import observe

ROOT=Path(__file__).resolve().parents[2]
PUBLIC=ROOT/'research/batched-payment-costs-2026-11-06/run'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return observe.read(p)
def main():
    reuse=read(Path(__file__).with_name('REUSE.json'))
    for p,expected in reuse['sources'].items():assert sha(ROOT/p)==expected,('changed reused source',p)
    for target,source in reuse['exactCopies'].items():assert (Path(__file__).parent/target).read_bytes()==(ROOT/source).read_bytes()
    manifest=read(PUBLIC/'MANIFEST.json')
    files={str(p.relative_to(PUBLIC)):p for p in PUBLIC.rglob('*') if p.is_file() and p.name!='MANIFEST.json'}
    assert set(files)==set(manifest['files'])
    for name,p in files.items():assert p.stat().st_size==manifest['files'][name]['bytes'] and sha(p)==manifest['files'][name]['sha256'],name
    score=PUBLIC/'scores';validation=read(score/'VALIDATION.json');counts={}
    for p in sorted(score.glob('*-prediction.json')):
        name=p.name.removesuffix('-prediction.json')
        prediction=observe.predict(read(score/(name+'-observation.json')))
        assert prediction==read(p),name;counts[name]=prediction['assignmentCount']
    assert counts==validation['counts']
    for name in ['BASE-PREDICTION-SEAL.json','CONTROL-PREDICTION-SEAL.json']:
        seal=read(score/name);assert seal['observerSha256']==sha(Path(observe.__file__))
        for p,expected in seal['files'].items():assert sha(score/p)==expected
    assert validation['baseSealSha256']==sha(score/'BASE-PREDICTION-SEAL.json')
    assert validation['controlsSealSha256']==sha(score/'CONTROL-PREDICTION-SEAL.json')
    costs=read(PUBLIC/'costs/COSTS.json')
    assert costs['valuationSnapshotSha256']==sha(ROOT/'research/batched-payment-costs-2026-11-06/VALUATION-ASSUMPTIONS.json')
    assert costs['providerCatalogueReferenceSha256']==sha(ROOT/'research/batched-payment-costs-2026-11-06/PROVIDER-REFERENCE.json')
    for name,c in costs['worlds'].items():
        world=read(PUBLIC/'core'/name/'world.json');txs=world['transactions'];fees=0;principal=c['usefulPaymentSompi'];balance=principal+300_000_000
        for i,r in enumerate(txs):
            tx=r['transaction'];fee=balance-sum(o['value'] for o in tx['outputs']);assert fee==r['report']['feeSompi']==r['report']['minimumDefaultRelayFeeSompi'];fees+=fee
            assert r['report']['fitsBlock'] and r['report']['nativeFullValidation']
            if i:principal-=r['payoutPrincipalSompi']
            balance=tx['outputs'][0]['value'] if principal else 0
        assert fees==c['nativeFeesSompi']==world['totalNativeFeeSompi']
        assert c['initialSourceSompi']==fees+c['principalPayoutSompi']+c['ordinaryFundingChangeSompi']+c['unusedFeeAllowanceRefundSompi']
        assert principal==balance==world['finalPrincipalSompi']==world['finalPrivateLiabilitySompi']==0
        assert c['nativeFeeTarget2Percent']==(fees*100<=c['usefulPaymentSompi']*2)
        for model in c['economicSensitivity']:
            work=c['measuredSequentialWorkSeconds'];rate=model['assumedWholeProverUsdPerHour'];price=costs['snapshotKasUsd']
            expected=fees/1e8*price+work/3600*(rate+20*.1/730)
            assert abs(model['networkPlusProverAndActiveDiskUsd']-expected)<1e-10
            assert abs(model['costPercent']-expected/(c['usefulPaymentSompi']/1e8*price)*100)<1e-8
    assert costs['worlds']['30-kas/named-batched']['nativeFeesSompi']==costs['worlds']['30-kas/batched']['nativeFeesSompi']
    assert not costs['completeEconomicCostQualified'] and costs['noClaimOfZeroHardwareCost']
    abort=read(PUBLIC/'extras/abort.json');assert abort['nativeFeeSompi']==abort['principalLostSompi']==0 and abort['deliveredExitApprovals']==2
    solo=read(PUBLIC/'extras/solo.json');assert solo['finalPrincipalSompi']==0 and solo['restoredWallets']==3 and solo['issuerOrPeerAuthorizationRequired'] is False
    for p in (PUBLIC/'extras').glob('solo-*-nf-replay.json'):assert 'current economic nullifier spent' in read(p)['error']
    refund=read(PUBLIC/'extras/refund.json');assert refund['replayRejected'] and refund['finalPrincipalSompi']==0
    replay=read(PUBLIC/'replay/public-replay.json');assert len(replay['worlds'])==4 and all(w['allNativeFull'] and not w['privateFilesRead'] for w in replay['worlds'])
    print(json.dumps({'ownershipAssignments':counts,'exactNativeFeesAndCashflowsVerified':True,'allPublicSourceAndEvidenceHashesVerified':True,'publicProofReplayReceiptPresent':True,'nativeFeeTargetIsSeparateFromFullEconomicQualification':True},indent=2))
if __name__=='__main__':main()
