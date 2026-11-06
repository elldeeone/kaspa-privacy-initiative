#!/usr/bin/env python3
"""Analyse public, completed histories; never open wallet backups/parameters."""
import json
from pathlib import Path
import sys

SHARED = ['initial', 'external', 'stale']
PRIORITY = ['priority-withdrawal', 'queued-batch', 'later-payouts']
REFERENCE = [f'reference-payment-{i}' for i in range(3)] + ['reference-withdrawal', 'reference-later-payouts']

def read(p):
    return json.loads(p.read_text())

def analyse(run):
    main, reference, service = (read(run/n) for n in ['MAIN.json', 'REFERENCE.json', 'SERVICE.json'])
    assert main['nativeFull'] and reference['nativeFull']
    assert main['reserve'] == main['liability'] == reference['remainingPrincipalSompi'] == 0
    reports = {n:read(run/n/'proof-report.json') for n in SHARED+PRIORITY+REFERENCE}
    fees = lambda v: sum(r['report']['feeSompi'] for r in v['records'])
    result = {'scope':'two complete offline counterfactual histories, one GPU, supplied synthetic funding UTXO',
              'chainAccepted':False, 'independentPeople':False,
              'usefulPaymentSompi':main['usefulPaymentSompi'], 'principalSompi':main['principalSompi'],
              'sameOriginalApprovalsAfterRace':True, 'additionalCohortApprovals':0,
              'uniqueCompleteReceipts':len(reports), 'oneExternalAdvanceOnly':True}
    for name, trace, suffix in [('priority', main, PRIORITY), ('reference', reference, REFERENCE)]:
        seconds=sum(reports[n]['totalProofSeconds'] for n in SHARED+suffix)
        native=fees(trace)/100_000_000
        # Frozen scenario from preceding research, deliberately not a current
        # offer, invoice, reservation or complete hosted-service quote.
        hypothetical_proving_kas=seconds/3600*0.13/0.02987
        result[name]={'nativeFeesSompi':fees(trace), 'nativeFeesKas':native,
                      'nativeFeePercentOfUsefulPayments':100*fees(trace)/main['usefulPaymentSompi'],
                      'successfulSettlementReceipts':len(trace['records'])-1,
                      'chargedCompleteProofSeconds':seconds,
                      'chargedStaleProofSeconds':reports['stale']['totalProofSeconds'],
                      'chargedCompetingPrecomputationSeconds':reports['external']['totalProofSeconds'],
                      'conditionalProofOnlyKas':hypothetical_proving_kas,
                      'conditionalNativePlusProofSubtotalPercent':100*(native+hypothetical_proving_kas)/(main['usefulPaymentSompi']/1e8),
                      'completeTwoPercentTargetQualified':False}
    result['priority']['groupWaitSeconds']=read(run/'PRIORITY-WAIT.json')['groupWaitSeconds']
    result['reference']['groupWaitSeconds']=reference['groupWaitSeconds']
    result['nativeFeesSavedSompi']=fees(reference)-fees(main)
    result['groupWaitReductionPercent']=100*(1-result['priority']['groupWaitSeconds']/result['reference']['groupWaitSeconds'])
    if (run/'ARTIFACT-TIMES.json').exists():
        timing=read(run/'ARTIFACT-TIMES.json')
        ready=(timing['proofReportUnixNs']['queued-batch']-timing['staleWorkItemUnixNs'])/1e9
        shared=read(run/'PRIORITY-WAIT.json')['sharedFirstProofSeconds']
        events=read(run/'ARRIVALS.json')['events']
        arrivals={e['index']:e['seconds'] for e in events if e.get('event')=='payment queued'}
        result['queuedPaymentProofReadiness']={'scope':'request to complete proof; native Full acceptance follows; not chain confirmation',
            'limits':'derived from original same-host filesystem timestamps; reference is a sequential counterfactual clock',
            'prioritySeconds':[ready-arrivals[i] for i in range(3)],
            'referenceSeconds':[shared+(timing['proofReportUnixNs'][f'reference-payment-{i}']-timing['referenceFirstWorkItemUnixNs'])/1e9-arrivals[i] for i in range(3)]}
    result['wallet']={'genuineProofs':sum(c['response']['result'].get('proofs',0) for c in service['calls']),
                      'totalCallSecondsIncludingColdParameterChecks':sum(c['response']['seconds'] for c in service['calls']),
                      'restoredNativePayoutSpends':len(main['restoredPayoutSpends']),
                      'payoutSpendControlFeesSompi':sum(s['report']['feeSompi'] for s in main['restoredPayoutSpends'])}
    result['costLimits']={'frozenConditionalGpuUsdPerHour':0.13, 'frozenConditionalKasUsd':0.02987,
                         'actualProviderInvoiceUsd':0,
                         'conditionalSubtotalExcludes':['cold wallet loading and wallet CPU pricing','optional protected registration and eligibility proof work not retested here','operator and transport','availability','whole-host electricity and depreciation'],
                         'receiverSelfSpendControls':'ordinary later spends, separately reported, excluded from settlement fees',
                         'localWorkIsNotAProviderSpeedOrAvailabilityQualification':True}
    # Roles are the explicitly disclosed contact graph, not hidden commitment
    # labels or transaction positions. Three equal cashout entitlements alone do
    # not prove the graph; the observer must independently know these edges.
    cohort=read(run/'APPROVALS.json')['intent']['denomination']
    initial=main['principalSompi']
    bc=cohort
    ab=cohort+bc
    ad=cohort
    assert initial-ab-ad == cohort
    result['privacy']={'identifiedLocalRequestPayoutAssignments':1,
                       'protectedRegistrationRetested':False,
                       'priorProtectedRegistrationResult':'retained separately; do not relabel this identified run anonymous',
                       'knownRoleControl':{'suppliedEdges':['Alice to Bob','Bob to Carol','Alice to Dave'],
                                           'publicPreBurstUnspentNoteCount':4,
                                           'identifiedDistinctCohortClaims':3,
                                           'remainingRecipientCannotHaveSpentGivenSuppliedPreBurstGraph':'Dave',
                                           'inferredPreBurstCohortBalancesSompi':[cohort]*3,
                                           'inferredDaveBalanceSompi':initial-3*cohort,
                                           'inferredOriginalPaymentsSompi':[ab,bc,ad],
                                           'originalPaymentAmountsUniqueGivenTheseFacts':True,
                                           'laterDaveToAliceIndividualAmounts':'not inferred individually from their sum alone'},
                       'strongKnownOwnerFinancialPrivacyQualified':False}
    return result

if __name__=='__main__':
    print(json.dumps(analyse(Path(sys.argv[1])),indent=2,sort_keys=True))
