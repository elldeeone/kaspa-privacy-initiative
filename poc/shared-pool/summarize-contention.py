#!/usr/bin/env python3
"""Summarize exported race receipts; all timings are local observations."""
import argparse
import datetime
import json
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('export',type=Path,nargs='+');a=p.parse_args()
read=lambda f:json.loads(f.read_text())
ms=lambda s:round(datetime.datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()*1000)
rows=[]
for root in a.export:
    r=read(root/'result.json');loser=root/f"agents/{r['loser']}";winner=root/f"agents/{r['winner']}"
    first=read(loser/'attempt-0.submission.json');retry=read(loser/'attempt-1.submission.json')
    proof=read(loser/'attempt-1.proof.json');finish=read(loser/'result.json');stop=read(winner/'process-exit.json')
    response=read(loser/'attempt-0.response.json')
    assert r['success'] and r['winnerStoppedBeforeLoserPayout']
    rows.append({
        'purpose':r['purpose'],'confirmedTransactions':r['confirmedTransactions'],
        'submittedTransactions':r['submittedTransactions'],'acceptedFeeSompi':r['acceptedFeeSompi'],
        'winningWallet':r['winner'],'rebuildingWallet':r['loser'],'submissionSkewMs':r['submissionSkewMs'],
        'minimumClaimPayoutSompi':r['wallets'][1]['payout']['amount'],
        'payoutsSompi':[w['payout']['amount'] for w in r['wallets']],
        'parameterLoadMs':[read(root/f'agents/{i}/wallet0-isolated/ready.json')['parameter_load_ms'] for i in range(2)],
        'initialProofMs':[read(root/f'agents/{i}/attempt-0.proof.json')['report']['extra']['proving_ms'] for i in range(2)],
        'recoveryProofMs':proof['report']['extra']['proving_ms'],
        'firstSubmissionToLoserPayoutMs':ms(finish['payoutConfirmedAt'])-ms(first['submittedAt']),
        'retrySubmissionToPayoutMs':ms(finish['payoutConfirmedAt'])-ms(retry['submittedAt']),
        'winnerStopToLoserPayoutMs':ms(finish['payoutConfirmedAt'])-ms(stop['observedAt']),
        'winnerStoppedBeforeRecoveryProofCompleted':r['winnerProcessExitedBeforeRecoveryProofCompleted'],
        'initialConflict':response,'oldProofRejected':read(loser/'stale-proof-control.json')['rejected'],
        'terminalReserveSpent':r['terminalReserveSpent'],
    })
print(json.dumps({'runs':rows,'timingScope':'Local wall-clock observations with millisecond timestamp resolution and polling/RPC/proof overhead; not exact network simultaneity or consensus latency.'},indent=2))
