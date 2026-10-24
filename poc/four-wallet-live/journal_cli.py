#!/usr/bin/env python3
"""Closed once-send bookkeeping helper. It cannot record chain acceptance."""
import argparse
import copy
from pathlib import Path

from journal import Journal
from owner_journal import OwnerJournal
from public import (ROOT, case_summary, digest, encoded, guard_public_paths, need,
                    parse, read_public, read_stable_public)


def run(a):
    guard_public_paths((a.case, a.sdk_candidate), a.trial_directory)
    case = parse(read_public(a.case, a.case_sha256, a.trial_directory))
    candidate = parse(read_public(a.sdk_candidate, a.sdk_candidate_sha256, a.trial_directory))
    summary = case_summary(case)
    # Do not trust candidate's claimed fingerprints: join the exact body that
    # Node will hand to RPC to the retained intent, including unsigned budgets
    # and witnesses. Conversion is lossless and uses decimal strings at the
    # Python/Node boundary, preserving all u64 bits.
    expected_body = copy.deepcopy(case['transaction'])
    for row in expected_body['inputs']:
        row['sequence'] = str(row['sequence'])
    for row in expected_body['outputs']:
        row['value'] = str(row['value'])
    for name in ('lockTime', 'gas'):
        expected_body[name] = str(expected_body[name])
    expected_body['storageMass'] = str(expected_body.pop('mass'))
    expected_contexts = [{'amount_sompi': str(row['amount']),
        'script_public_key': row['scriptPublicKey'],
        'block_daa_score': str(row['blockDaaScore']),
        'is_coinbase': row['isCoinbase'], 'covenant_id': row['covenantId']}
        for row in case['entries']]
    need(candidate['transaction'] == expected_body and candidate['contexts'] == expected_contexts,
         'exact-SDK-candidate-body-context-and-intent')
    need(candidate['schema'] == 'kpx6-four-wallet-public-SDK-candidate/v1'
         and candidate['trial_id'] == a.trial_id and candidate['stage'] == a.stage
         and candidate['financial_profile_sha256'] == a.financial_sha256
         and candidate['descriptor_sha256'] == a.descriptor_sha256
         and candidate['case_file_sha256'] == a.case_sha256
         and candidate['canonical_case_sha256'] == summary['case_sha256']
         and candidate['financial_projection_sha256'] == summary['financial_projection_sha256']
         and candidate['transaction']['id'] == summary['transaction_id'], 'journal-candidate-binding')
    if a.stage == 'owner-exit':
        need(a.owner_attempt and not a.journal, 'standalone-owner-attempt-only')
        journal = OwnerJournal(a.owner_attempt, a.trial_id, a.financial_sha256,
            a.descriptor_sha256, trial_directory=a.trial_directory,
            previous_head=candidate['previous_head'],
            prior_evidence_sha256=candidate['prior_evidence_sha256'])
    else:
        need(a.journal and not a.owner_attempt, 'campaign-journal-only')
        journal = Journal(a.journal, a.trial_id, a.financial_sha256,
            a.descriptor_sha256, trial_directory=a.trial_directory)
    if a.operation == 'reserve':
        submit_sha = digest(read_stable_public(ROOT / 'poc/four-wallet-live/submit.mjs',
                                               a.trial_directory))
        need(submit_sha == a.submit_source_sha256, 'running-submit-source-binding')
        if a.stage == 'owner-exit':
            result = journal.reserve(case, submit_sha)
        else:
            result = journal.reserve(a.stage, case, previous_head=candidate['previous_head'],
                prior_evidence_sha256=candidate['prior_evidence_sha256'], submit_source_sha256=submit_sha)
        return {'status': result['status'], 'transaction_id': summary['transaction_id'],
                'accepted_or_confirmed': False}
    need(a.acknowledged in ('true', 'false'), 'explicit-submission-result')
    acknowledged = a.acknowledged == 'true'
    if a.stage == 'owner-exit':
        return journal.submission_result(summary['transaction_id'], acknowledged)
    return journal.submission_result(a.stage, summary['transaction_id'], acknowledged=acknowledged)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('reserve', 'response'))
    for name in ('trial-directory', 'case', 'sdk-candidate'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('trial-id', 'financial-sha256', 'descriptor-sha256', 'stage',
                 'case-sha256', 'sdk-candidate-sha256'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--journal', type=Path); p.add_argument('--owner-attempt', type=Path)
    p.add_argument('--submit-source-sha256'); p.add_argument('--acknowledged')
    return p


if __name__ == '__main__':
    p = parser()
    try:
        print(encoded(run(p.parse_args())).decode())
    except (ValueError, OSError, KeyError, TypeError):
        p.exit(2, 'four-wallet once-send record incomplete; used intent remains reserved\n')
