"""Durable one-attempt experiment journal; it is no consensus authority.

Only the fixed runner's fresh accepted-prefix/native/proof pipeline may call
record_accepted. These structural methods do not turn caller JSON into chain
evidence. Raw journal records and any private controller mapping stay outside Git.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path

from public import (ROOT, amount, case_summary, checked, digest, encoded, fields,
                    guard_public_paths, need, parse, read_stable_public, sha, trial, write_new)

NORMAL = ('funding', 'settlement', 'exit-01', 'exit-02', 'exit-03', 'exit-04')
ABORT = ('funding', 'fallback-01', 'fallback-02')
STAGES = frozenset(NORMAL + ABORT)


class Journal:
    def __init__(self, directory, trial_id, financial_sha256, descriptor_sha256,
                 *, trial_directory):
        self.directory = checked(directory)
        self.trial_directory = checked(trial_directory)
        need(not self.directory.is_relative_to(ROOT), 'journal-outside-code-tree')
        need(not self.directory.is_relative_to(self.trial_directory / 'owners'),
             'journal-outside-private-owner-tree')
        self.identity = {'schema': 'kpx6-four-wallet-live-journal/v1',
            'trial_id': trial(trial_id), 'financial_profile_sha256': sha(financial_sha256),
            'descriptor_sha256': sha(descriptor_sha256),
            'journal_is_consensus_or_withdrawal_authority': False}
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        need(self.directory.stat().st_mode & 0o777 == 0o700, 'private-controller-directory')
        self.intents = self.directory / 'intents'; self.receipts = self.directory / 'receipts'
        self.cases = self.directory / 'cases'
        self.intents.mkdir(exist_ok=True, mode=0o700)
        self.receipts.mkdir(exist_ok=True, mode=0o700)
        self.cases.mkdir(exist_ok=True, mode=0o700)
        with self.locked():
            header = self.directory / 'IDENTITY.json'
            if header.exists():
                need(self._read(header) == self.identity, 'journal-identity-mismatch')
            else:
                write_new(header, self.identity)

    @contextmanager
    def locked(self):
        lock = checked(self.directory / 'LOCK')
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read(self, path):
        try:
            return parse(read_stable_public(path, self.trial_directory))
        except (ValueError, UnicodeError, OSError):
            raise ValueError('four-wallet-live:corrupt-journal-reconcile-only') from None

    def _retain_case(self, case, summary):
        path = self.cases / (summary['case_sha256'] + '.json')
        if path.exists():
            need(self._read(path) == case, 'retained-public-case-differs')
        else:
            write_new(path, encoded(case) + b'\n')

    def _records(self, directory):
        result = {}
        for path in sorted(directory.iterdir()):
            need(path.name.endswith('.json') and path.stem in STAGES, 'unknown-journal-record')
            value = self._read(path)
            need(value.get('stage') == path.stem
                 and value.get('trial_id') == self.identity['trial_id']
                 and value.get('financial_profile_sha256') == self.identity['financial_profile_sha256']
                 and value.get('descriptor_sha256') == self.identity['descriptor_sha256'],
                 'journal-record-identity')
            result[path.stem] = value
        return result

    def _state(self):
        intents, receipts = self._records(self.intents), self._records(self.receipts)
        need(set(receipts) <= set(intents), 'acceptance-without-intent')
        ids = [row['summary']['transaction_id'] for row in intents.values()]
        need(len(ids) == len(set(ids)), 'duplicate-journal-transaction-id')
        return intents, receipts

    @staticmethod
    def _order(stage):
        return ABORT if stage.startswith('fallback-') else NORMAL

    def reserve(self, stage, case, *, previous_head, prior_evidence_sha256, submit_source_sha256):
        need(stage in STAGES, 'closed-submission-stage')
        summary = case_summary(case)
        sha(submit_source_sha256)
        if stage == 'funding':
            need(previous_head is None and prior_evidence_sha256 is None
                 and len(summary['input_outpoints']) == 2, 'funding-no-previous-W')
        else:
            sha(prior_evidence_sha256)
            need(type(previous_head) is dict and summary['input_outpoints'] == [previous_head],
                 'candidate-spends-fresh-physical-head')
        with self.locked():
            intents, accepted = self._state()
            need(stage not in intents, 'used-stage-never-resubmit')
            need(summary['transaction_id'] not in
                 {row['summary']['transaction_id'] for row in intents.values()},
                 'used-transaction-id-never-resubmit')
            if stage == 'funding':
                need(not intents, 'funding-first')
            else:
                order = self._order(stage); index = order.index(stage)
                need(set(accepted) == set(order[:index])
                     and set(intents) == set(accepted), 'accepted-predecessors-only')
                predecessor = accepted[order[index - 1]]
                need(predecessor['new_head'] == previous_head
                     and predecessor['remaining_reserve_sompi'] > 0,
                     'fresh-predecessor-physical-head')
            row = {**self.identity, 'stage': stage, 'status': 'RESERVED_NEVER_RESUBMIT',
                'summary': summary, 'previous_head': previous_head,
                'prior_evidence_sha256': prior_evidence_sha256,
                'submit_source_sha256': submit_source_sha256,
                'submission_acknowledgment_is_confirmation': False}
            self._retain_case(case, summary)
            write_new(self.intents / (stage + '.json'), row)
            return row

    def submission_result(self, stage, transaction_id, *, acknowledged):
        """An unknown response remains reserved forever; only reads may retry."""
        need(stage in STAGES and type(acknowledged) is bool, 'submission-result-fields')
        sha(transaction_id)
        with self.locked():
            intents, _ = self._state()
            need(stage in intents and intents[stage]['summary']['transaction_id'] == transaction_id,
                 'submission-result-intent-binding')
            row = {**self.identity, 'stage': stage, 'transaction_id': transaction_id,
                'status': 'RPC_ACK_ONLY' if acknowledged else 'RECONCILE_READ_ONLY',
                'accepted_or_confirmed': False, 'submission_attempted': True}
            write_new(self.directory / (stage + '.submission-result.json'), row)
            return row

    def record_accepted(self, stage, actual_case, *, evidence_sha256, new_head,
                        remaining_reserve_sompi, native_metrics):
        """Called only after fixed actual Full-page/native/semantic verification.

        This reducer verifies correspondence/accounting, not chain or proofs.
        There is intentionally no public 'accept JSON receipt' CLI.
        """
        need(stage in STAGES, 'closed-observation-stage')
        sha(evidence_sha256)
        remaining = amount(remaining_reserve_sompi)
        summary = case_summary(actual_case)
        need(type(native_metrics) is dict and native_metrics.get('actual_fee_sompi') == summary['fee_sompi'],
             'native-actual-fee-binding')
        if remaining:
            need(new_head == {'transactionId': summary['transaction_id'], 'index': 0},
                 'actual-continuation-head-zero')
            need(actual_case['transaction']['outputs'][0]['value'] == remaining,
                 'actual-continuation-value')
        else:
            need(new_head is None, 'terminal-no-head')
        need((remaining == 0) == (stage in ('exit-04', 'fallback-02')),
             'campaign-exit-count-and-reserve')
        with self.locked():
            intents, accepted = self._state()
            need(stage in intents and stage not in accepted, 'exact-once-observation')
            intended = intents[stage]['summary']
            need(summary['transaction_id'] == intended['transaction_id']
                 and summary['financial_projection_sha256'] == intended['financial_projection_sha256'],
                 'actual-accepted-financial-effects-differ')
            variant = summary['case_sha256'] != intended['case_sha256']
            row = {**self.identity, 'stage': stage,
                'status': 'RECORDED_AFTER_SELECTED_ACCEPTED_PIPELINE',
                'intent_case_sha256': intended['case_sha256'],
                'accepted_case_sha256': summary['case_sha256'],
                'byte_correspondence': 'INTENT_VS_ACCEPTED_BYTES_DIFFER' if variant else 'EXACT_INTENT_BYTES',
                'summary': summary, 'accepted_evidence_sha256': evidence_sha256,
                'new_head': new_head, 'remaining_reserve_sompi': remaining,
                'actual_native_metrics': native_metrics,
                'no_resubmission_or_intent_mutation': True,
                'node_scope': 'TRUSTED_NONATOMIC_VALIDATING_NODE_AND_RETAINED_FULL_PAGES',
                'journal_reducer_itself_verifies_consensus_or_proofs': False}
            self._retain_case(actual_case, summary)
            write_new(self.receipts / (stage + '.json'), row)
            return row

    def snapshot(self):
        with self.locked():
            intents, receipts = self._state()
            return {'identity': self.identity, 'intents': intents, 'receipts': receipts,
                'ready_or_privacy_qualification': False}

    def accepted_cases(self):
        with self.locked():
            _, receipts = self._state()
            order = ABORT if any(k.startswith('fallback-') for k in receipts) else NORMAL
            return [(stage, self._read(self.cases / (receipts[stage]['accepted_case_sha256'] + '.json')))
                    for stage in order if stage in receipts]
