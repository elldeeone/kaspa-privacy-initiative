"""An owner's one-attempt public send record, independent of the coordinator."""
from contextlib import contextmanager
import fcntl
import os

from public import (ROOT, case_summary, checked, encoded, guard_public_paths,
                    need, parse, read_stable_public, sha, trial, write_new)


class OwnerJournal:
    def __init__(self, directory, trial_id, financial_sha256, descriptor_sha256,
                 *, trial_directory, previous_head, prior_evidence_sha256):
        self.directory = checked(directory)
        self.trial_directory = checked(trial_directory)
        need(not self.directory.is_relative_to(ROOT)
             and not self.directory.is_relative_to(self.trial_directory / 'owners'),
             'attempt-outside-code-and-private-owner-tree')
        need(type(previous_head) is dict and set(previous_head) == {'transactionId', 'index'}
             and type(previous_head['index']) is int and previous_head['index'] == 0,
             'accepted-owner-attempt-head')
        sha(previous_head['transactionId']); sha(prior_evidence_sha256)
        self.identity = {'schema': 'kpx6-four-wallet-owner-submit-attempt/v1',
            'trial_id': trial(trial_id), 'financial_profile_sha256': sha(financial_sha256),
            'descriptor_sha256': sha(descriptor_sha256), 'previous_head': previous_head,
            'prior_evidence_sha256': prior_evidence_sha256,
            'operator_journal_or_other_owner_data_required': False}
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        need(self.directory.stat().st_mode & 0o777 == 0o700, 'private-attempt-directory')
        with self.locked():
            path = self.directory / 'IDENTITY.json'
            if path.exists():
                need(self._read(path) == self.identity, 'attempt-identity-mismatch')
            else:
                write_new(path, self.identity)

    @contextmanager
    def locked(self):
        fd = os.open(checked(self.directory / 'LOCK'),
                     os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read(self, path):
        return parse(read_stable_public(path, self.trial_directory))

    def reserve(self, case, submit_source_sha256):
        summary = case_summary(case)
        need(summary['input_outpoints'] == [self.identity['previous_head']],
             'own-attempt-current-physical-head')
        sha(submit_source_sha256)
        with self.locked():
            path = self.directory / 'INTENT.json'
            need(not path.exists(), 'used-owner-attempt-never-resubmit')
            case_path = self.directory / 'CASE.json'
            if case_path.exists():
                need(self._read(case_path) == case, 'prepared-owner-case-differs')
            else:
                write_new(case_path, encoded(case) + b'\n')
            row = {**self.identity, 'summary': summary,
                'submit_source_sha256': submit_source_sha256,
                'status': 'RESERVED_NEVER_RESUBMIT', 'accepted_or_confirmed': False}
            write_new(path, row)
            return row

    def submission_result(self, transaction_id, acknowledged):
        sha(transaction_id); need(type(acknowledged) is bool, 'own-submission-result-type')
        with self.locked():
            row = self._read(self.directory / 'INTENT.json')
            need(row['summary']['transaction_id'] == transaction_id, 'own-submit-response-intent')
            result = {'schema': 'kpx6-four-wallet-owner-submit-response/v1',
                'trial_id': self.identity['trial_id'], 'transaction_id': transaction_id,
                'status': 'RPC_ACK_ONLY' if acknowledged else 'RECONCILE_READ_ONLY',
                'submission_attempted': True, 'accepted_or_confirmed': False}
            write_new(self.directory / 'RESPONSE.json', result)
            return result

    def record_accepted(self, actual_case, evidence_sha256, native_metrics):
        """Fixed accepted-prefix verifier calls this; no public receipt CLI."""
        sha(evidence_sha256); summary = case_summary(actual_case)
        need(type(native_metrics) is dict and native_metrics.get('actual_fee_sompi') == summary['fee_sompi'],
             'own-accepted-native-fee')
        with self.locked():
            intent = self._read(self.directory / 'INTENT.json')
            wanted = intent['summary']
            need(summary['transaction_id'] == wanted['transaction_id']
                 and summary['financial_projection_sha256'] == wanted['financial_projection_sha256'],
                 'own-accepted-financial-effects-differ')
            result = {**self.identity, 'status': 'RECORDED_AFTER_SELECTED_ACCEPTED_PIPELINE',
                'intent_case_sha256': wanted['case_sha256'],
                'accepted_case_sha256': summary['case_sha256'],
                'byte_correspondence': ('EXACT_INTENT_BYTES' if wanted['case_sha256'] == summary['case_sha256']
                    else 'INTENT_VS_ACCEPTED_BYTES_DIFFER'),
                'actual_native_metrics': native_metrics, 'accepted_evidence_sha256': evidence_sha256,
                'no_resubmission_or_intent_mutation': True,
                'reducer_itself_verifies_consensus_or_proofs': False}
            write_new(self.directory / 'ACCEPTED.json', result)
            return result
