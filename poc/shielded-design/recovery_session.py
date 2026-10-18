"""Continue the ideal model from authenticated MODEL effects, never a live pool.

The new oracle is empty; old proofs are not re-registered. Wallet/prover roles
may coexist in these synthetic harness processes, with no confidentiality claim.
"""
import copy

from model import Pool, ProofOracle, amount, hash_id
from nacl.exceptions import CryptoError
from recovery import model_checkpoint, reconstruct_public
from recovery_format import canonical, reject


class RecoverySession:
    def __init__(self, archive, checkpoint):
        state = reconstruct_public(archive, checkpoint)
        self._archive = copy.deepcopy(archive)
        self.proof_oracle = ProofOracle()
        self._pool = Pool(self.proof_oracle)
        pool = self._pool
        pool.commitments = copy.deepcopy(state['commitments'])
        pool.outputs = copy.deepcopy(state['outputs'])
        pool.nullifiers = set(state['nullifiers'])
        # Retain only the exact permitted historical operation-end roots. A
        # prefix inside a multi-output append is not implicitly a valid anchor.
        anchors = set(state['anchors'])
        pool.anchors = {}
        for end in range(len(pool.commitments) + 1):
            snapshot = pool.commitments[:end]
            anchor = hash_id(snapshot)
            if anchor in anchors:
                pool.anchors[anchor] = snapshot
        if set(pool.anchors) != anchors:
            reject('historical_anchor_unavailable')
        pool.deposits = copy.deepcopy(state['deposits'])
        pool.claims = copy.deepcopy(state['claims'])
        pool.fees = copy.deepcopy(state['fees'])
        pool.processed = {hash_id(record['public']) for record in archive['records'] if record['kind'] == 'operation'}
        pool.reserve = state['reserve_sompi']
        pool.private_total = state['private_liability_sompi']
        pool.rent_reserve = state['rent_reserved_sompi']
        pool.rent_sponsor_available = state['rent_available_sompi']
        pool.rent_external_funded = state['rent_funded_sompi']
        pool.rent_paid = state['rent_paid_sompi']
        pool.invariant()

    def _record(self, kind, **data):
        self._archive['records'].append({'seq': len(self._archive['records']), 'kind': kind,
                                         **copy.deepcopy(data)})

    def process(self, proof):
        """Use the real model predicate plus CURRENT restored economic state."""
        outcome = self._pool.process(proof)
        if outcome['accepted']:
            self._record('operation', public=proof.public)
        else:
            self._record('rejection', operation_hash=hash_id(getattr(proof, 'public', {})))
        return outcome

    def fund_rent(self, value):
        self._pool.fund_rent(value)
        self._record('rent_funding', amount=value)

    def request_refund(self, identity, recipient, signature):
        request = {'deposit': identity, 'recipient': recipient, 'signature': signature}
        try:
            claim = self._pool.request_refund(identity, recipient, signature)
        except (ValueError, KeyError, TypeError, CryptoError):
            operation = hash_id(request)
            self._record('rejection', operation_hash=operation)
            return {'id': operation, 'accepted': False, 'reason': 'model refund request rejected'}
        if self._archive['schema'] != 'kpi-model-records/v3':
            self._archive['schema'] = 'kpi-model-records/v2'
        self._record('refund_request', **request)
        return {'id': claim, 'accepted': True}

    def payout(self, identity, recipient, principal, rent, remaining_reserve):
        """Record a synthetic payment effect, never a native transaction/authority."""
        request = {'claim': identity, 'recipient': recipient, 'principal': principal,
                   'rent': rent, 'remaining_reserve': remaining_reserve}
        try:
            value = self._pool.payout(identity, recipient, principal, rent, remaining_reserve)
        except (ValueError, KeyError, TypeError):
            operation = hash_id(request)
            self._record('rejection', operation_hash=operation)
            return {'id': operation, 'accepted': False, 'reason': 'model payout rejected'}
        self._archive['schema'] = 'kpi-model-records/v3'
        self._record('payout', **request)
        return {'id': identity, 'accepted': True, 'output_sompi': value}

    def pay_fee(self, identity, recipient, value, remaining_reserve):
        """Pay only an already authorized model fee; principal rent is separate."""
        request = {'claim': identity, 'recipient': recipient, 'amount': value,
                   'remaining_reserve': remaining_reserve}
        try:
            if amount(remaining_reserve) != self._pool.reserve - amount(value):
                raise ValueError('fee remaining reserve')
            paid = self._pool.pay_fee(identity, recipient, value)
        except (ValueError, KeyError, TypeError):
            operation = hash_id(request)
            self._record('rejection', operation_hash=operation)
            return {'id': operation, 'accepted': False, 'reason': 'model fee payment rejected'}
        self._archive['schema'] = 'kpi-model-records/v3'
        self._record('fee_payment', **request)
        return {'id': identity, 'accepted': True, 'output_sompi': paid}

    def export(self):
        """Harness-generated next MODEL horizon, not independently proved state."""
        archive = copy.deepcopy(self._archive)
        return {'archive': archive, 'checkpoint': model_checkpoint(archive)}

    def reorganize(self, archive, checkpoint, common_records):
        """Trusted replacement MODEL lineage; no independent chain/fork choice.

        Replaying from genesis removes orphan notes, spentness, claims and paid
        effects together. A missing prefix cannot be repaired from a root alone.
        """
        replacement = RecoverySession(archive, checkpoint)
        old, new = self._archive['records'], replacement._archive['records']
        if (type(common_records) is not int or not 0 <= common_records <= min(len(old), len(new)) or
                canonical(old[:common_records]) != canonical(new[:common_records])):
            reject('common_history_mismatch')
        self.__dict__ = replacement.__dict__
