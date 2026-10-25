"""Preauthorization fee quotes from the selected actual native codec.

Shape probes contain zero Spend proofs and public template outputs. They are
quotes only, never authorizations. Actual complete owner projections are quoted
again without changing their effects before any Spend/Exit proof is generated.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from support import DOMAIN, digest, fields, hx, need, parse, read, selected_module


class NativeFees:
    def __init__(self, assets, raw, expected_sha256):
        need(digest(raw) == hx(expected_sha256, 32).hex(), 'selected-native-fee-policy-pin')
        value = parse(raw)
        fields(value, ('schema', 'native_case', 'codec', 'outer_image_hex32',
            'component_profile_sha256', 'payment_compute_budget', 'exit_compute_budget',
            'fee_rate_sompi_per_mass', 'template_projection'), 'native-fee-policy-fields')
        need(value['schema'] == 'kpxa-native-fee-policy/v1', 'native-fee-policy-schema')
        for key in ('payment_compute_budget', 'exit_compute_budget', 'fee_rate_sompi_per_mass'):
            need(type(value[key]) is int and value[key] > 0, 'native-fee-policy-integer')
        self.assets, self.value = assets, value
        self.module = selected_module(value['native_case'], '_kpxa_selected_native_fee_codec')
        # Authenticate the executable before the first quote. NativeCodec also
        # rechecks the whole selected ELF for every request.
        read(value['codec']['path'], value['codec']['sha256'])
        self.codec = self.module.NativeCodec(Path(value['codec']['path']), value['codec']['sha256'])
        self.image = hx(value['outer_image_hex32'], 32)
        self.profile = hx(value['component_profile_sha256'], 32)
        self.exit_vk = hx(assets.relation.parameters['exit'][1]['vk_hex328'], 328)
        self.rows = [o.tuple_bytes for o in assets.wire.parse_projection(
            read(value['template_projection']['path'], value['template_projection']['sha256'])).body.outputs]
        self.quotes = []

    def quote(self, raw, kind, *, save=True):
        wire = self.assets.wire
        body = (wire.parse_projection(raw).body if kind == 'payment'
                else wire.parse_exit_projection(raw).body)
        budget = self.value['payment_compute_budget' if kind == 'payment' else 'exit_compute_budget']
        case, projection, journal, report = self.module.make_case(
            self.codec, body.raw, self.image, self.profile, self.exit_vk, budget)
        need(projection == raw, 'independent-native-projection-agreement')
        metrics = report['metrics']
        required = self.value['fee_rate_sompi_per_mass'] * metrics['mining_mass']
        need(type(required) is int and required > 0 and metrics['actual_fee_sompi'] == body.fee,
             'native-fee-quote-actual-effects')
        result = {'kind': kind, 'compute_budget': budget, 'metrics': metrics,
            'fee_rate_sompi_per_mass': self.value['fee_rate_sompi_per_mass'],
            'required_fee_sompi': required, 'actual_fee_sompi': body.fee,
            'meets_selected_rate': body.fee >= required,
            'classification': 'PUBLIC_NATIVE_QUOTE_NO_VM_OR_CHAIN_ACCEPTANCE'}
        if save:
            self.quotes.append(result)
        return required, case, journal, result

    def require(self, raw, kind):
        required, case, journal, result = self.quote(raw, kind)
        need(result['actual_fee_sompi'] == required, 'exact-native-fee-fixed-point-before-authorization')
        return case, journal, result

    def payment_fee(self, accepted):
        """Quote the current head before constructing actual payment/change."""
        assets = self.assets
        nf = hashlib.sha256(b'KPXA PUBLIC FEE SHAPE PROBE' + accepted.point
                            + accepted.state.state()).digest()
        need(nf not in accepted.state.nfs and nf != bytes(32), 'fee-probe-fresh-nullifier')
        following = accepted.state.copy()
        witness = following.insert(nf)
        paths = [following.append(row[:32]) for row in self.rows]
        fee, seen = 1, set()
        while True:
            need(fee not in seen, 'native-fee-fixed-point-cycle')
            seen.add(fee)
            core = assets.wire.build_body_core(action_id=hashlib.sha256(b'KPXA QUOTE ACTION' + nf).digest(),
                point=accepted.point, old_state=accepted.state.state(), new_state=following.state(),
                old_reserve=accepted.reserve, new_reserve=accepted.reserve - fee, fee=fee,
                delta=bytes(32), nf=nf, cv=self.rows[0][32:96], outputs=self.rows,
                nf_witness=witness, cm_paths=paths)
            raw = assets.wire.build_projection(core + bytes(128), assets.tail)
            required, _, _, _ = self.quote(raw, 'payment', save=False)
            if fee == required:
                return fee
            fee = required

    def exit_fee(self, accepted, claim, payout_spk):
        """Quote exact current head/output shape before the Exit authorization."""
        assets = self.assets
        following = accepted.state.copy()
        witness = following.insert(claim.nf)
        remaining = accepted.reserve - claim.receipt.value_sompi
        fee, seen = 1, set()
        while True:
            need(fee not in seen, 'native-exit-fee-fixed-point-cycle')
            seen.add(fee)
            body = assets.wire.build_exit_body(action_id=hashlib.sha256(b'KPXA QUOTE EXIT' + claim.nf).digest(),
                point=accepted.point, old_state=accepted.state.state(), new_state=following.state(),
                old_reserve=accepted.reserve, new_reserve=remaining, fee=fee,
                payout=claim.receipt.value_sompi - fee, payout_spk=payout_spk,
                nf=claim.nf, nf_witness=witness)
            raw = assets.wire.build_exit_projection(body, assets.tail)
            required, _, _, _ = self.quote(raw, 'exit', save=False)
            if fee == required:
                return fee
            fee = required
