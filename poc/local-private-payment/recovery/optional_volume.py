#!/usr/bin/env python3
"""Optional own-leaf boolean attestation of the public matched21 workload.

Reuse the reviewed replay, receipt discovery and one-leaf boundary. This never
publishes decrypted values, owner mappings, indices or invoices. Actual use
requires separately reviewed accepted-history provenance and private-read GO.
"""
import argparse
from pathlib import Path

import publication_derived as audit


def _check_loaded(value, accepted, owned, assets, expected_second_kind):
    """Pure private arithmetic after the existing genuine replay/claim checks."""
    need = audit.support.need
    need(expected_second_kind in ('received', 'change'), 'approved-second-input-policy-required')
    by_nf = {claim.nf: claim for claim in owned}
    by_position = {claim.position: claim for claim in owned}
    need(len(by_nf) == len(by_position) == len(owned), 'unique-owned-claim-identities')
    cursor = len(value['genesis']['outputs_hex520'])
    outgoing, outgoing_kinds, matched_nfs, payment_count = [], [], set(), 0
    for transition in value['transitions']:
        if transition['kind'] != 'payment':
            continue
        body = assets.wire.parse_projection(bytes.fromhex(transition['projection_hex'])).body
        need(body.old_state.cm_count == cursor and len(body.outputs) == 2,
             'exact-public-payment-append-positions')
        positions = (cursor, cursor + 1)
        for position, output in zip(positions, body.outputs):
            need(accepted.deliveries[position] == output.tuple_bytes,
                 'exact-replayed-output-at-position')
        nf = body.spends[0].nf
        if nf in by_nf:
            own_input = by_nf[nf]
            own_outputs = [by_position[position] for position in positions if position in by_position]
            need(own_input.spent and nf not in matched_nfs and len(own_outputs) == 1,
                 'one-owned-spent-input-and-one-change-not-self-payment')
            input_value = audit.support.amount(own_input.receipt.value_sompi)
            change_value = audit.support.amount(own_outputs[0].receipt.value_sompi)
            fee = audit.support.fee_amount(body.fee)
            outgoing.append(audit.support.amount(input_value - change_value - fee))
            outgoing_kinds.append(own_input.kind)
            matched_nfs.add(nf)
        cursor += 2
        payment_count += 1
    need(cursor == len(accepted.deliveries) and payment_count == 6,
         'complete-six-payment-history-required')
    # Both values are already fixed by the public approved campaign contract.
    # Keep the computed amounts private: emit only whether that contract matched.
    need(len(outgoing) == 2 and sorted(outgoing) == [200_000_000, 500_000_000]
         and sum(outgoing) == 700_000_000, 'approved-own-fixed-workload-mismatch')
    need(outgoing_kinds[1] == expected_second_kind, 'approved-second-input-policy-mismatch')
    return {'schema': 'kpxa-own-matched21-boolean-attestation/v1',
            'status': 'PASS', 'approved_own_workload_matched': True}


def attest_loaded(value, accepted, receiver, assets, expected_second_kind):
    owned = audit.history.claims(accepted, receiver, assets)
    return _check_loaded(value, accepted, owned, assets, expected_second_kind)


def execute(a):
    before = audit.namespace(a.owner, Path('/candidates'), a.output)
    assets, accepted = audit.accepted_history(a, before)
    # Authenticate and retain the same public transition bytes before the leaf.
    value = audit.support.parse(audit.public_read(a.history, a.history_sha256, before))
    seed = audit.original_seed(a.owner, before)
    result = attest_loaded(value, accepted, assets.receiver(seed), assets, a.expected_second_kind)
    audit.need(audit.identity(a.owner.lstat()) == audit.identity(before))
    audit.support.write_new(a.output, audit.support.encoded(result) + b'\n')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('owner', 'output', 'assets', 'history', 'context'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('assets', 'history', 'context'):
        p.add_argument('--' + name + '-sha256', required=True)
    p.add_argument('--expected-second-kind', choices=('received', 'change'), required=True)
    try:
        execute(p.parse_args())
    except Exception:
        p.exit(2, 'Own workload attestation refused; no private material exported.\n')


if __name__ == '__main__':
    main()
