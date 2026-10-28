"""Complete new-profile public-state replay for isolated owner operations.

This module deliberately accepts only UNFUNDED_SUPPLIED_CONTEXT histories. It
checks public framing, Output proofs and every tree update, but supplies no
aggregate/R0/Exit verification or accepted-chain authority. The real chain
adapter must qualify those layers before a separate funded entry is added.
No caller-provided ``accepted`` flag can upgrade this interface.
"""
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys

import exit_wire
import wallet_profile as wallet

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('_kpb_wallet_public_trees', HERE.parent / 'integration/trees.py')
trees = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = trees
_spec.loader.exec_module(trees)
SCOPE = 'UNFUNDED_SUPPLIED_CONTEXT'


def need(value, category):
    if not value:
        raise wallet.Invalid(category)


def fields(value, names):
    need(type(value) is dict and set(value) == set(names), 'wallet-history-exact-fields')


def hx(value, size):
    need(type(value) is str and len(value) == size * 2, 'wallet-history-hex-width')
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise wallet.Invalid('wallet-history-canonical-hex') from None
    need(raw.hex() == value, 'wallet-history-canonical-hex')
    return raw


def amount(value, *, zero=False):
    need(type(value) is int and (0 if zero else exit_wire.NOTE_FLOOR) <= value <= exit_wire.MAX,
         'wallet-history-integer-sompi')
    return value


def state_bytes(state, domain):
    return (exit_wire.STATE_TAG + domain + state.cm.root() + len(state.cms).to_bytes(4, 'little')
            + state.nf.root() + len(state.entries).to_bytes(4, 'little'))


def context(identity, point, state, reserve):
    need(point is not None and reserve > 0, 'wallet-history-live-head')
    return exit_wire.HeadContext(*identity, point, state.cm.root(), state.nf.root(),
                                len(state.cms), len(state.entries), reserve)


@dataclass(frozen=True, repr=False)
class SuppliedHistory:
    identity: tuple
    state: object
    rows: tuple
    point: bytes | None
    reserve: int
    exits: tuple

    @property
    def head(self):
        return context(self.identity, self.point, self.state, self.reserve)

    def recover(self, receiver):
        deliveries = [wallet.legacy.Delivery(i, row[:32], row[96:360])
                      for i, row in enumerate(self.rows)]
        return wallet.recover_openings(receiver, deliveries, self.state.cm.root(), self.state.nfs)


def payment(raw, expected, state, tail, verify_output):
    """Replay the exact Rust common/wire.rs 3-NF/6-output frame.

    A structural replay is not proof validity. The genuine public wrapper and
    actual accepted whole CASE remain mandatory outside this supplied context.
    """
    need(type(raw) is bytes and len(raw) == 10685, 'wallet-payment-projection-width')
    prefix, body = raw[:193], raw[193:]
    need(body[:8] == b'KPBAEF01' and body[8:284] == expected.encode(),
         'wallet-payment-exact-current-context')
    need(int.from_bytes(body[372:404], 'little')
         < 2736030358979909402780800718157159386076813972158567259200215660948447373041,
         'wallet-payment-canonical-aggregate-Delta')
    following = state.copy()
    nfs = [body[404 + i * 96:436 + i * 96] for i in range(3)]
    need(all(nf != bytes(32) for nf in nfs)
         and [int.from_bytes(nf, 'little') for nf in nfs]
             == sorted(set(int.from_bytes(nf, 'little') for nf in nfs)),
         'wallet-payment-sorted-distinct-NFs')
    for i, nf in enumerate(nfs):
        need(following.insert(nf) == body[3812 + i * 1160:3812 + (i + 1) * 1160],
             'wallet-payment-exact-NF-witness')
    rows = tuple(body[692 + i * 520:692 + (i + 1) * 520] for i in range(6))
    need(len({row[:32] for row in rows}) == 6, 'wallet-payment-distinct-output-CMs')
    for i, row in enumerate(rows):
        need(verify_output(row), 'wallet-payment-real-output-proof')
        need(following.append(row[:32]) == body[7292 + i * 512:7292 + (i + 1) * 512],
             'wallet-payment-exact-CM-path')
    new_reserve = amount(int.from_bytes(body[356:364], 'little'))
    fee = int.from_bytes(body[364:372], 'little')
    need(1 <= fee <= exit_wire.MAX and new_reserve + fee == expected.reserve,
         'wallet-payment-exact-reserve-fee')
    need(body[284:316] == following.cm.root() and body[316:348] == following.nf.root()
         and int.from_bytes(body[348:352], 'little') == len(following.cms)
         and int.from_bytes(body[352:356], 'little') == len(following.entries),
         'wallet-payment-exact-successor-state')
    expected_prefix = (b'KPBAFX01' + b'\x01\0\x01\0' + expected.point + b'\xff' * 8
        + expected.reserve.to_bytes(8, 'little') + b'\x25\0' + exit_wire.state_spk(expected.state(), tail)
        + b'\x01\0' + new_reserve.to_bytes(8, 'little') + b'\x25\0'
        + exit_wire.state_spk(state_bytes(following, expected.domain), tail) + b'\0'
        + bytes(36) + (10492).to_bytes(4, 'little'))
    need(prefix == expected_prefix, 'wallet-payment-exact-native-projection')
    return following, rows, new_reserve


def load_supplied(value, profile, expected_identity, immutable_tail, verify_output, initial_cv):
    """Check complete ordered data without converting it into chain authority."""
    fields(value, ('schema', 'scope', 'chain_hex32', 'pool_hex32', 'profile_hex32',
                   'domain_hex32', 'service_hex32', 'genesis', 'transitions', 'head'))
    need(value['schema'] == 'kpb-private-batch-public-history/v1' and value['scope'] == SCOPE,
         'wallet-history-only-unfunded-supplied-context')
    identity = tuple(hx(value[name], 32) for name in
                     ('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32', 'service_hex32'))
    need(identity == expected_identity and identity[2] == profile.profile_id
         and identity[3] == profile.domain, 'wallet-history-exact-selected-identity')
    genesis = value['genesis']
    fields(genesis, ('outpoint_hex36', 'state_hex112', 'reserve_sompi', 'outputs_hex520'))
    need(type(genesis['outputs_hex520']) is list and len(genesis['outputs_hex520']) == 3,
         'wallet-history-three-initial-outputs')
    rows = [hx(row, 520) for row in genesis['outputs_hex520']]
    need(type(initial_cv) is bytes and len(initial_cv) == 64
         and all(row[32:96] == initial_cv and verify_output(row) for row in rows),
         'wallet-history-real20KAS-zero-blind-output-proofs')
    need(len({row[:32] for row in rows}) == 3, 'wallet-history-distinct-initial-CMs')
    state = trees.PublicState([row[:32] for row in rows])
    point, reserve = hx(genesis['outpoint_hex36'], 36), amount(genesis['reserve_sompi'])
    need(reserve == 6_000_000_000 and hx(genesis['state_hex112'], 112) == state_bytes(state, profile.domain),
         'wallet-history-exact60KAS-initial-state')
    context(identity, point, state, reserve).encode()
    need(type(value['transitions']) is list, 'wallet-history-ordered-transitions')
    exits = []
    for event in value['transitions']:
        need(point is not None, 'wallet-history-no-post-terminal-transition')
        need(type(event) is dict and event.get('kind') in ('payment', 'exit'), 'wallet-history-transition-kind')
        fields(event, ('kind', 'projection_hex', 'successor_outpoint_hex36')
               + (('proof_hex128',) if event['kind'] == 'exit' else ()))
        expected = context(identity, point, state, reserve)
        raw = hx(event['projection_hex'], 10685 if event['kind'] == 'payment' else
                 len(event['projection_hex']) // 2)
        if event['kind'] == 'payment':
            state, appended, reserve = payment(raw, expected, state, immutable_tail, verify_output)
            rows.extend(appended)
        else:
            body = exit_wire.require_current_head(raw, expected, immutable_tail)
            hx(event['proof_hex128'], 128)  # Required retained proof; not a verification claim.
            following = state.copy()
            need(following.insert(body.nf) == body.witness, 'wallet-history-exact-Exit-NF-witness')
            need(body.next_state() == state_bytes(following, profile.domain), 'wallet-history-Exit-state')
            exits.append((body.nf, body.payout_spk, body.payout, body.fee))
            state, reserve = following, body.new_reserve
        successor = event['successor_outpoint_hex36']
        need((successor is None) == (reserve == 0), 'wallet-history-terminal-outpoint')
        point = None if successor is None else hx(successor, 36)
        if point is not None:
            need(point[:32] != bytes(32), 'wallet-history-nonzero-successor-point')
    head = value['head']
    fields(head, ('outpoint_hex36', 'state_hex112', 'reserve_sompi'))
    need(head['outpoint_hex36'] == (None if point is None else point.hex())
         and hx(head['state_hex112'], 112) == state_bytes(state, profile.domain)
         and amount(head['reserve_sompi'], zero=True) == reserve, 'wallet-history-exact-final-head')
    return SuppliedHistory(identity, state, tuple(rows), point, reserve, tuple(exits))


def select_for_round(claims, round_number, owner_component):
    need(type(round_number) is int and round_number in (1, 2)
         and type(owner_component) is int and owner_component in (0, 1, 2), 'wallet-fixed-workload-round')
    # Invoice indexes are encrypted. This is the frozen benchmark's owner-local
    # key schedule, not a public sender/output classifier or a general wallet policy.
    index = 0 if round_number == 1 else (2 if owner_component == 1 else 1)
    selected = [claim for claim in claims if not claim.spent and claim.receipt.index == index]
    need(len(selected) == 1, 'wallet-exact-original-recovered-benchmark-input')
    return selected[0]
