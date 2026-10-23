"""Strict public framing for the selected one-real-input arithmetic model."""
from dataclasses import dataclass
import hashlib
import json

NOTE_FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
MAX = 2_870_000_000_000_000_000
PUBLIC_KEYS = {'schema', 'classification', 'wallet_policy', 'coverage_complete',
               'note_floor_sompi', 'payout_floor_sompi', 'max_sompi', 'events'}
EVENT_KEYS = {'ordinal', 'tx_id', 'kind', 'fee_sompi', 'payout_sompi',
              'payout_destination', 'prior_reserve_sompi', 'reserve_sompi',
              'prior_cm_count', 'cm_count', 'prior_nf_count', 'nf_count',
              'cms', 'nfs', 'terminal', 'ingress_value_sompi'}
PRIOR_KEYS = {'position', 'cm', 'minimum_sompi', 'maximum_sompi', 'source'}


class InputError(ValueError):
    pass


class ScopeLimit(ValueError):
    pass


def need(condition, category):
    if not condition:
        raise InputError(category)


def integer(value, maximum=MAX):
    need(type(value) is int and 0 <= value <= maximum, 'noncanonical-integer')
    return value


def fixed_hex(value, width=32):
    need(type(value) is str and len(value) == 2 * width, 'hex-width')
    need(all(c in '0123456789abcdef' for c in value), 'hex-encoding')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(InputError('json-constant')))


@dataclass(frozen=True)
class Note:
    position: int
    cm: str
    birth: int
    known_value: int | None


@dataclass(frozen=True)
class Event:
    ordinal: int
    kind: str
    tx_id: str
    fee: int
    payout: int
    reserve: int
    prior_count: int
    new_positions: tuple
    ingress_value: int | None


@dataclass(frozen=True)
class Ledger:
    public: dict
    priors: dict
    policy: str
    notes: tuple
    events: tuple
    bounds: tuple


def decode(public, priors):
    need(type(public) is dict and set(public) == PUBLIC_KEYS, 'public-fields')
    need(public['schema'] == 'kpx3-change-public-integer-ledger/v1'
         and public['classification'] == 'SYNTHETIC_PUBLIC_INTEGER_MODEL', 'public-schema')
    need(public['wallet_policy'] in ('whole_claim', 'change_capable'), 'wallet-policy')
    need(public['coverage_complete'] is True, 'coverage-incomplete')
    need(type(public['note_floor_sompi']) is int and public['note_floor_sompi'] == NOTE_FLOOR
         and type(public['payout_floor_sompi']) is int and public['payout_floor_sompi'] == PAYOUT_FLOOR
         and type(public['max_sompi']) is int and public['max_sompi'] == MAX, 'profile-amounts')
    rows = public['events']
    need(type(rows) is list and bool(rows), 'events')
    if len(rows) > 20:
        raise ScopeLimit('event-bound')
    notes, events, seen_nf, seen_tx = [], [], set(), set()
    reserve, nf_count, private_count, ended = 0, 1, 0, False
    for ordinal, row in enumerate(rows):
        need(type(row) is dict and set(row) == EVENT_KEYS, 'event-fields')
        need(integer(row['ordinal'], 20) == ordinal and not ended, 'event-order')
        tx = fixed_hex(row['tx_id'])
        need(tx not in seen_tx, 'duplicate-transaction')
        seen_tx.add(tx)
        fee, payout = integer(row['fee_sompi']), integer(row['payout_sompi'])
        after = integer(row['reserve_sompi'])
        need(integer(row['prior_reserve_sompi']) == reserve, 'prior-reserve')
        need(integer(row['prior_cm_count'], 65_535) == len(notes)
             and integer(row['prior_nf_count'], 131_071) == nf_count, 'prior-counts')
        cms, nfs = row['cms'], row['nfs']
        need(type(cms) is list and type(nfs) is list, 'public-label-arrays')
        for cm in cms:
            fixed_hex(cm)
        for nf in nfs:
            fixed_hex(nf)
            need(nf != '00' * 32 and nf not in seen_nf, 'duplicate-or-zero-nf')
            seen_nf.add(nf)
        need(type(row['terminal']) is bool, 'terminal-boolean')
        terminal = row['terminal']
        if row['kind'] == 'ingress':
            value = integer(row['ingress_value_sompi'])
            need(value >= NOTE_FLOOR and payout == 0 and row['payout_destination'] is None
                 and len(cms) == 1 and not nfs and not terminal
                 and after == reserve + value, 'ingress-effects')
        elif row['kind'] == 'private':
            private_count += 1
            if private_count > 8:
                raise ScopeLimit('private-action-bound')
            value = None
            need(row['ingress_value_sompi'] is None and fee > 0 and len(nfs) == 2
                 and payout <= reserve and fee <= reserve - payout
                 and after == reserve - payout - fee, 'private-effects')
            need(payout == 0 or payout >= PAYOUT_FLOOR, 'payout-floor')
            if payout:
                destination = fixed_hex(row['payout_destination'], 36)
                need(destination.startswith('000020') and destination.endswith('ac'), 'payout-frame')
            else:
                need(row['payout_destination'] is None, 'p0-destination')
            need(terminal == (after == 0) and len(cms) == (0 if terminal else 2)
                 and (after == 0 or after >= NOTE_FLOOR), 'terminal-topology')
            need(not terminal or payout > 0, 'terminal-payout')
            need(terminal or cms[0] != cms[1], 'same-event-cm-distinctness')
        else:
            raise InputError('event-kind')
        new_positions = tuple(range(len(notes), len(notes) + len(cms)))
        if len(notes) + len(cms) > 12:
            raise ScopeLimit('note-bound')
        for position, cm in zip(new_positions, cms, strict=True):
            notes.append(Note(position, cm, ordinal, value))
        nf_count += len(nfs)
        need(integer(row['cm_count'], 65_535) == len(notes)
             and integer(row['nf_count'], 131_071) == nf_count
             and nf_count <= 2 * len(notes) + 1, 'next-counts')
        events.append(Event(ordinal, row['kind'], tx, fee, payout, after,
                            row['prior_cm_count'], new_positions, value))
        reserve, ended = after, terminal
    need(type(priors) is dict and set(priors) == {'schema', 'facts'}
         and priors['schema'] == 'kpx3-change-value-priors/v1'
         and type(priors['facts']) is list, 'prior-schema')
    if len(priors['facts']) > 12:
        raise ScopeLimit('prior-bound')
    bounds, seen = [], set()
    for fact in priors['facts']:
        need(type(fact) is dict and set(fact) == PRIOR_KEYS, 'prior-fields')
        position = integer(fact['position'], 65_535)
        need(position < len(notes) and position not in seen
             and fixed_hex(fact['cm']) == notes[position].cm, 'positioned-prior-identity')
        seen.add(position)
        low, high = integer(fact['minimum_sompi']), integer(fact['maximum_sompi'])
        need(low <= high and fact['source'] in ('public_opening', 'declared_legitimate_value_prior'),
             'prior-range-source')
        need(fact['source'] != 'public_opening' or notes[position].known_value is not None,
             'opening-not-public')
        bounds.append((position, low, high))
    return Ledger(public, priors, public['wallet_policy'], tuple(notes), tuple(events), tuple(bounds))
