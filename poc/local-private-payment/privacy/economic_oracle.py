"""Independent, public small-toy oracle for economic-linkage forest inference.

This deliberately enumerates chronological assignments of consumers to live
notes. It does not use the subset-mask algorithm, read files, or access a
runtime. Amounts are integer sompi. Times are distinct integer event positions.

The reported forests identify payment and exit events, but quotient equal
genesis roots and each payment's two children. Features therefore describe
payment origins and anonymous root groups, never genesis-owner identities.
"""

from __future__ import annotations

from itertools import combinations, product
from math import factorial


MAX_VISITS = 1_000_000
DEFAULT_MAX_VALUE = 2_870_000_000_000_000_000
FEATURE_NAMES = ("parent", "ancestor", "co_root_exit")


class OracleLimitExceeded(RuntimeError):
    """The complete enumeration exceeded its bound; no result was returned."""


def brute_force(
    root_values,
    payment_fees,
    exit_gross,
    payment_times,
    exit_times,
    note_floor=1,
    max_value=DEFAULT_MAX_VALUE,
    advertised_values=None,
    high_count=None,
):
    """Return exact counts and possible/must features for a bounded public toy.

    Supports 1--3 equal genesis roots, 0--3 one-input/two-output payments,
    and at most six direct exits, with ``exits = roots + payments``.
    Each exit gross is its native payout plus its exact exit fee.

    Optional ``advertised_values=(low, high)`` and ``high_count`` constrain
    the multiset of one outgoing child value per payment. Full assignments
    explicitly enumerate outgoing-role values and are accepted once if any
    role assignment has exactly high_count high values. Role ambiguity never
    multiplies forest counts. Both arguments must be supplied together.

    Consumers are indexed payments ``0..m-1``, then exits ``m..m+n-1``.
    ``parent`` contains ``(origin_payment, consumer)``; origin ``-1`` means
    a genesis note. ``ancestor`` contains strict payment/event ancestry.
    ``co_root_exit`` contains ascending pairs of exit indices, not consumer
    indices. Possible/must sets are over the unique quotiented forests.
    An empty feasible set gives empty possible and must sets.

    The dict also contains ``forest_count``, ``labeled_assignment_count``,
    ``visits``, and ``visit_limit``. Invalid input raises ValueError. Crossing
    MAX_VISITS raises OracleLimitExceeded, never a partial successful result.
    """
    root_values = tuple(root_values)
    payment_fees = tuple(payment_fees)
    exit_gross = tuple(exit_gross)
    payment_times = tuple(payment_times)
    exit_times = tuple(exit_times)
    root_count = len(root_values)
    payment_count = len(payment_fees)
    exit_count = len(exit_gross)

    if not 1 <= root_count <= 3:
        raise ValueError("oracle requires 1--3 genesis roots")
    if not 0 <= payment_count <= 3 or exit_count > 6:
        raise ValueError("oracle supports at most 3 payments and 6 exits")
    if exit_count != root_count + payment_count:
        raise ValueError("terminal zero reserve requires exits = roots + payments")
    if len(payment_times) != payment_count or len(exit_times) != exit_count:
        raise ValueError("every consumer must have exactly one time")
    if type(note_floor) is not int or note_floor <= 0:
        raise ValueError("note_floor must be a positive integer")
    if type(max_value) is not int or max_value < note_floor:
        raise ValueError("max_value must be an integer at least note_floor")
    if (advertised_values is None) != (high_count is None):
        raise ValueError("advertised_values and high_count must be supplied together")
    if advertised_values is not None:
        advertised_values = tuple(advertised_values)
        if (
            len(advertised_values) != 2
            or any(type(value) is not int or not note_floor <= value <= max_value for value in advertised_values)
            or not advertised_values[0] < advertised_values[1]
        ):
            raise ValueError("advertised_values must be distinct ascending note values in range")
        if type(high_count) is not int or not 0 <= high_count <= payment_count:
            raise ValueError("high_count must be an integer in [0, payment_count]")
    for name, values in (
        ("root_values", root_values),
        ("payment_fees", payment_fees),
        ("exit_gross", exit_gross),
    ):
        if any(type(value) is not int or not 0 <= value <= max_value for value in values):
            raise ValueError(f"{name} must contain integers in [0, max_value]")
    if len(set(root_values)) != 1:
        raise ValueError("root-permutation quotient requires equal root values")
    all_times = payment_times + exit_times
    if any(type(time) is not int for time in all_times):
        raise ValueError("times must be distinct integer event positions")
    if len(set(all_times)) != len(all_times):
        raise ValueError("times must give a strict total order; ties are ambiguous")

    def empty_result():
        return {
            "forest_count": 0,
            "labeled_assignment_count": 0,
            "possible": {name: frozenset() for name in FEATURE_NAMES},
            "must": {name: frozenset() for name in FEATURE_NAMES},
            "visits": 0,
            "visit_limit": MAX_VISITS,
        }

    if (
        any(value < note_floor for value in root_values + exit_gross)
        or sum(root_values) != sum(exit_gross) + sum(payment_fees)
    ):
        return empty_result()

    event_order = tuple(sorted(range(len(all_times)), key=all_times.__getitem__))
    note_count = root_count + 2 * payment_count
    consumer_by_note = [-1] * note_count
    note_by_consumer = [-1] * len(all_times)
    forests = set()
    possible = {name: set() for name in FEATURE_NAMES}
    must = None
    labeled_assignment_count = 0
    visits = 0

    def child_notes(payment):
        first = root_count + 2 * payment
        return first, first + 1

    def infer_values():
        # In a chronological assignment, both children are consumed later
        # than their creating payment, so reverse order determines every value.
        values = [None] * note_count
        for consumer in reversed(event_order):
            if consumer < payment_count:
                left, right = child_notes(consumer)
                value = values[left] + values[right] + payment_fees[consumer]
            else:
                value = exit_gross[consumer - payment_count]
            if not note_floor <= value <= max_value:
                return None
            values[note_by_consumer[consumer]] = value
        if not all(values[root] == root_values[root] for root in range(root_count)):
            return None
        return values

    def advertised_roles_feasible(values):
        if advertised_values is None:
            return True
        allowed = []
        for payment in range(payment_count):
            child_values = tuple(values[child] for child in child_notes(payment))
            options = tuple(value for value in advertised_values if value in child_values)
            if not options:
                return False
            allowed.append(options)
        high = advertised_values[1]
        return any(sum(value == high for value in roles) == high_count for roles in product(*allowed))

    def encode_note(note):
        consumer = consumer_by_note[note]
        if consumer >= payment_count:
            return ("exit", consumer - payment_count)
        children = tuple(sorted(encode_note(child) for child in child_notes(consumer)))
        return ("payment", consumer, children)

    def forest_features(forest):
        features = {name: set() for name in FEATURE_NAMES}

        def walk(node, origin, ancestors):
            if node[0] == "exit":
                exit_index = node[1]
                consumer = payment_count + exit_index
                features["parent"].add((origin, consumer))
                features["ancestor"].update((ancestor, consumer) for ancestor in ancestors)
                return [exit_index]
            payment = node[1]
            features["parent"].add((origin, payment))
            features["ancestor"].update((ancestor, payment) for ancestor in ancestors)
            exits = []
            for child in node[2]:
                exits.extend(walk(child, payment, ancestors + (payment,)))
            return exits

        for root in forest:
            exits = walk(root, -1, ())
            features["co_root_exit"].update(combinations(sorted(exits), 2))
        return features

    def visit(position, live_notes):
        nonlocal labeled_assignment_count, must, visits
        visits += 1
        if visits > MAX_VISITS:
            raise OracleLimitExceeded(f"oracle exceeded {MAX_VISITS} visits; no complete result")
        if position == len(event_order):
            if live_notes:
                return
            values = infer_values()
            if values is None or not advertised_roles_feasible(values):
                return
            labeled_assignment_count += 1
            forest = tuple(sorted(encode_note(root) for root in range(root_count)))
            if forest in forests:
                return
            forests.add(forest)
            features = forest_features(forest)
            for name in FEATURE_NAMES:
                possible[name].update(features[name])
            if must is None:
                must = {name: set(features[name]) for name in FEATURE_NAMES}
            else:
                for name in FEATURE_NAMES:
                    must[name].intersection_update(features[name])
            return

        consumer = event_order[position]
        for offset, note in enumerate(live_notes):
            consumer_by_note[note] = consumer
            note_by_consumer[consumer] = note
            next_live = live_notes[:offset] + live_notes[offset + 1 :]
            if consumer < payment_count:
                next_live += child_notes(consumer)
            visit(position + 1, next_live)
            consumer_by_note[note] = -1
            note_by_consumer[consumer] = -1

    visit(0, tuple(range(root_count)))
    # Equal roots and distinct event labels make these symmetry actions free.
    # This check also catches accidental canonicalization of distinct events.
    symmetry_factor = factorial(root_count) * (1 << payment_count)
    if labeled_assignment_count != len(forests) * symmetry_factor:
        raise RuntimeError("oracle root/child canonicalization multiplicity mismatch")
    return {
        "forest_count": len(forests),
        "labeled_assignment_count": labeled_assignment_count,
        "possible": {name: frozenset(possible[name]) for name in FEATURE_NAMES},
        "must": {
            name: frozenset(must[name]) if must is not None else frozenset()
            for name in FEATURE_NAMES
        },
        "visits": visits,
        "visit_limit": MAX_VISITS,
    }
