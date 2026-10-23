#!/usr/bin/env python3
"""Independent counter-only capacity screen; no keys, Notes or native execution.

The proof is the algebra in CAPACITY-DESIGN-REVIEW-01.md. This finite screen
checks its transition accounting and retains counterexamples to false premises.
It overapproximates positive-output choices; it does not establish valid roots,
cryptographic soundness, reachable history, fees or accepted chain state.
"""
import json
from collections import Counter


def holds(n, m, live):
    return n >= 1 and m >= 1 and 0 <= live <= n and m + 2 * live <= 2 * n + 1


def run():
    checked = Counter()
    for n in range(1, 64):
        for live in range(n + 1):
            # Extremal slack values; the algebra is affine in m. This finite
            # screen intentionally does not claim every intermediate count.
            for m in sorted({1, 2 * n + 1 - 2 * live}):
                assert holds(n, m, live)
                checked['starting_states'] += 1
                assert holds(n + 1, m, live + 1)
                checked['ADMIT'] += 1
                if live:
                    assert holds(n, m + 1, live - 1)
                    checked['REVEAL'] += 1
                for consumed in range(1, min(2, live) + 1):
                    assert holds(n, m + 2, live - consumed)
                    checked['private_noappend'] += 1
                    for width in (2, 32):
                        # All possible alignment gaps. This is a superset of
                        # the unique gap determined by an actual physical n.
                        for gap in range(width):
                            for made in range(width + 1):
                                assert holds(n + gap + width, m + 2,
                                             live - consumed + made)
                                checked[f'private_append_{width}'] += 1

    n, m, live = 65535, 131067, 2
    boundary = [[n, m, live]]
    for _ in range(2):
        assert m + 2 <= 131071
        m, live = m + 2, live - 1
        assert holds(n, m, live)
        boundary.append([n, m, live])
    assert boundary[-1] == [65535, 131071, 0]

    # Calibrated breaks: each forbidden premise really is necessary.
    bad = {
        'all_dummy_private_can_insert_two_without_spending': (1, 3, 1),
        'REVEAL_of_zero_value_can_insert_without_spending': (1, 2, 1),
        'positive_admission_without_new_CM_slot': (1, 1, 2),
    }
    assert all(not holds(*state) for state in bad.values())
    return {'schema': 'independent-capacity-induction-screen/v1',
            'scope': 'COUNTER_ONLY_PUBLIC_NO_KEYS_NO_NATIVE_NO_CHAIN',
            'all_expected': True, 'checked': dict(checked),
            'near_full_boundary_n_m_live': boundary,
            'forbidden_premise_counterexamples': bad,
            'cryptographic_or_reachable_history_qualification': False}


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, sort_keys=True))
