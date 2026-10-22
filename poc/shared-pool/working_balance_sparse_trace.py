"""Public-only explanation of the frozen working-balance split-tail heuristic.

This diagnostic does not change an attack, rescore a target, or receive truth.
It recovers decompositions discarded by the frozen book's unioned support sets.
Every retained decomposition supports the public winner; truth must never select
which explanations this helper retains. A separate private classifier may assess
their factual ancestry, without promoting that ancestry into observer knowledge.
"""

from collections import defaultdict

import working_balance_observer as frozen


SCHEMA = "kpi-working-balance-public-split-tail-trace-v1"


def normalized_book(book):
    """Canonical JSON representation of all keys, ranks and deduplicated supports."""
    return [
        dict(
            key=list(key),
            rank=list(record["rank"]),
            supports=[dict(events=list(events), coinput=coinput)
                      for events, coinput in sorted(
                          record["supports"],
                          key=lambda item: (item[0], -1 if item[1] is None else item[1]))],
        )
        for key, record in sorted(book.items())
    ]


def _residue(row):
    return dict(value=row["value"], events=list(row["events"]), owner=row["owner"],
                coinput=row["coinput"], partial=bool(row.get("partial", False)))


def trace_split_tail(engine, target, *, expected_guess=None):
    """Recover every selected-key construction and verify the entire frozen book.

    ``engine`` must be the unchanged frozen Engine constructed with the exact
    permitted public prefix/directory/view and original public target floor.
    ``expected_guess``, when supplied, is the sealed prediction's split_tail
    guess. No hidden target eligibility, inputs, amounts or ownership enter here.
    The returned rows are public hypotheses, never statements of true lineage.
    """
    frozen.need(type(target) is int and target in engine.targets, "public trace target")
    reference_books = engine.books(target)
    reference = reference_books["split_tail"]
    prior = engine.prior(target)
    selected = engine.best(reference, prior, "split_tail")
    all_guesses = {"prior": prior}
    all_guesses.update((kind, engine.best(reference_books[kind], prior, kind))
                       for kind in frozen.VARIANTS if kind != "prior")
    if expected_guess is not None:
        frozen.need(frozen.digest(selected) == frozen.digest(expected_guess),
                    "trace does not reproduce sealed split_tail guess")
    selected_key = (selected["sender"], selected["recipient"], selected["amount"])
    book, decompositions = {}, []
    known = engine.known(target)

    # These are the frozen split_tail residue family and eight-support ordering.
    # Do not loosen eligibility, increase the bound, or use hidden ancestry here.
    residues = engine.residuals + [row for row in engine.sums if row["partial"]]
    index = defaultdict(lambda: defaultdict(list))
    for residue in residues:
        index[residue["value"]][len(residue["events"])].append(residue)

    def fixed_rank(residue):
        events = residue["events"]
        return (-int(residue["owner"] is not None),
                sum(engine.events[event]["minute"] for event in events),
                engine.events[events[-1]]["minute"] - engine.events[events[0]]["minute"],
                events, -1 if residue["coinput"] is None else residue["coinput"],
                -1 if residue["owner"] is None else residue["owner"])

    for lengths in index.values():
        for rows in lengths.values():
            rows.sort(key=fixed_rank)

    def bounded(position, receipt=False):
        def rank(residue):
            events = residue["events"]
            distance = sum(engine.events[event]["minute"] - engine.events[target]["minute"]
                           for event in events)
            span = engine.events[events[-1]]["minute"] - engine.events[events[0]]["minute"]
            return (-int(residue["owner"] is not None), distance, span, events,
                    -1 if residue["coinput"] is None else residue["coinput"],
                    -1 if residue["owner"] is None else residue["owner"])

        result = {}
        for value, lengths in index.items():
            if ((receipt and not frozen.LOW <= value <= frozen.HIGH)
                    or (position in engine.notes and engine.notes[position]["value"] != value)):
                continue
            candidates = []
            for rows in lengths.values():
                accepted = 0
                for residue in rows:
                    if engine.eligible(target, residue, position):
                        candidates.append(residue)
                        accepted += 1
                        if accepted == frozen.SPLIT_SUPPORT_LIMIT:
                            break
            if candidates:
                result[value] = sorted(candidates, key=rank)[:frozen.SPLIT_SUPPORT_LIMIT]
        return result

    def offer(positions, sender, total, receipt, tail):
        value, recipient = receipt["value"], receipt["owner"]
        if (not frozen.LOW <= value <= frozen.HIGH
                or (known["amount"] is not None and known["amount"] != value)):
            return
        pair = engine.roles(target, sender, recipient)
        if pair is None:
            return
        tags = [role for role in range(8) if value in
                (20 * frozen.SOMPI + (role + 1) * 1000,
                 20 * frozen.SOMPI + (role + 1) * 1000 + 1)]
        if value % frozen.CENT:
            if not tags or sender not in (None, tags[0]):
                return
            pair = engine.roles(target, tags[0], recipient)
            if pair is None:
                return
        support = tuple(sorted(receipt["events"] + tail["events"]))
        distance = sum(engine.events[event]["minute"] - engine.events[target]["minute"]
                       for event in support)
        rank = (int(sender is not None) + int(recipient is not None), 4, -distance)
        key = (pair[0], pair[1], value)
        record = book.setdefault(key, dict(rank=rank, supports=set()))
        record["rank"] = max(record["rank"], rank)
        # The original offer() intentionally receives no coinput for split_tail.
        # Count its unioned support once, while retaining every decomposition.
        record["supports"].add((support, None))
        if key == selected_key:
            decompositions.append(dict(
                input_positions=list(positions), input_total_after_fee=total,
                offered_sender=sender, offered_recipient=recipient,
                guessed_pair=list(pair), amount=value, rank=list(rank),
                union_events=list(support), receipt=_residue(receipt), tail=_residue(tail)))

    payment, change = engine.events[target]["new"]
    by_value = bounded(change)
    receipts = [row for rows in bounded(payment, receipt=True).values() for row in rows]
    for positions, sender, total in engine.inputs(target):
        for receipt in receipts:
            if not engine.eligible(target, receipt, payment, positions):
                continue
            remainder = total - receipt["value"]
            if remainder == 0:
                alternatives = [dict(value=0, events=(), owner=sender, coinput=None)]
            else:
                alternatives = by_value.get(remainder, ()) if remainder >= frozen.FLOOR else ()
            for tail in alternatives:
                if tail["events"] and (
                        set(tail["events"]) & set(receipt["events"])
                        or not engine.eligible(target, tail, change, positions)
                        or tail["owner"] not in (None, sender)):
                    continue
                if tail["coinput"] is not None and tail["coinput"] == receipt["coinput"]:
                    continue
                offer(positions, sender, total, receipt, tail)

    canonical = normalized_book(book)
    frozen.need(canonical == normalized_book(reference), "public trace full split_tail book drift")
    reproduced = engine.best(book, prior, "split_tail")
    frozen.need(frozen.digest(reproduced) == frozen.digest(selected), "public trace winner drift")
    if book:
        frozen.need(decompositions, "selected split_tail key has no public decomposition")
        selected_record = next(row for row in canonical if tuple(row["key"]) == selected_key)
        frozen.need({tuple(row["union_events"]) for row in decompositions}
                    == {tuple(row["events"]) for row in selected_record["supports"]},
                    "selected split_tail support decomposition coverage")
    else:
        frozen.need(not decompositions, "prior fallback has no split_tail support")
        selected_record = None
    return dict(
        schema=SCHEMA, event=target, event_id=engine.events[target]["event_id"],
        guess=selected, prior=prior, all_guesses=all_guesses, fallback=not book,
        selected_key=list(selected_key) if book else None,
        selected_record=selected_record, decompositions=decompositions,
        book_key_count=len(book), book_sha256=frozen.digest(canonical),
        full_book_verified=True,
        boundary="public-only frozen hypotheses; decomposition is not factual ancestry")
