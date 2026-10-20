"""Private controller-side projection. Never mount this module in the observer.

The plan is the original H14 synthetic ledger, not a wallet key/opening file.
Only records a single author or recipient can retain leave this module.
"""


def ledger(plan):
    notes = {0: dict(owner=0, value=plan["initial"])}
    events = []
    for step in plan["steps"]:
        inputs = step["inputs"]
        owners = {notes[p]["owner"] for p in inputs}
        if len(owners) > 1:
            raise ValueError("plan violates known client's single-author rule")
        author = step["depositor"] if step["mode"] == 0 else next(iter(owners))
        outputs = []
        for slot, (owner, value) in enumerate(zip(step["owners"], step["values"], strict=True)):
            position = step["count_before"] + slot
            if position in notes:
                raise ValueError("duplicate position in original plan")
            note = dict(owner=owner, value=value)
            notes[position] = note
            outputs.append(dict(position=position, **note))
        events.append(dict(author=author, inputs=inputs, outputs=outputs))
    for note in plan["drains"]:
        if notes[note["position"]] != {k: note[k] for k in ("owner", "value")}:
            raise ValueError("plan drain differs from note")
        events.append(dict(author=note["owner"], inputs=[note["position"]], outputs=[]))
    return notes, events


def project(plan, participant, public_sha256):
    notes, events = ledger(plan)
    receipts = [dict(position=p, value=n["value"]) for p, n in notes.items()
                if n["owner"] == participant and n["value"] > 0]
    # These aliases reveal equality of receive addresses the sender actually
    # used, not experiment wallet IDs or a global population bound.
    handles = {participant: 0}
    authored = []
    for event, record in enumerate(events):
        if record["author"] != participant:
            continue
        outputs = []
        for output in record["outputs"]:
            handle = None
            if output["value"] > 0:
                handle = handles.setdefault(output["owner"], len(handles))
            outputs.append(dict(position=output["position"], value=output["value"],
                                recipient=handle))
        authored.append(dict(event=event, inputs=list(record["inputs"]), outputs=outputs))
    return dict(schema="kpi-h16-participant-view-v1", public_sha256=public_sha256,
                receipts=receipts, authored=authored)


def eligible_targets(plan, participant):
    notes, events = ledger(plan)
    return {
        i for i, record in enumerate(events)
        if record["inputs"]
        and all(notes[p]["owner"] != participant for p in record["inputs"])
        and all(n["owner"] != participant or n["value"] == 0 for n in record["outputs"])
    }
