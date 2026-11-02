#!/usr/bin/env python3
"""Regression checks for the post-hoc role-conditioned correction."""

from __future__ import annotations

import json
from pathlib import Path

import observer
import observer_correction_v2 as corrected


HERE = Path(__file__).resolve().parent
PUBLIC = HERE / "run" / "public"


def main() -> None:
    predictions = corrected.build_predictions(PUBLIC)
    target = predictions["checkpoints"]["target-cashout"]
    known = target["O-public-known"]
    unmapped = target["O-public-unmapped"]

    assert known["diagnostics"]["hiddenTargetLabelCount"] == 2
    assert known["withdrawingChain"]["withdrawalLinkedTuple"]["count"] == 1
    assert known["withdrawingChain"]["earlierReceivedAmountSompi"]["count"] == 1
    assert known["withdrawingChain"]["onwardPaymentAmountSompi"]["count"] == 1

    assert unmapped["diagnostics"]["hiddenTargetLabelCount"] == 2
    assert unmapped["withdrawingChain"]["earlierReceivedAmountSompi"]["count"] == 1
    assert unmapped["withdrawingChain"]["onwardPaymentAmountSompi"]["count"] == 2
    assert unmapped["withdrawingChain"]["withdrawalLinkedTuple"]["count"] == 8

    assert known["withdrawingChain"]["onwardRelationship"]["count"] == 1
    assert unmapped["withdrawingChain"]["onwardRelationship"]["count"] == 4
    assert known["unrelatedChain"]["onwardRelationship"]["count"] == 1
    assert unmapped["unrelatedChain"]["onwardRelationship"]["count"] == 4

    _, aux, events = observer.load_public(PUBLIC)
    credits, history, exits = observer.public_material(aux, events)
    records = observer.target_records(exits, aux, True)
    original = corrected.project_checkpoint("target-cashout", records, credits, history)
    renamed = corrected.project_checkpoint(
        "target-cashout", corrected.rename_hidden_chains(records, "target-cashout"), credits, history
    )
    assert original == renamed

    legacy = json.loads((PUBLIC / "SCORE.json").read_text())
    assert legacy["checkpoints"]["target-cashout"]["O-public-known"]["privacyGatePassed"]
    assert not known["withdrawingChain"]["properties"]["earlierReceivedAmountProtected"]
    assert not known["withdrawingChain"]["properties"]["onwardPaymentAmountProtected"]
    assert not known["withdrawingChain"]["properties"]["onwardRelationshipProtected"]
    print(json.dumps({"regressions": 17, "passed": True}))


if __name__ == "__main__":
    main()
