"""The same batch search with explicit, redundant one-input balances.

The runner mounts the unchanged batch implementation as
common_payout_batch_impl.py. Only its model constructor is replaced here.
"""
import hashlib
import json
from pathlib import Path
import sys
import time

import z3
import common_payout_batch_impl as implementation
from common_payout_observer import is_common, need


class BatchModel(implementation.BatchModel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for i, event in enumerate(self.data["events"]):
            if event["mode"] != 2 and not is_common(event, self.payout):
                continue
            # Exactly one real input is already required by this client model.
            # Sum(If(selected, value, 0)) == debit therefore implies each
            # selected input equals that debit. State this directly so the
            # solver need not rediscover it across all other false selectors.
            debit = sum(self.relaxed.values[p] for p in event["new"])
            debit += event["payout"] + event["fee"]
            for p, selected in enumerate(self.relaxed.select[i]):
                self.relaxed.solver.add(z3.Implies(selected, self.relaxed.values[p] == debit))


implementation.BatchModel = BatchModel


if __name__ == "__main__":
    raw = Path(sys.argv[1]).read_bytes()
    raw_view = Path(sys.argv[2]).read_bytes() if sys.argv[2] != "-" else None
    view = json.loads(raw_view) if raw_view is not None else None
    if view is not None:
        need(view["public_sha256"] == hashlib.sha256(raw).hexdigest(), "view identity")
    start = time.monotonic()
    result = implementation.analyze(json.loads(raw), view)
    result.update(input_sha256=hashlib.sha256(raw).hexdigest(),
                  view_sha256=hashlib.sha256(raw_view).hexdigest() if raw_view else None,
                  seconds=time.monotonic()-start)
    with Path(sys.argv[3]).open("x") as out:
        json.dump(result, out, separators=(",", ":"))
