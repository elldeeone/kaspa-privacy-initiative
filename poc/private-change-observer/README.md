# Exact private-change arithmetic observer

Research-only v1 selected by the frozen
[plan](../../research/next-session/private-change/observer/PLAN-01.md) and
[API](../../research/next-session/private-change/observer/API-01.json).
No heldout evaluation or financial privacy qualification is provided.

Use the already installed exact Z3 environment:

```sh
/home/luke/.local/share/kpi-shared-pool-tools/bin/python observe.py < PUBLIC_REQUEST.json
/home/luke/.local/share/kpi-shared-pool-tools/bin/python run_controls.py NEW_RESULT.json
```

The observer accepts only strict public integer chronology/value priors. It models
one real earlier input, positioned single-spend, conservation and every prefix's
reserve under a declared whole-claim or change-capable policy. It does not receive
input/owner/change-slot maps, private operation intent, keys or generator truth.
Repeated CM bytes at different public positions remain distinct liabilities.

It checks every public note amount and each private event's input sum, output sum
and selected position. An UNSAT alternative establishes a forced arithmetic fact
under the declared model. Two independently checked SAT certificates are only
ARITHMETIC_ALTERNATIVE_ONLY. UNKNOWN is INCOMPLETE, never ambiguity. Owner links
are NOT_MODELLED. Hash preimages, ownership, ciphertext/proof correctness,
consensus/data availability and network privacy are missing constraints.

A singleton partial exit still exposes its aggregate remaining change through
global reserve conservation. The controls deliberately retain that negative
result. A public payout plus fee always exposes the whole-claim input sum; hiding
its positioned CM is a different question. More than one arithmetic solution
does not establish equal probabilities or any adopted privacy target.

The fixed public controls never read the old72-case ledger corpus. Each observer
child receives only its public JSON request; expectations stay in the controller.
The independent certificate checker uses Python integers. One solver thread per
child and at most four children respect the selected resource plan.
