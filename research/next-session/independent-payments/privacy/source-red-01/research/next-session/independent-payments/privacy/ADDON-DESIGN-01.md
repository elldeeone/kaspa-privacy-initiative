# Outgoing-recipient ownership calibration

The original ec337927 eight-group run and all nine source payloads are retained
under `source-01`. Review found a real omission: outgoing invoice values entered
the global solver, but the known recipient role did not enter the owner facts.
The original finite negatives remain valid; they did not test a later spend of
such an outgoing note. That result is not exhaustive legitimate-role coverage.

Before changing core source, freeze and run one new fixed public calibration:
Alice funds 100 KAS, pays Bob 30 KAS plus exit credit, and Bob later pays Carol
20 KAS plus credit. Alice is the observer. She knows her bootstrap/change NFs
and her outgoing Bob invoice CM/value/recipient role. Her change NF is absent
from Bob's later action, so Bob's receipt is the unique input. Both one- and
two-real-input allowances must recover current payer role Bob (1), while its
original funding ancestor remains Alice's source (0). Carol's invoice is not
one of Alice's own payments. No privacy target is passed.

The same addon code/fixture is used for red and green. The correct assertion is
role=1. Old source should fail it with role=None; retain that RED result. Add
only the missing outgoing position→known recipient owner fact to observer and
independent derived-field checker, under SOURCE-FREEZE-02. Re-run the affected
finite controls once and this calibration; keep all source identities/results.
No old96 case, threshold, hidden sample or cryptographic relation is changed.
Independent source review precedes any declared corrected-coverage claim.
