# Public-control interface

This is a symbolic control schema, not an encoded native action or new privacy
protocol. Its primary purpose is falsification. Current wallet crypto canaries
may be adapted only after source review and remain no-proof/no-native evidence.

`independent-payment-public-control/v1` includes exactly a classification,
profile, max_real_inputs (1 or 2), wallet_policy, funder directory, participant
role, complete own-note records, outgoing-invoice facts and ordered events. No global owner/purpose/selected-input map is a
public field. `ledger.py` defines exact whitelists and canonical integer/byte
bounds; future/random holdout use is not authorized.

Each event exposes public reserve before/after, fee, native payout/SPK, physical
CM cursor, NF count, mode, aligned output positions/CM/ciphertext and two NFs.
Ingress value/source are public. A separately declared known bootstrap owner can seed an ownership fact for
that initial note only. It never becomes an identity between later invoice
payer roles and original funding lineage. Profiles distinguish legacy mode0-at-R0 from a
prospective no-append full-input mode that can leave other reserve. The latter
is a symbolic capability control, not a claim of current native acceptance.

A legitimate own-note record contains its position, CM, claim value and original
NF, including its bootstrap and private-change claims if it is also a payer. An
incoming invoice may add its authenticated payer role; bootstrap/change records
use null. Separate outgoing-invoice facts include the known recipient CM/value
and business-recipient role, without claiming knowledge of its NF. A payer/payee
participant is not weakened to incoming receipt knowledge only. Expected own
payments in either direction cannot count as unknown third-party targets. Its absent NF excludes
that receipt from prior observed spends. Under the explicitly known one-invoice
plus sender-change wallet policy, a positive sibling belongs to that payer.
The actual new preparation API also guarantees positive change;
`one-invoice-positive-change` enforces both P0 values at the floor in the solver
and independent checker. Zero-change controls use the separate generic
optional-change relation. That fact can propagate through globally mandatory later inputs. It is not an
unconditional owner fact under generic two-payment output behavior.

`observer.py` uses an exact global integer relation with one/two distinct real
inputs, chronological positive selection, at-most-once spend, same-CM value
binding, exact output/payout/fee conservation and all-prefix backing. Native
mode2 may leave positive private change; no full-cashout assumption is imported.
The independent checker in `ledger.py` has no solver dependency. Certificates
contain only note values and selected input positions. They are arithmetic
controls, not secret keys or authorized alternative cryptographic worlds.

Every global action queries inclusion and exclusion of every earlier actual
position (not alignment gaps). Complete results require all rows and an
independently checked SAT certificate satisfying each exact requested predicate;
public-baseline contradictions reject. Only complete results emit mandatory
inputs or conditional wallet payer roles. First UNKNOWN stops that view and
leaves all further rows incomplete. A resource/canceled result never means
UNSAT or privacy.

The visible-partition and direct-cohort controls in `partitions.py` evaluate
restricted metadata claims; they do not label an unrun global reconstruction as
complete privacy measurement. Their complete true ledger still receives an
independent conservation/spentness check. Explicit public component arrays
remain public under a display permutation. A genuinely hidden assignment needs
a new relation and is not falsified merely by assuming its assignment is shown.

Initial public-control resource proposal: one process/solver thread at a time,
2 CPU cores, 6 GiB cgroup memory, zero swap; per-query300 seconds and Z3 4096 MiB.
These are generous operational limits for fixed small fixtures, not security or
privacy thresholds. Source/fixture review and root release precede execution.
No heldout sampling is selected.

The global solver deliberately remains a value/spentness relaxation, not a
complete cryptographic owner-world model. Role deductions use mandatory inputs
or an all-feasible-input ownership cover, legitimate known bootstrap/own-note
facts, and the declared one-payer wallet policy. Actual control ownership and
invoice provenance are checked by the separate fixture verifier. SAT is never
an ownership/cryptographic indistinguishability certificate.
