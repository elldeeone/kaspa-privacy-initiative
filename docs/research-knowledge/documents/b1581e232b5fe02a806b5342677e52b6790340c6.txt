# Private change design review

Reviewer: `/root/private_exit_review`. Baseline:
`a8392f1127e656da59709e0b6f93ece7cf5eb9c2`. Prior closed files are unchanged.
This is independent source/design review, not a cryptographic audit or authority
to run a trial. No reviewer seed, backup, PK, witness, private recipe, VM, proof,
setup or RPC access occurred. No additional reviewer agents were spawned.

## Reviewed design

Final draft contract:
`1290887276efea1c0e3afca6ef683c0a7aac2ec6c72625be04564a557a34fd7e`.
ADR draft:
`84f1d0ca6150e3d49f4748c4e79d8746fbfb70644cb07581176c015c6b1ed906`.
Source notes:
`76a23b88fa49238075c9d7972ea61384bbc80b88b2f61ce5612f0add3548e44f`.

The exact requested payout/payment, private change and fee equations preserve
the existing relation: `V=P+f+C` for partial withdrawal, `V=T+f+C` with P0 for
private payment, and `V=P+f` for full withdrawal. Reserve decreases by `P+f`,
not by the entire consumed note when change remains. Positive notes retain the
60M floor, native payouts the10M floor, and all amounts the existing maximum.
The proposed10-KAS route has sufficient headroom for both real change notes;
the previous60M receipts could not fund a partial payout plus change plus fee.

The five-proof/six-body main workload, plus a separately labeled sixth local
C0 fork proof, is coherent. Main counts advance to CM9/NF11/R0. Both positive
branches created by the later private payment are independently recovered and
spent. Whole-source equations count all three native payouts, every actual fee
and both possible ordinary change tails once. The alternative C0 supplied-
context fork must never enter the main/live drainage ledger.

No remaining design blocker was identified in these exact drafts. Root's final
accepted ADR/common contract and the new implementation remain distinct stages.

## Recovery and role invariants

Selected V2 source
`93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2`
decrypts the encrypted u64 index before deriving its expected receive fields.
Its stable delivery key therefore permits original-seed restoration without
an issuance counter, lookahead window or operator ownership map.

Root chose uniform little-endian OS-u64 indices for new self-change, rejecting
all recognized historical own indices/receive tuples, spent included, and the
current input/recipient tuple. This does not prove uniqueness against unseen
pending invoices, orphan-only history or another device. The contract correctly
states64-bit probabilistic freshness and retains duplicate ownership authority.
`owner_action_available` remains true for every valid unspent accepted position;
`normal_credit_sompi` deliberately excludes duplicate invoices and cannot be the
new wallet's spend-selection authority. The bounded largest-claim policy and
lowest-position tie-break do not claim arbitrary aggregation/affordability.

Each actual recovered receipt's index must select its s/k/native authority.
The earlier trial assembler's index0 shortcut cannot survive this extension.
Current CM membership and the original positioned NF must come from freshly
authenticated public state. Orphan/reverted state cannot remain spendable, while
lost orphan history cannot be relabeled fresh or assumed reconstructible.

Input and output roles are independently shuffled once per preparation. Real
NF is slot-independent; dummy HMAC includes its actual chosen slot. Both NF
insertions and their witnesses must be rebuilt sequentially in Auth order:
simply swapping old witness chunks changes append indices and is incorrect.
CM appends, paths, ciphertexts and private output witnesses must share the same
chosen output order. A fixed positive-change slot or exported role/index/CM map
would defeat the intended hiding. Continuing padding remains established sealed
box ciphertext, not publicly recognizable zeros.

## Fee-dependent material and the C0 barrier

For fixed requested P/T, a changed fee changes self-change value and therefore
the Note, CM, ciphertext, append roots, next state and Auth. The selected old
full-claim builder freezes its outputs and only adjusts payout; reusing it
unchanged would be wrong. Hold the index/receive fields/rho/permutations stable
within one preparation, use fresh sealing for changed plaintext, and keep the
exact final selected candidate after quoting. New preparations sample anew.

Root explicitly added exact-zero-change payment support. Its public sizing
candidate must have no private-witness field/serialization API and must never
write the witness pipe or authorize proving. It intentionally is not a valid
private-conservation statement. After sizing, derive C from the exact requested
T and provisional fee, reject negative/subfloor-positive C, then build and check
the actual recipient plus positive change or legal zero-value padding. Requote
that exact actual material and select only its actual quote ID/body. Any fee
change invalidates and rebuilds the candidate. Actual proof substitution and
Full/all-engine/whole-context quote equality remain mandatory.

The already authenticated local prover may wait with an empty pipe throughout
sizing; parameter authentication must still precede backup bytes. This needs
no second full PK load. Sizing/intermediate NF/Auth/CM/candidate hashes, bodies
and diagnostics remain private and unbroadcast. The new quote export will
contain only the final actual quote, without intermediate sizing attempts.

The new generic API will also reject own-backup aliases before any caller-
selected public/executable/PK file read or hash: original-path metadata checks,
regular files, and device+inode comparison catch hardlinks as well as identical
paths. Invoice size208 is checked before its single read/snapshot. This guard
does not read/hash backup bytes and does not claim to discover arbitrary other
secret files; the one-backup cold namespace remains the actual exposure bound.

## Evidence and prototype boundaries

The accounting module `economics.py`
`4ea534e7e2f5556f0fd2e32f57003fbd223294d23a8e7658455b523dd979c870`
was read. Its bounded integer fee map, all change/payout floors, per-action and
whole-source equations match the fixed workload. Owner control report
`428f4bd1ed1f36d600efdf4e4fe5a18c64e44c3b36f8731b4ce2168fa70f2d35`
pins the source and labels its five controls/250 generated partitions as a pure
planning model. Actual note recognition, ordinary output legality, fee/body
quotes and native acceptance remain later evidence; no controls were repeated.

Five positive proofs do not alone establish a genuine current-state occupied-NF
adversarial proof. Retain meaningful original/change owner-refusal, stale-head
and original-proof/body mutation controls, with unchanged prior native occupied-
NF evidence cited separately. An extra genuine rebased occupied-NF statement is
needed only if claiming that stronger new coverage; early native rejection with
an old proof must be labeled accurately. The sixth C0 proof tests its own
separate integration branch.

Fresh D changes circuit constants and requires fresh parameters/source identity;
equal dimensions never authorize loading prior AA/CAF/S7 keys. No NF/current-CM
or ownership checks may be removed for a fee prototype without a constrained
replacement. Budget1500 is not justified by a measured path alone. The scoped
old two-recipient baseline shares three verifications, or1.5 per recipient;
its22,125,000-sompi floor is not a universal three-check/recipient bound.

Private change removes a universal whole-claim wallet equation; this small
single-owner trace still exposes intermediate reserve totals and public P/fees/
timing. Financial privacy, the complete fee target, audit, setup honesty,
durable software/data/parameter availability, hostile-host protection and
independent consensus remain unqualified.
