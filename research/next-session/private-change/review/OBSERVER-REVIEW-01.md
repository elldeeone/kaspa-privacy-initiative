# Independent review of the public arithmetic observer

The selected v1 source and its fixed public control artifacts are consistent with
the declared bounded integer model. No correctness blocker was found in this
source pass. This is not a privacy qualification or a new evaluation release.

Reviewed source freeze: `3affbf544bcd124df36397a2c66550978e500eb5e971f1e31004c9892cbcf41c`.
The seven current source files match its hashes and lengths. Selected plan,
API and selection remain `34cbf94c21e174a9f2ecb48b2695feb4ef94c25550be5afad15e62323a285ad5`,
`6f333059b978b9d5664a4584e4bf26fe08c79c67454d631e5558d44d8a0039e0` and
`2625177929270e41e505b5c45e33f51314fe8cf9564a89664b3c1a438752b9a8`.

The review covered `public_ledger.py`, `change_model.py`, `certificate.py`, the
stdin interface, public cases, control assertions and result interpretation.

- Each private event selects exactly one earlier positive positioned note.
  Uses of a position are limited to one. Conservation holds for each event and
  every prefix's remaining liabilities equal its public reserve.
- Note values use exact bounded integers, with zero or the positive note floor.
  Public ingress values and explicitly supplied legitimate priors constrain
  those values. Whole-claim and change-capable payout policies are distinct
  declared assumptions; neither receives a hidden partial/full operation flag.
- A forced amount query excludes the baseline value over the complete declared
  relation. A forced selection query excludes that event's baseline positioned
  note. These are solver UNSAT queries, not sampled alternatives.
- Every SAT baseline and countermodel passes the separate Python integer
  checker. The queried difference is recomputed from that checked certificate.
  The checker independently rejects future, zero and repeated input positions,
  incorrect conservation, incorrect policy and incorrect prefix backing.
- Exact field sets reject owner maps, input selection, operation intent and
  change-slot hints. Noncanonical amounts, inconsistent counts/reserves,
  duplicate nullifiers and incomplete coverage reject. Scope limits and UNKNOWN
  produce incomplete results. At most 37 queries cover the selected limits.

Repeated CM bytes remain separate positioned liabilities. Version 1 deliberately
omits equal-hash/value equations and cryptographic preimage constraints. This is
a conservative relaxation for forced facts under the stated wallet-policy
assumptions. A SAT alternative does not establish an authorized cryptographic
history, owner ambiguity, equal probability or financial privacy. Adding those
binding equations requires a separately specified stronger model version.

The reviewer read the retained results
`d6040cabe261d5390fba3d3ce39310f45baca5d399201b7d3972a8e3c717c475`:
eight analytical cases, 19 malformed/scope cases, four invalid certificates and
one test-only UNKNOWN control. No controls were rerun. The source and docs
explicitly trust Z3/model correctness for UNSAT; they do not claim an independent
formal UNSAT proof checker. Owner links remain `NOT_MODELLED`.

No old population, hidden truth, private wallet material, proof, native VM,
network or funding was read or run by this review. Heldout evaluation remains
unauthorized by this packet.
