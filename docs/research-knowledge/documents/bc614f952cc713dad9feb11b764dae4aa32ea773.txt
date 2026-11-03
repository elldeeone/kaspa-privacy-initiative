# Privacy after aborts: architecture options

**2026-10-25 — research proposal, not a selected architecture or implementation.**
This review used public source and primary literature only. It does not change
the frozen study, financial profile, RFC-0028 or ADR-0065. The external
[active diagnostic](ACTIVE-RETRY-EXECUTION-01.json) used three actual phase-one
MPC admissions with synthetic wire inputs: changed-cohort retries identified
3/3 eligible owners, versus 0/2 in the same-cohort control. All aborted before
authorization. This is wire-fixture ownership leakage, not financial acceptance
or a confirmed payout.

**Recommendation:** compare a self-contained local shielded spend with anonymous
submission against a larger fair MPC construction before committing to the
latter. Interactive batching is a fee/design choice, not an established privacy
requirement. Delaying nullifier disclosure helps only if its release and retry
contract also handles unavailable outputs, competing exits and stale state.

## What the present code establishes

| Source evidence | Consequence for a replacement |
| --- | --- |
| [Spend statement](../../../../poc/owner-private-lifecycle/relation/src/statements.rs), lines 15–64, and [circuit](../../../../poc/owner-private-lifecycle/relation/src/circuit.rs), lines 129–171, bind domain, membership anchor, own NF/CV and effects digest. | An owner can generate this proof from an authenticated digest without learning other owners' NFs. The circuit does not prove that this digest includes the owner's intended payment/change. |
| [Wallet authorization](../../../../poc/sender-private-lifecycle/wallet/worker.py), lines 411–446, independently checks current state/outpoint, reserve, fee, successor policy, complete MPC rows, own outputs/change, input inclusion and balance. | These consent checks need authenticated equivalents. Blindly signing a coordinator-supplied hash would remove a theft-prevention boundary. |
| [Effects hash](../../../../poc/owner-private-lifecycle/verification/wire.py), lines 219–243, excludes the final three Spend proofs but includes the complete body core. [Body construction](../../../../poc/sender-private-lifecycle/integration/public.py), lines 235–242, creates sequential NF witnesses and roots. | There is no Spend-proof/hash cycle. Hidden construction still needs correct oblivious tree work, exact serialization and semantic validation. |
| [MPC program](../../../../poc/sender-private-lifecycle/admission/kpx9_admission.mpc), lines 34–99, opens shuffled records; [backend](../../../../poc/sender-private-lifecycle/admission/backend.py), lines 516–528, aborts on party failure and accepts only three equal outputs. | The selected implementation provides no demonstrated mechanism for an honest party to recover a complete transaction after unfair output release. READY flags or arbitrary proof bytes are not a valid-proof release gate. |
| [Native policy](../../../../poc/owner-private-lifecycle/verification/native/src/policy.rs), lines 267–297, checks the actual consumed reserve outpoint and exact effects. [Independent exit](../../../../poc/sender-private-lifecycle/integration/public.py), lines 291–306, consumes that same current head. | Valid proofs and fair delivery do not guarantee settlement. Another valid exit can consume the head first, leaving exposed honest batch NFs unspent. This is a source-derived conflict case, not an executed experiment. |
| [Attempt reconciliation](../../../../poc/sender-private-lifecycle/wallet/worker.py), lines 99–108/449, waits for an authorized NF to become spent; seed restore at lines 220–225 imports no attempt journal. | A private permanent retry refusal is neither durable seed-only recovery nor a complete payment/retry policy. |

## Established designs and their limits

**Orchard:** the pinned builder takes owned notes/Merkle paths and recipient
addresses, then creates the bundle, proof and authorizations locally. A normal
single-wallet payment need not recruit other live owners. Its signatures still
bind the transaction sighash; this is not a precedent for signing unconstrained
intents. [Orchard builder, pinned 616a669](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L901).
The specification permits earlier-block Orchard anchors and separately enforces
chain-wide NF uniqueness. Membership need not depend on the latest unrelated
spend. Our exact reserve-outpoint binding is an additional constraint; historical
anchors alone would not remove it. [Pinned protocol, action and NF rules](https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/protocol/protocol.tex#L3976).

**WabiSabi:** anonymous credentials and separate network identities separate
registration roles. Its protocol explicitly identifies targeted coordinator
denial/intersection and timing attacks, leaving their mitigation outside its
scope. Blame or banning can raise disruption costs; credentials do not establish
our stronger retry guarantee. [Pinned protocol 1e6deb9, roles and attacks](https://github.com/WalletWasabi/WabiSabi/blob/1e6deb989f58bc6edce91bc300252d2bed18db30/protocol.md#attacks-on-privacy).

**Fair MPC:** the selected MASCOT family is malicious/dishonest-majority MPC;
that label does not promise output delivery. [Official MP-SPDZ model table](https://mp-spdz.readthedocs.io/en/latest/readme.html#protocols).
Veldhuizen et al. provide an established SPDZ adaptation with fairness below
half corrupt parties and selective-abort security otherwise. Its synchronous,
authenticated-channel model and additional agreement/opening assumptions require
mapping to our deployment. Two honest parties out of three fit its corruption
threshold, but the selected binary does not implement this adaptation. The
paper's benchmarks do not measure this workload or Kaspa settlement.
[PoPETs 2024, §§2.2,4–5/Theorem 5.1](https://petsymposium.org/popets/2024/popets-2024-0053.pdf).

**Ledger assistance:** Bentov–Kumaresan's Bitcoin construction offers fairness
through predefined financial penalties and a claim-or-refund abstraction.
Compensation does not erase disclosed NFs or make our stale transaction valid.
A native-KAS mapping is unverified. [Authors' publication page](https://www.microsoft.com/en-us/research/publication/use-bitcoin-design-fair-protocols/).

## Candidate comparison

These are engineering inferences from the evidence above, not measured results.

| Candidate | Reuse / change | Cost, assumption and unresolved issue |
| --- | --- | --- |
| Hidden construction, valid-proof gate, fair output | Can retain Spend200 semantics; replace/expand MPC and owner private views. | Secret tree/hash/curve/proof checks and a fair-release implementation are substantial. Fair delivery still leaves chain conflicts and reorgs. |
| Fixed cohort and local attempt lock | Operational change under current financial rules. | Restricts availability; recovery or changing eligible inputs breaks the simple cohort premise. The same-cohort control is not general privacy evidence. Not sufficient alone. |
| Anonymous submission/admission | Can retain current financial checks; remove the coordinator's authenticated owner-to-request association. Credentials are optional research candidates. | Requires an explicit transport, timing, admission and collusion model. Hiding payload labels does not hide endpoints. Known-member selective exclusion still needs analysis. |
| Self-contained local 3-input/6-output spend | In principle retains current statements/keys if one wallet controls all three eligible notes. No other live owner is inherently required by native verification. | Unimplemented wallet/orchestration path. One genesis note per owner prevents its first payment; it does not create three-party mixing privacy. Network-origin anonymity remains separate. |
| Local 1-input/2-output spend, with optional later aggregation | New shape, financial profile, outer guest/proof identity and native policy. Existing per-note Spend/Output keys may remain if their predicates stay unchanged. | Removes mandatory multi-owner authorization rounds. Proving/fees and anonymous ingress need measurement. Current exact-effects proofs still need rebuilding after head movement. |
| Reusable private payment intents / historical anchors | Requires a new authorization-and-verification contract separating owner consent from mutable executor state. | Must bind intended outputs, fee limits, domain and replay rules without publishing an input-to-output ownership map. Do not reinterpret the existing effects field silently. No reviewed construction selected. |
| Ledger reservation or durable pending claim | New consensus-enforced protocol state and recovery rules, not a local mutex. | Extra transactions/state and exit-delay/availability obligations. A reservation that later expires with the same exposed NF unspent does not solve the leak. |

The current [wire](../../../../poc/owner-private-lifecycle/verification/wire.py),
lines 168–192, and native policy fix three real inputs/six outputs. The component
[circuit](../../../../poc/owner-private-lifecycle/relation/src/circuit.rs), lines 53–68,
requires positive note values; lines 129–171 require real membership and nonzero NFs.
Zero dummy inputs therefore cannot be assumed under the present component VK.
Supporting them changes that circuit/key; supporting fewer real inputs need not
change the per-note predicate, but does change aggregate/native acceptance.
Domain reuse is also conditional: SpendCircuit line 133 constrains the domain to
the compiled constant. Selecting a new financial domain requires a corresponding
component circuit/key refresh; it cannot be treated as a free public parameter.

## Exit and release contract to resolve first

[I-8](../../../../SECURITY-INVARIANTS.md) forbids privileged arbitrary freezes;
I-9 permits safe halting/delay, and I-10 requires recovery after a hosted service
disappears. No numeric maximum exit delay is currently specified. A proposed
bounded reservation must state consensus-enforced expiry, user authorization,
independent recovery and resistance to adversarial renewal. Outstanding pending
claims must retain backing under I-1. Changing these rules needs explicit
RFC/ADR review; none is selected here.

The decisive question is: **after the first stable NF becomes observable, what
prevents an honest owner being left with that NF unspent and needing a changed
cohort to continue?** Specify the answer for aborted output, invalid peer data,
a competing independent exit, stale state, reorg and seed-only restoration.
Distinguish ledger anonymity (hiding which commitment a NF spends) from network
origin, participant membership and public transaction grouping.

Before a large new MPC build, write the smallest authorization/validator contract
for a local 1-input/2-output payment and compare it with fair MPC under this same
question. Neither option may claim privacy from encryption, passing controls,
fairness alone or assumed inclusion. This review ran no active experiments,
read no private wallets/truth and changed no selected runtime source.
