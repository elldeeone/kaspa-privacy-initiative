# H15 adversarial review

Implementing agent's second pass, not an independent audit. The changed
subsystem is an offline observer/controller. The circuit, covenant, wallet
construction, native validator, parameter identity and H14 evidence are pinned
and unchanged.

## Is the extra knowledge legitimate?

The additions are explicitly conditional on correct attribution to this
prototype's client behavior. They are not implied by Kaspa or v6 consensus.
The private plan chooses inputs and recipients; those choices do not become
observer facts. An attacker who learns the whole public synthetic recipe could
do more, but this experiment tests an isolated program that does not receive it.

Admission and partial-withdrawal padding are derived from generic construction
branches, rather than the private amount rows. A full exit consumes one note
because the actual fallback helper passes one real input. Its old anchor is
assumed to be the note's birth root because the driver creates fallbacks at
receipt. That last assumption can be false for a different backup policy; the
shape-only ablation measures inference without it.

An anchor equal to current commitment count does **not** identify the newest
note. It may be a fresh proof of any eligible note. The observer never receives
the fresh/saved arm label. A control specifically retains an older-note
explanation at a current root. Full exits append no commitments, so this remains
true throughout drainage.

There is no implemented automatic oldest/largest-first input selector. Ordinary
payments and partial withdrawals can select one or two notes. Positive/dummy
payment outputs remain hidden. The intended change owner is not a public wallet
identity. Equal-owner constraints alone cannot remove histories when assigning
all notes to one owner satisfies them; distinct funding keys do not justify
inventing distinct owners. Linking actual people, known merchants or externally
labelled accounts remains outside this model.

## Could the solver manufacture privacy or false certainty?

- The original H14 integer relation is reused unchanged. One implementation adds
  policy equations in CP-SAT; a separate implementation adds them in SMT.
  Independent exhaustive small ledgers check both and the hybrid engine.
- Rational graph search may prove infeasibility, but a positive answer requires
  validation of the whole chosen input graph by integer CP-SAT with the same
  policy. Rejected rational graphs are blocked, not counted as alternatives.
  No amount rounding or floating-point value arithmetic is introduced.
- Zero-slot knowledge excludes that slot from future input choices; it never
  creates a participant. Every note can be consumed at most once. Terminal zero
  backing consumes all positive notes.
- Required targets and horizons are inherited from H14. Backward computation
  reuses only witnessed feasible histories at earlier prefixes. It never carries
  future negative answers backward. Independent forward-prefix controls check
  the resulting information boundary.
- Each true input/source set must survive every attack and horizon. Results must
  nest: wallet subset of shape subset of protocol. Empty/unknown, missing
  results and any truth exclusion abort the comparison; none count as privacy.
- Logical uniqueness, fixed recency guess correctness and marginal candidate
  counts remain separate. A correct guess does not establish certainty; a large
  candidate set does not establish equal probabilities or user anonymity.
- Deliberately out-of-profile fixtures remain feasible in the protocol model
  and become infeasible under the assumed wallet behavior. They test conditional
  attribution, not consensus rejection.

## Isolation, exits and unchanged security obligations

The observer receives public JSON, its fixed profile name, its code and solver
libraries inside a filesystem/network sandbox. The controller, generator,
manifest, private truth, keys and unused fallback bundles are not mounted.
Scoring opens truth after predictions have been written. Source/input hashes
and denied-access probes record the tested boundary. The researcher knows the
recipe; this is process isolation rather than independent human blinding.

No transaction is generated or broadcast. No spend capability or amount rule
is changed. H14's genuine calibration and independent-exit results are inherited,
not rerun or extended. Inflation, double spending, unauthorized withdrawal,
stale/replayed state, setup trust, reorg handling, history availability and
dependency failure therefore retain their existing implementation boundaries.
This study cannot improve or establish those properties. Solver failure affects
only completion of the analysis and cannot move native funds.

RPC/IP observation, realistic arrival distributions, compromised wallets, later
ordinary payout spending and cryptographic byte attacks are untested. All
privacy conclusions are conditional on this small synthetic workload, the
declared hiding assumptions and the stated client profile.
