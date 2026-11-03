# Stage 2 audit evidence

Offline reanalysis of three earlier synthetic TN10 traces. No new transactions,
fees or private proofs. [Report](../../PRIVACY.md),
[method recorded before observer execution](../../PRIVACY-AUDIT-SPEC.md).

- `compact-rehearsal/observer.json`: four exits, matching and joint-value models;
  first-exit newer-anchor sensitivity is abstract, not a valid replacement proof.
- `compact-trial/observer.json`: all 102 exits, anchor/single-spend matching only.
  The first exit's source is unique; other candidate sets are upper bounds before
  amount analysis. No aggregate anonymity or owner-identification score.
- `recovery-trial/observer.json`: all three exits, matching and joint-value models.
- Each case's `isolation.json` and `execution.json`: software/chain-only mounts,
  unavailable host home, loopback-only network, successful observer exit.
- `scoring.json`: separately checks the two already documented H6 target sources
  after the attacker finishes; never mounted into the attack process.
- `provenance.json`: retained source paths, exact source/projection/output and
  software/specification hashes. Recreate the projections with the runner; the
  large original transaction bodies are already versioned and are not duplicated.
- `controls.txt`: twelve analytic/parser tests, including exhaustive matching
  against brute force on small prefix systems.

All amounts are integer sompi. Each report carries exact candidate positions and
source transaction IDs in shared `candidate_sets`, referenced by every withdrawal
and horizon so repeated lists are stored once. Candidate
sets are not independent users, posterior probabilities or real-world anonymity.
The retained node receipts are the chain-acceptance evidence; this run did not
requery the network or independently verify consensus/Groth16. RPC and public
archive/experiment-label observation are separate from the chain-only model.
