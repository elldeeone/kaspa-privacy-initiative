# Explicit independent Exit release

`exit_release.py` completes the boundary between an owner's private prepared
AuthExit candidate and the public native transaction builder. Its default
`release` command stages a finite selection without reading or exporting the
candidate. `--execute` launches a network-off role with one candidate leaf,
the exact public head and immutable tail, and the selected AuthExit binary/VK.
It mounts no Original, note opening, proving key, MPC share or service state.

The controller derives the private leaf from the same trial's typed Exit
operation result. It checks metadata only. The role checks the candidate's
strict public schema, complete native projection, actual indexed-NF insertion,
exact selected head and tail, exact152-byte owner statement, and genuine
AuthExit proof before publishing `PUBLIC-CANDIDATE.json`. Unknown fields and
caller acceptance flags refuse. The controller may read/hash only the newly
released public output, after the worker has completed.

```sh
python3 -B poc/local-private-payment/private_batch_trial/exit_release.py release \
  --label FRESH-LABEL \
  --bootstrap-trial TRIAL.json --bootstrap-trial-sha256 TRIAL_SHA \
  --prepared-exit-result EXIT-RESULT.json --prepared-exit-result-sha256 EXIT_RESULT_SHA \
  --owner-component 0 \
  --history PUBLIC-HISTORY.json --history-sha256 HISTORY_SHA \
  --tail IMMUTABLE-TAIL.bin --tail-sha256 TAIL_SHA \
  --execute
```

Labels use lowercase letters, digits and hyphens. Staging consumes its fresh
operation identity; use a new label for an executing attempt. A release does
not submit a transaction. The native builder must separately normalize the
complete CASE, quote its exact fee, run actual Native Full/all input engines
and obtain fresh accepted-chain evidence.

This interface accepts **`UNFUNDED_SUPPLIED_CONTEXT` only**. Its head decoder
does not replay or admit an accepted history. The earlier owner preparation
performed the complete supplied-context wallet replay; neither that replay nor
this proof check establishes GEN3 backing or chain currentness. The separately
selected live history adapter remains mandatory before funded use.

Nine independent withdrawals need nine successive heads: restore/prepare one
owner's next unspent claim, release it, build and confirm that exact transaction,
then reacquire the new head before preparing the next claim. Parallel candidates
from the same head are competing spends. No nine-Exit terminal rehearsal or
native payout confirmation is claimed by these source controls.

The public selection and `OBSERVED-RELEASE-ROUTE.json` retain the actual owner,
private leaf pathname, operation identity and execution times, including failed
attempts. They reveal the owner's association with its released NF and payout.
These legitimate terminal observables belong in the frozen observer model;
this local route does not provide unlinkable withdrawal publication. Terminal
and economic privacy remain unqualified until their actual views are measured.

Seven focused model controls cover finite export fields, exact continuing and
terminal contexts, proof/statement refusal, stale and cross-lane replay, changed
native policy/NF witness, noncanonical proof bytes, and private leaf aliases.
They test the boundary, not cryptographic correctness. The separate retained
public-fixture controls exercise the real AuthExit verifier inside the actual
network-off release role without any actual Original or private wallet input.
