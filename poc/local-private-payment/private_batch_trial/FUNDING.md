# New-profile funding and activation route

Source integration only. No mining, node query, funding, private funding
signature or broadcast has run through these new modules. The accepted-wallet
history and live private-prover integration remain separate qualification work.

Create a fresh unfunded identity with one command:

```sh
python3 -B poc/local-private-payment/private_batch_trial/funding.py new \
  --label fresh-new-profile-trial
```

This delegates the already executed bootstrap: three separate new Originals,
three genuine20-KAS Output proofs and three Original-only recovery probes.
It uses `kpb-ak-bound-original-seed-backup/v1` and `KPBKDF01`. No legacy backup,
legacy seed parser or legacy receiving/signing KDF is accepted.

`funding.py identity` takes that exact public trial receipt/hash plus the final
component manifest/tail selections. It independently verifies the three initial
Output/CV liabilities and derives the three public `kaspatest:` funding addresses.
The output is `kpb-three-owner-funding-identity/v1`, binding all five IDs, the
bootstrap/component/tail hashes and exactly three distinct funding keys.
It is explicitly not a readiness declaration.

`funding_worker.py` runs two operations inside one-owner network-off namespaces:

1. `consolidate`: admit only that owner's exact new-profile mature coinbase
   observation, normalize and price a self-payment, reopen one new Original,
   derive its versioned native funding key and sign only its own inputs. Reuse
   the existing arbitrary-input `consolidation_sdk.mjs`, then actually verify
   every native input. The GEN3-only `sdk.mjs` cannot sign coinbase consolidation.
2. `approve-genesis`: independently validate the actual new GEN3 Output/CV,
   funding/contribution/change/fee equations, exact native ID/mass and SDK
   roundtrip before reopening the Original. Recover its exact admitted note,
   verify its designated funding key and sign that complete CASE with ALL.
   Only its signature/public approval leaves the owner namespace.

`funding.py propose-genesis` uses three integer-sompi ordinary sources and the
actual selected tail. `combine-genesis` binds all three approvals to the same
unsigned CASE, then reexecutes native normalization, SDK roundtrip and actual
NativeFull/all input engines. Public CASE validation alone never grants entry
authority or proves accepted backing.

`funding_network.py` provides closed public operations through the selected
Tor/SDK stack: anchor, mining, maturity collection, one-shot submission,
ordinary-output readback and fresh Full-prefix whole-CASE confirmation. The
default stages only; `--execute` activates the selected operation. Every
submission has a durable one-use trial/stage record before the RPC write.
An uncertain submission is reconciled read-only and is never resubmitted.
The public namespace mounts certificates and two admitted Python wheels only;
it mounts no wallet Original, private TLS/CA keys or installed Python dependency
tree. Node/SDK/software are shared read-only rather than copied per owner.

The concrete final research funding entry is:

```sh
python3 -B poc/local-private-payment/private_batch_trial/activate.py \
  --label ACTUAL_FRESH_LABEL \
  --trial ACTUAL_BOOTSTRAP_TRIAL --trial-sha256 EXACT_TRIAL_SHA \
  --identity ACTUAL_FUNDING_IDENTITY --identity-sha256 EXACT_IDENTITY_SHA \
  --component-profile ACTUAL_COMPONENT_MANIFEST --component-profile-sha256 EXACT_COMPONENT_SHA \
  --tail ACTUAL_IMMUTABLE_TAIL --tail-sha256 EXACT_TAIL_SHA \
  --rehearsal COMPLETE_NATIVE_REHEARSAL_MANIFEST --rehearsal-sha256 EXACT_REHEARSAL_SHA \
  --output FRESH_PUBLIC_ACTIVATION_DIRECTORY --execute
```

Without `--execute`, this writes a finite plan and performs no network action.
With it, `rehearsal_gate.py` first directly reexecutes the complete signed GEN3,
two private-batch CASEs and nine current-head Exit CASEs, every actual NativeFull
check, complete public state replay and the same terminal-history three
Original-scan reports. It accepts no imported ready/PASS Boolean. A successful
offline gate still does not establish a real testnet terminal payout or trial
readiness. The command activates a research GEN3; real R1/R2, nine payouts and
zero-reserve Original scans must follow through the qualified accepted-history
and live private-prover path. It does not silently run those through the
unfunded wallet-history facade.

Activation runs three independent public miners concurrently, waits for their
own reward maturity, consolidates only to the matching owner keys, obtains
three actual Original ALL approvals, submits GEN3 once, then acquires/replays
the exact whole accepted CASE and current60-KAS reserve. Its handoff retains
the birth anchor, signed CASE, actual admission and fresh acquisition locations.
It claims no independent consensus proof, terminal completion, privacy or fee
saving. Failed stages retain their identities and logs; retry means a fresh
unfunded trial, with no journal reset, weaker check or new broadcast of an old
used action.

Four focused public funding-observation tests pass: exact1000-DAA maturity,
single RPC-string to integer-sompi conversion, profile/network/role separation,
and refusal of amount aliases, duplicate/foreign sources and wrong coinbase
flags. Eight GEN3 tests and eleven wallet boundary tests pass separately. These
checks qualify their tested parser/state behavior; they are not executed new
funding or proof of cryptographic/production safety.
