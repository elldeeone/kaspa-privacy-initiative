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

`funding_network.py` is currently `CONFIGURED0`. Its default mode writes only an
inert `kpb-public-network-source-only/v1` receipt. It writes no command, child
job, controller, registry, journal, namespace mount plan or RPC selection.
`--execute` refuses before reading the root guard or constructing any network
command. Both selected JavaScript children independently refuse before mounted
inputs or RPC. The retained Tor/SDK implementation is source for a future
parent-owned path; it is not currently executable through this profile.

The concrete final research funding entry is:

```sh
python3 -B poc/local-private-payment/private_batch_trial/activate.py \
  --label ACTUAL_FRESH_LABEL \
  --trial ACTUAL_BOOTSTRAP_TRIAL --trial-sha256 EXACT_TRIAL_SHA \
  --identity ACTUAL_FUNDING_IDENTITY --identity-sha256 EXACT_IDENTITY_SHA \
  --component-profile ACTUAL_COMPONENT_MANIFEST --component-profile-sha256 EXACT_COMPONENT_SHA \
  --tail ACTUAL_IMMUTABLE_TAIL --tail-sha256 EXACT_TAIL_SHA \
  --preflight SAME_TRIAL_ACTIVATION_PREFLIGHT --preflight-sha256 EXACT_PREFLIGHT_SHA \
  --output FRESH_PUBLIC_ACTIVATION_DIRECTORY --execute
```

Without `--execute`, this writes a non-executable research plan and performs no
network action. `--execute` is also blocked: saved preflight JSON is evidence,
not authority. Future activation must be spawned by the selected live parent
while consuming both a one-shot `BatchPrivacyPassAuthority` and a one-shot
`PreNetworkSafetyAuthority`. The parent-owned namespace/argv must be built in
memory; no saved plan may replay it. The current assembler therefore cannot
mine, query RPC, fund or broadcast through the new profile.

The first full Testnet path is the rehearsal. After activation, real R1/R2, the
current-head double-spend refusal, ordered service loss, nine accepted payouts,
zero-reserve Original scans and terminal Exit-privacy capture must complete.
Only then may `complete_rehearsal_manifest.py`, `rehearsal_gate.py` and
`complete_testnet_trial_gate.py` rejoin and reexecute the full retained evidence.
The command does not silently run those stages through the unfunded wallet-
history facade.

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
