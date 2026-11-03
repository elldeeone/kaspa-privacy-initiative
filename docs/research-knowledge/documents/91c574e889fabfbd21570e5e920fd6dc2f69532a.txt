# Two-input payments and saved-proof exits — offline result

**Result: the bounded H13 payment/exit test passed offline.** Two receipts funded
a payment and private change; a partial withdrawal left change that was spent
again; all four synthetic wallets received payouts through six unchanged saved
proofs. Native backing reconciled and the reserve drained to zero.

This is genuine Groth16 proving and execution of the pinned Kaspa native
validator against **synthetic UTXOs**. No TN10 transaction was broadcast and no
tKAS was spent. It is not a privacy measurement, independent audit or guarantee
of recovery from a live chain. Stage 2 remains open for general payment privacy.

Date: 2026-10-19 UTC. Branch: `shared-pool-four-wallet`. The specification was
committed first as `c50855a`; the owner then authorized implementation and an
offline test. [RFC-0011](../../docs/rfc/0011-two-input-private-payments.md) and
[ADR-0024](../../docs/adr/0024-two-input-private-payment-scope.md) record the
design and its limits. Earlier variants and evidence remain unchanged.

## What was built

`kpi-two-input` is a separate immutable v6 candidate in [src/two_input](src/two_input).
It uses the existing note/encryption format, historical private membership and
current native settlement checks, with a new two-input circuit and setup. It
does not port old proofs or migrate old pools.

- `ADMIT` binds an ordinary signed native funding input and credits its value
  less the exact fee into two private output slots.
- `SPEND` consumes one or two real notes, with constrained zero padding, and
  creates two output slots. It may also make an authorized public withdrawal.
- `DRAIN` consumes one or two real notes without appending commitments. The
  tested fallback uses one note, pays its exact fee, and leaves no private
  change. Native reserve exhaustion, not note counts, determines termination.

Two sequential current nullifier insertions apply to each spend. Padding NFs
must satisfy the domain-separated HMAC derivation in the proof; they cannot be
arbitrary public values selected to invalidate another user's note. Both
private inputs require ownership, historical membership, distinct positions
and correctly derived real NFs. Amounts and aggregate input sums are bounded
integer sompi. All private outputs are zero or at least 60,000,000 sompi.

The normal envelope has a 377-byte authorization, 128-byte compressed proof,
two 185-byte ciphertexts, 105-byte state and 5,228-byte payload. The redeem
script is padded to 24,576 bytes. Commitment/history trees have depth 16; the
indexed NF tree has depth 17. No new native opcode, mandatory service, token
or privileged exit path was added.

## Workload and observations

Every amount below is synthetic tKAS; the code and evidence use integer sompi.
Alice starts with 20. Bob, Carol and Dave supply separately signed synthetic
funding inputs of 11, 12 and 13. Their independent keys do not establish real
funding provenance or four independent people.

1. Alice's bootstrap creates notes of 9 and 10.6. She saves a private fallback
   for each. Later admissions create one positive note and one zero slot each;
   Bob saves his proof before Carol's and Dave's admissions.
2. Alice combines both receipts, pays Bob **7.31**, and keeps **11.89** private
   change. Both recipients decrypt their outputs. Alice saves a fallback for
   her change, which is later used successfully.
3. Bob withdraws **2.11** publicly and retains **4.8** private change. He decrypts
   and re-spends that change, paying Carol **1.7** and retaining **2.7**.
4. Six isolated exit workers settle all remaining positive notes using their
   saved proof and authorization bytes unchanged. All four wallets receive
   their assigned native payouts; reserve value ends at zero.

The exact fee is 0.4 per transaction throughout this fixture. The public
accounting is `56 = 50.8 payouts + 5.2 fees + 0 reserve`, checked after every
accepted transition. The 13-transaction trace contains one bootstrap, three
admissions, two payments, one partial withdrawal and six saved exits.

| Wallet | Final saved-exit payouts | Earlier partial payout | Total payout |
| --- | ---: | ---: | ---: |
| Alice | 11.49 | 0 | 11.49 |
| Bob | 12.50 | 2.11 | 14.61 |
| Carol | 12.50 | 0 | 12.50 |
| Dave | 12.20 | 0 | 12.20 |

Exit workers run under `bwrap --unshare-all` with an empty environment, a
separate PID/mount/network namespace, the executable, system libraries and one
request file. No wallet keys, proving key, home directory or external network
are mounted. The request contains the saved proof, authorization, VK, and
current public state/UTXO. Each worker builds and natively validates its exit;
the parent verifies unchanged proof/authorization bytes and validates settlement.

This establishes **no private re-proving or privileged secret in the exit
worker**. The parent controller generated the wallets and supplies public
state. It does not establish independent chain discovery, authenticated genesis
recovery, pruning tolerance, or successful broadcast without the controller.
Those obligations are not closed by the word “independent” in this result.

## Controls and remaining qualification gaps

- All 13 positive transactions pass full native validation, script metering and
  the local policy screen against the pinned SDK. Fifteen genuine proofs were
  generated, including unused alternative fallbacks.
- 279 native reserve-script mutations are rejected across bootstrap, admission,
  partial withdrawal and every exit: altered proof/domain, anchor, both NFs,
  commitments, fee/payout/destination, funding binding, ciphertexts, state roots,
  sequential NF witnesses, append witnesses, backing or output shape. These
  controls execute input 0 directly, so a broken depositor signature cannot
  stand in for a missing reserve check.
- Twenty-one supplementary admission controls exercise the ordinary funding signature,
  `SIGHASH_ALL`, actual outpoint/value/script, missing funding and reordered
  native inputs. See [audit evidence](evidence/2026-10-19-two-input-offline/audit.json).
- The circuit has 15 evaluated constraint fixtures: four positive and eleven
  negative. They cover two real inputs, duplicate input, the second owner's
  secret/path/NF, chosen dummy NF, nonzero dummy value, inflation, minimum and
  below-minimum change, zero outputs, wrong domain/position and overflow.
  These are constraint satisfaction checks, not negative proof generation.
- Normal-first rejects both of Alice's old per-note fallbacks in the public
  builder. A fork validates her first fallback, then rejects the normal
  two-input payment. Native rebased stale/replay controls also reject the losing
  authorization in both winner orders. The native replay control uses Alice's
  first input; it is not a separate race test for every possible input ordering.
- Five unit tests cover the exact layouts, depth-16/17 path positions, parity
  and capacity arithmetic, sequential insertion/replay, and incremental tree
  reconstruction against full recomputation.

The capacity fixture extends public data to 65,535 commitments and 131,068
inserted NFs. It uses an existing genuine saved proof for a terminal native
exit, inserts its two NFs, appends no commitments/history and refuses a further
commitment append. **This is a constructed state, not a replay of a valid
65,000-operation funded history.** It tests boundary execution; the capacity
induction still requires review. Normal payments stop at commitment capacity.

The first supplementary missing-funding control stopped at the harness balance
check. Its corrected fixture subtracts the omitted funding value from the
successor so the intended covenant input-count check is reached. No covenant or
proof check was relaxed. The original complete proof run was unaffected.

Broader qualification remains open: negative malformed-delivery cases in this
new adapter, private-input permutations, genuine-proof minimum-value native
exits, adversarial schedules at capacity, history recovery/reorgs, sustained
contention, real relay acceptance and independent cryptographic review. The
successful trace does not exhaust the RFC's larger qualification checklist.

## Measured cost and fee envelope

The immutable circuit floor is **0.6 tKAS**; the payout floor is **0.1 tKAS**.
The selected fixture fee is **0.4 tKAS**, authorizing exactly that fee per proof.
At that fee the minimum positive note leaves **0.2 tKAS** on a one-note exit.
The circuit permits other explicitly authorized fees within its range checks;
0.4 is the tested policy, not a perpetual network fee or mandatory fixed tariff.

| Native shape | Mining mass in the main trace | Fee floor at 100 sompi/mass | Chosen fee |
| --- | ---: | ---: | ---: |
| Bootstrap / internal payment | 330,508 | 33,050,800 sompi | 40,000,000 sompi |
| Admission | 331,628 | 33,162,800 sompi | 40,000,000 sompi |
| Partial / continuing exit | 330,920 | 33,092,000 sompi | 40,000,000 sompi |
| Terminal exit | 330,497 | 33,049,700 sompi | 40,000,000 sompi |

Native estimated size is 30,137–30,258 bytes. The reserve input declares
30,000,000 script units; measured full-transaction usage ranges from 14,847,195
to 15,029,210. Admission has a separate ordinary signature budget. This is a
deliberately generous, **unoptimized budget**. Mass and fees charge declared
budget; unused capacity is not a refund. Lowering it requires another bounded
qualification and is not silently reflected in these estimates.

The supplementary 36-case amount sweep checks local mass/policy for continuing
and terminal exit layouts, including payout floors, a minimum remaining reserve
  and large amounts. Its changed-amount transactions **do not carry valid proofs**;
it is mass-only evidence. In a correctly backed state, a positive remaining
reserve is at least the note floor. With native output plurality one and the
pinned storage parameter `10^12`, storage mass is bounded above by
`floor(10^12 / 60,000,000) + floor(10^12 / 10,000,000) = 116,666` for a continuing
exit, or 100,000 for a terminal payout. Input subtraction can only lower it.
Both bounds are below the measured compute mass. This explains the bounded
fee envelope; it is not a claim about future fee markets or a malformed pool.

Proof work used CPU with `RAYON_NUM_THREADS=4`, Rust 1.95.0 and a fresh
single-party BN254 setup:

| Measurement | Observed |
| --- | ---: |
| Circuit constraints | 4,372,824 |
| Compressed proving key | 962,197,520 bytes |
| Setup generation | 42.431 seconds, excluding prior constraint check |
| Cold parameter load/validation | 214.688 seconds |
| Warm proofs (15) | 20.131–22.286 seconds each |
| Complete main fixture including load | 534.974 seconds |

Constraint controls also ran on this host during the main run; these timings
are workload observations, not an isolated benchmark. Peak RAM was not measured.
Fees total **5.2 synthetic tKAS**, with **zero actual funds spent**. No privacy
benefit is inferred from paying this cost.

## Adversarial second pass and decision

The implementing agent reviewed the circuit, native script, public trees and
exit isolation after the successful run. This is author review, not independent
assurance.

| Risk | Check and limit |
| --- | --- |
| Inflation / incorrect backing | Range-constrained sums, zero dummy values, actual funding binding, exact native debit, singleton bootstrap and per-step reconciliation. Soundness still depends on the circuit and trusted setup. |
| Double spend / replay | Positioned real NFs are invariant across anchors/modes/slots; both are inserted into the current indexed set sequentially. Same-note alternative proofs conflict. Broader interleavings and reorgs remain open. |
| Unauthorized reserve release | Proof binds payout, destination and fee; native script binds successor code/state and actual amounts. No operator authorization path. |
| Padding / capacity denial | HMAC-constrained dummy NFs; depth-17 NF headroom; no-append exits. The cryptographic composition and capacity induction need independent review. |
| Sender/receiver/amount leakage | Notes/change are not plaintext public fields, but entry/exit amounts, anchors, timing and native ancestry remain observable. Ciphertext digest binds bytes, not correct encryption; receivers must decrypt and check commitments/ownership. |
| Disappearing dependencies | Saved exits use no private prover material. Lost accepted history, invalid public data, inadequate fee, or unavailable chain access can still block settlement; this harness supplies the current view. |
| Hidden trust | New experimental single-party setup, exact verifier identity, honest native chain context and retained public data. No security invariant is weakened. |

**Decision:** keep this relation as the next research candidate. It removes the
compact variant's split-only and full-withdrawal-only restrictions using the
current pinned L1 primitives. The resulting cost/startup burden remains material.
Do not choose a production architecture or declare strong privacy from this run.
Before a privacy comparison, replace the old one-parent observer with a model
that permits merged inputs, padding and private change; freeze meaningful
workloads and thresholds. No further run is authorized by this report.

## Reproduction and evidence

Dependencies are pinned in [Cargo.toml](Cargo.toml) / [Cargo.lock](Cargo.lock).
Native SDK: `01b532e8b553523216471682649693af92f0fd16`. The
[source review](../../docs/rfc/0011-two-input-private-payments.md#source-grounding-and-reuse)
records existing Kaspa, Orchard, Aztec, RAILGUN, Monero and MWEB work reused or
rejected. Native mass comes from the pinned SDK's `consensus/core/src/mass`;
no estimates are substituted for executed main-trace validation.

From `poc/shared-pool`, using a fresh path outside the repository:

```sh
cargo +1.95.0 build --release --bin kpi-two-input
cargo +1.95.0 test --release two_input::tests --lib
export RAYON_NUM_THREADS=4
export KPI_H13_PRIVATE=/absolute/private/h13-new-run
mkdir -m 700 "$KPI_H13_PRIVATE"
target/release/kpi-two-input setup "$KPI_H13_PRIVATE/params"
target/release/kpi-two-input controls > "$KPI_H13_PRIVATE/controls.jsonl"
target/release/kpi-two-input demo "$KPI_H13_PRIVATE/params" "$KPI_H13_PRIVATE/run"
target/release/kpi-two-input audit "$KPI_H13_PRIVATE/run/result-private.json" "$KPI_H13_PRIVATE/audit.json"
target/release/kpi-two-input boundary "$KPI_H13_PRIVATE/run/exit-7.json" "$KPI_H13_PRIVATE/boundary.json"
```

The runner requires Linux `bwrap` with working unprivileged namespaces. The
recorded run reused an existing `CARGO_TARGET_DIR`; substitute its executable
path when doing the same. Setup/run directories must be fresh. The binary has
no RPC/broadcast command. Treat raw reports and saved request files as private:
they contain fallback bundles and wallet-linked experiment material.

[Sanitized evidence](evidence/2026-10-19-two-input-offline/summary.json) retains
aggregates, per-operation costs, control results and source/binary hashes.
Unused fallbacks, raw transaction/proof/authorization bytes, keys, note openings
and proving parameters are excluded. Raw artifacts stay outside Git. This makes
the report inspectable and the generator reproducible; the sanitized bundle
alone is not a standalone cryptographic verification package.
