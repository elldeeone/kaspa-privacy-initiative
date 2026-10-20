# Early privacy test: actual public data and amount inference

Date: 2026-10-20. Current protocol/wallet candidate: `bf4505c`.
The work-order change was committed and pushed as `6dff59d`.

**Status:** public-surface review and the declared amount-inference calibration
are complete. Later withdrawals narrow one ordinary payment's possible amount.
Neither ordinary payment is uniquely determined by these models. The broader
early privacy gate remains open. No privacy qualification, funds, broadcast,
setup or new cryptographic proof is claimed.

The [specification](EARLY-PRIVACY-SPEC.md) was fixed before new inference:
SHA-256 `1b21810517d21d1221364e4c63f258710022100c8942dcc795c200266142e96e`.
It uses the existing genuine M2 proof/native history with synthetic ancestry.
The published experiment has only three generated wallets and known outcomes;
it is calibration material, not a fresh blinded privacy evaluation.

## Findings before execution

The older [wallet-policy observer](wallet_policy_observer.py) constrains DRAIN
to one real input. The [current wallet](src/two_input/wallet.rs) permits one or
two. Reusing the old restriction could create false unique value/source
deductions. Historical tests retain their original workload/policy scope;
their results are not rewritten. The new method starts from the H14 relation
and applies only the current wallet's documented shape.

The older [native projector](two_input_privacy_native.py) assumes distinct
commitments and assigns synthetic times. The new projection must preserve
positions even for equal commitments, constrain their values equal under the
binding assumption, and supply no timing observation that the source lacks.
Funding-parent equality is not proof of common ownership.

The 4,368-byte settlement witness is computed from public state and public
authorization in [PublicState::witness](src/two_input/tree.rs). Its history,
nullifier-insertion and append indices are not private consumed-note positions.
This source-derived property does not establish proof-system privacy.

Funding and exits use the same native key derivation namespace. A chosen funding
index equal to a later exit's minimum note position can reuse a native script.
This is a source-derived allowed-use boundary-link risk, not an executed exploit
or automatically a disclosure of an undisclosed internal payment. The existing
M2 trace does not exhibit that collision. Changing the key scheme is not part of
this test.

The [primary-source review](../../research/shielded-kas-privacy-surface-sources-2026-10-20.md)
records why fixed change order, public native values, counterparty knowledge,
timing and anchor age must remain observer inputs. No cryptographic assurance is
borrowed from those other protocols.

## Execution and controls

Each attempt freezes the specification, four public input files, four observer
source files, native replay binary hash and installed dependency hashes before
inference. Attempt `20261020-method-04` completes the declared method. The
[public evidence](evidence/2026-10-20-early-privacy/README.md) also preserves three
interrupted search attempts. Native replay validates seven transactions including
founding, with six genuine pool proofs; chain acceptance remains unverified.
The observer projection retains the full public bytes and reconstructs its
arithmetic fields from them.

All 20 controls passed: five native rejection cases, six projection/schema
checks and nine arithmetic controls. The arithmetic controls compare 454 tiny
feasible-value cases against both solver encodings and an independently written
exhaustive ledger enumerator. CP-SAT and Z3 share framing and preliminary bound
code, so agreement between those two alone would not validate that shared code.
The native mutations test their recorded rejection stages: authorization and
ciphertext changes fail transaction-ID consistency; the proof mutation reaches
native ZK deserialization. These are not newly generated adversarial proofs.

The process runs with the public input and frozen code mounted read-only,
without home directories, private wallet records or an external network
interface. The OS/runtime and author-written analysis remain trusted. This is
author-side testing with a second-pass review, not an independent audit.

The public equality checks found no repeated nonzero commitments, nullifiers,
ciphertexts, ephemeral encryption prefixes or proofs, and no reused funding/
payout scripts in this history. Mode-specific zero slots are recorded separately.
Absence of those repetitions rules out only those exact matching attacks here;
it does not establish identity or amount privacy.

## Amount result

Both profiles complete all 24 position/horizon rows: **48 exact bound checks**
in total, using 146 CP-SAT and 242 Z3 queries including feasibility and zero
checks. Every endpoint has a feasible model; every reported extremum has the
declared exact optimality/outside-bound checks. Solver witnesses are alternative
satisfying assignments, not recovered private note openings or actual inputs.

For the two ordinary SPEND output-0 positions, the current-wallet-shape profile
gives these extrema in tKAS (the artifact stores integer sompi):

| Payment output | At creation | After first withdrawal | At complete drainage |
| --- | ---: | ---: | ---: |
| Position 5, event 2 | 0.6–30.8 | 0.6–30.8 | 0.6–30.8 |
| Position 7, event 3 | 0.6–30.4 | 0.6–20.4 | 0.6–20.4 |

The relation-only profile permits zero for those outputs and has the same upper
bounds. No created value is forced in that broader profile. The wallet-shape
profile forces the ADMIT credit at position 3 to **11.6 tKAS** and its padding at
position 4 to **zero**, at all three horizons. Those six forced rows are two
positions, not six private-payment disclosures. The credit follows directly from
the public 12-tKAS deposit, 0.4-tKAS fee and this wallet's admission convention.

The shrinking upper bound is actual later-disclosure leakage in this history.
The wide remaining extrema do not establish useful privacy: they are neither
continuous feasible intervals nor probabilities. Common input ownership,
counterparty knowledge and active attacks are absent. The models use the actual
0.6-tKAS note floor; they do not condition on the RFC's supported payment-size
workload. A stronger, correctly informed observer could narrow values further.
No amount-guessing or identity score is measured here.

The first three attempts were interrupted only after method-04 completed.
Method-02 added query logging to locate a CP-SAT maximum search that remained
unresolved with one worker. Method-03 tried a nonbinding objective hint and
remained unresolved at another query. Method-04 removes that hint and uses eight
CP-SAT search workers. Inputs, constraints, integer domains, horizons, metrics and
the frozen specification are identical; only diagnostics/search strategy change.
All attempts passed the controls. Interrupted attempts remain incomplete, with
no privacy verdict. Parallel search can change witnesses and runtime, not the
required exact bounds and certificates. No whole-KAS rounding or restricted
amount grid was introduced.

## What remains after this slice

Even successful calibration cannot pass RFC-0012's 32-role/eight-adversary gate.
The next evaluation still needs stable owner identities, explicit pooled
participant and active-adversary inputs, fresh held-out workloads, frozen strong
baselines and statistical procedures. Full native bytes remain available to
attacks; a restricted arithmetic model does not exhaust them. Infrastructure,
network, cryptographic assurance and known fee/latency gaps remain separate.
Next freeze and execute that held-out evaluation before dedicated milestone 3
work. Keep the source-derived address-reuse path as a separate untested case;
this calibration is neither a supported-use-case failure nor a privacy pass.
