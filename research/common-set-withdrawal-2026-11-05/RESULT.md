# Common-set withdrawals: bounded ownership-channel result

**Date:** 5 November 2026 (Australia/Sydney).
**Result:** a replacement can remove the explicit input-owner-to-payout
assignment in this finite offline test using current L1 interfaces. Native
scripts verified genuine whole-set authorizations and independently executable
solo exits. The declared application/native observer retained six complete
ownership assignments, or two with one participant's own payout disclosed.

This is **not** complete financial-privacy qualification or proof of cryptographic
anonymity. It uses three synthetic equal-value public claims, a supplied reserve
and assumed cryptographic properties. Actual network privacy, the real shielded
ledger, full native transaction/relay validation and accepted chain backing were
not tested. The identified-registration control is not a measured upstream
lifecycle benchmark or evidence of overall superiority to Olaf's design.

## What changed from the rejected wrapper

The [previous audit](../joint-withdrawal-feasibility-2026-11-05/RESULT.md) remains
valid: retaining individually public destination authorizations exposes all
five request-to-output links. This replacement creates a **different** relation:

1. Each claimant keeps its secret and chosen recipient key client-local. It
   obtains an RFC9474 blind registration signature after proving eligibility
   for a public claim. Identified issuance receives only blinded message and
   eligibility proof; the private blinding state/randomizer is not sent then.
2. After every issuance is complete, independent logical redemption messages
   supply signed output registrations without owner/session identifiers. The
   actual library blinds, signs, unblinds and verifies. Outputs are sorted
   independently of input owners. Logical separation is not measured IP privacy.
3. Every wallet checks its entire expected payout and approves the **same whole
   transaction**, using one common Groth16 relation. Public inputs contain its
   claim commitment, common-effects context and HMAC authorization tag. None
   selects that owner's output or names its recipient.
4. The native predicate reconstructs context from the actual current outpoint
   and all actual outputs. It enforces complete authorizations, input/output
   counts, principal, explicit fee allowances and exact successor policies.

Blind credentials are ephemeral coordination permissions, not an asset or native
spending authority. A malicious or absent issuer may abort cooperation; it cannot
spend or prevent the native solo branch. The registered public claim identifiers
are intentionally disclosed. This tests payout ownership even when input owners
are known; it introduces no new private-note/nullifier construction.

## Matched observation result

The [selection](SELECTION.md), [RFC-0005](../../docs/rfc/0005-common-set-withdrawals.md)
and [source review](SOURCES.md) preceded execution. One identified registration
API actually receives each owner's plaintext output request as a linkable
control. The candidate instead uses the exercised blind registration messages.
Both views include the same native full-set authorizations and real output keys.
The controller truth is not an input to either observer.

| Declared observation | Complete owner-to-real-output assignments |
| --- | ---: |
| Identified-registration control | 1 |
| Complete candidate application/native view | 6 |
| Candidate plus one participant's actual output | 2 |
| Candidate plus all-but-one participant outputs | 1 |
| Candidate plus externally known payout owners | 1 |
| Candidate with owner identifiers echoed at redemption | 1 |
| Candidate with client randomizers leaked at identified issuance | 1 |
| Candidate plus earlier individually public exit destinations | 1 |

All complete predictions retained the actual synthetic ownership map. These
are financial ownership assignments of distinct output keys, not permutations
of unnamed notes or proof slots. They are logical possibilities under RSA
blindness, Groth16 zero knowledge and the disclosed observation model, not
probabilities, independent people or a cryptanalytic privacy proof. In practice
timing, transport, wallet behavior or later ownership revelations may distinguish
them. The model rejects unreviewed public metadata instead of silently dropping it.

Eight observer runs use separate processes and one declared input file each.
The [prediction seal](run/PREDICTION-SEAL.json) is checked before the scorer reads
private synthetic controller truth. The deliberately public identified API
control also allows independent coupled-truth checks after prediction, using
only the committed public artifacts. An observer given both worlds' ownership
maps would obtain the known-owner result; the candidate observer is not given
the control's side information.

## Actual native and cryptographic execution

The final run generated **15 genuine Groth16 proofs**, including negative-context
authorizations, with one 237,779-constraint relation and six public field inputs.
Three real randomized SHA384/PSS blind credentials were finalized and verified.
The [execution report](run/execution.json) records 38 native VM cases: eight
positive executions and 30 intended rejections. A new process then reverified
the joint native predicate, all three eligibility proofs and all three final
credentials from public artifacts only; changed recipient/context/message
controls rejected. See [public replay](run/PUBLIC-REPLAY.json).

The current pinned Kaspa script engine accepted joint three-owner withdrawal,
each owner's standalone solo proposal, a full sequential solo drain and one
solo withdrawal followed by the remaining two owners jointly withdrawing.
Native checks rejected diversion, duplicated payouts/proofs, wrong claim or
context/outpoint/subset, reordered outputs, missing/corrupted authorization, malformed public fields,
incorrect amounts/successors and forbidden transaction metadata. A small local
UTXO map also submitted the actual conflicting joint/solo transactions in both
orders and rejected the spent predecessor and a repeated joint transaction.
Its successor sequence drained to
zero principal/backing. That model is not independent consensus or reorg evidence.

The initial reserve is 3,060,000,000 sompi: 3,000,000,000 principal plus explicit
60,000,000 fee allowance. Joint payout creates three 1,000,000,000-sompi outputs.
Solo exits preserve the remaining claims and their fee allowances in the exact
smaller-subset script. No server cooperation or forced retained principal is
needed to take a solo branch. General recovery after lost secrets/history is
not established.

## Current-L1 resource limit

The joint predicate used **47,267,756 script units**, with a 4,800-unit committed
compute budget. Its exact source-based quote is:

| Component | Quoted mass | Pinned block component limit |
| --- | ---: | ---: |
| Compute | 486,717 | 500,000 |
| Transient | 22,548 | 1,000,000 |
| Storage | 2,674 | 500,000 |

All seven finite subset scripts were constructed; the largest redeem script is
4,741 bytes and the joint signature script 5,333 bytes. Component-limit checks
are not full node/relay acceptance or paid fees. This layout is already close to
the block compute limit: four separate checks have a 630,000-compute-mass lower
bound from the pinned Groth16 base and six-input key pricing alone. It cannot
simply grow its cohort to four. No aggregation/runtime expansion was undertaken.

The 60,000,000-sompi withdrawal fee allowance is 2% of this instance's principal;
it excludes deposits, private payments and other lifecycle work and therefore
does not qualify the existing complete-cost target. No actual fee was paid.

## Verification, retained failures and remaining work

```bash
bash poc/common-set-withdrawal/check.sh
```

The check rebuilds the locked package, runs 11 observer controls, verifies all
public artifact hashes and frozen source identities, reproduces the eight
inference results, and invokes real public-only cryptographic/native replay.
The fresh execution took 14.09 seconds after building; this is one bounded
same-host run, not a wallet performance qualification. A prior successful run
before adding public-only replay also took about 14 seconds and had identical
ownership counts. Another successful run preceded the final additional replay
controls. All earlier local evidence and its earlier publication copy are retained
separately.

Earlier native-positive attempts failed at a sequence-field encoding guard:
`OpTxInputSeq` returns raw LE64 flags while the initial script compared minimal
integer zero. The exact eight-byte comparison fixed it; the zero-sequence
requirement remained. A failed build also exposed use of a stale executable;
the runner now builds successfully itself before freezing or starting a run.
Those unsuccessful runs and logs remain ignored locally, with no privacy
predictions promoted from them. Dependency failures were fixed by locking the
upstream-compatible RSA/PKCS1 prereleases, not modifying those libraries.

The [adversarial review](REVIEW.md) records the findings and their resolutions.
No invariant, existing wallet/runtime, consensus rule or historical evidence
changed. No secret, proving key, issuer private key or blinding factor is in the
22-file public run. No funds, broadcasts, node RPCs, paid providers, new asset,
paused MPC or mainnet action occurred.

The next unresolved product question is whether this narrow ownership benefit
survives integration with the actual shielded ledger and a concrete protected
network-registration path, within useful costs and cohort sizes. Known-owner
full drainage and the previous absolute qualification failures remain failures.

## Engineering decision

Keep this replacement as a candidate for one matched lifecycle comparison.
The result justifies further integration research, not replacing the current
architecture or claiming overall superiority to Olaf's direction. First map the
existing ledger's real spending/nullifier relation onto complete-set authorization
and price that exact path under current rules. The measured three-owner limit
belongs to this one-proof-per-owner layout, not every possible common-set design;
do not seek a consensus change or extrapolate its cost to an unbuilt layout.

If that integration fits, compare the current path and replacement on identical
deposit/payment/exit histories and observation checkpoints, including actual
registration-service data, honest/colluding participants, sole exits and complete
drainage. A concrete network-registration design must expose its origin/timing
assumptions before any network privacy claim. Preserve a negative result if
ownership leakage or useful-cohort costs defeat the benefit.
