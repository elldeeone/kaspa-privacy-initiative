# Boundary correctness plan: v6 constraints and S7 composition

Status: frozen expectations before execution. No new setup, proof generation,
PK restore, owner CLI, ledger replay or withdrawal workflow is included.

## Discriminator and code seams

The first useful gap is coverage, not a confirmed acceptance bug. The existing
`amount-overflow` control in `poc/shared-pool/src/two_input/harness.rs` changes
an input value to `u64::MAX` without rebuilding its commitment, membership root
or nullifier. Rejection can therefore occur before the amount constraint. New
amount controls must rebuild every affected hash/path so that the integer
relation is the intended failing condition.

The unchanged v6 circuit has 4,372,824 constraints per fixed-shape SPEND case.
Relevant seams in `poc/shared-pool/src/two_input/circuit.rs` are `bounds`
(62–72), canonical inactive inputs (132–165), 16-bit positions/count slack
(144–151), real/dummy NF binding (180–218), output bounds/liveness (223–249)
and aggregate value conservation (255–270). `MAX_SOMPI` is
2,900,000,000,000,000,000; arithmetic expectations use independent `u128` sums.

A separate composition boundary is intentional: the private circuit proves
position membership and `position < declared count`, while native/S7 context
authenticates the historical count/root. It does not itself cap the declared
count to the native odd-count state format. Relation-only acceptance at count
65,536 or `u32::MAX` must not be called native acceptance or a binding bypass.

Use a new `poc/shared-pool/src/bin/kpi_v6_boundary_check.rs` test-only executable,
with fixed public deterministic note/secret labels and no input file API. It
will synthesize/check constraints only. It will not call wallet, setup, prove,
funding, broadcast or replay entry points. Shared circuit/policy code and frozen
fixtures remain unchanged.

## Frozen full-circuit cases

Each amount case rebuilds the input tree, owner commitments, nullifiers and
output commitments from its declared values. All SPEND authorizations have
zero native payout/deposit/funding/bootstrap fields; ciphertext hashes are
explicit declarations for this constraint-only test, not delivery evidence.

| ID | Expected | Discriminating change |
| --- | --- | --- |
| baseline-two-real | satisfied | Two real inputs at positions 1 and 3, count 5 |
| aggregate-max | satisfied | Two bounded real notes sum exactly to MAX |
| aggregate-max-plus-one | unsatisfied | Each note/output individually bounded; input total MAX+1 |
| input-floor | satisfied | Each real input at NOTE_FLOOR; one positive output |
| input-floor-minus-one | unsatisfied | One real input NOTE_FLOOR−1; otherwise balanced valid notes |
| output-floor | satisfied | One output exactly NOTE_FLOOR |
| output-floor-minus-one | unsatisfied | Transfer one sompi to the other output, preserving conservation |
| zero-output-padding | satisfied | One zero output and one bounded positive output |
| one-sompi-output | unsatisfied | One positive output is 1; other output rebalanced |
| both-zero-outputs | unsatisfied | Fee equals bounded input total; conservation holds but no value recipient |
| fee-one | satisfied | Fee 1 with all remaining value in one bounded output |
| fee-zero | unsatisfied | Fee 0; outputs otherwise balanced and valid |
| inflation-one | unsatisfied | Output sum exceeds input sum by 1; output CMs rebuilt |
| deflation-one | unsatisfied | Output sum falls short by 1; fee unchanged |
| last-16-bit-position | satisfied | Real position 65,535, declared count 65,536; relation only |
| position-16-bit-alias | unsatisfied | Position 65,536 with matching low-16-bit path and full-position NF |
| count-underflow | unsatisfied | Declared count does not exceed real input position |
| count-u32-max | satisfied | Valid membership, count `u32::MAX`; relation only |
| real-input-swap | satisfied | Swap both real witnesses and their corresponding public NFs |
| inactive-real-dummy-keys | satisfied | Change dummy keys/seeds of real inputs; active statement unchanged |
| baseline-one-real | satisfied | One real input plus canonical padding slot |
| padding-secret | unsatisfied | Nonzero inactive secret, all other padding fields canonical |
| padding-owner | unsatisfied | Nonzero inactive owner |
| padding-incoming | unsatisfied | Nonzero inactive incoming key |
| padding-rho | unsatisfied | Nonzero inactive rho |
| padding-position | unsatisfied | Nonzero inactive position |
| padding-path | unsatisfied | Nonzero inactive sibling |
| unsupported-mode | unsatisfied | Mode 3, no alternate mode or owner workflow |

Witness shape errors (15/17 path elements) are separate synthesis-error controls;
they must not be counted as complete 4.37M-constraint executions. Case names,
expectations and source hashes are frozen before running; retain every mismatch.

## Follow-on S7 metamorphic controls

After the full-circuit lane, add tests only to the existing fresh S7 test module
or a standalone test package, with no policy edits. Reuse only the published
genuine pair input and public bytes. Never edit a frozen fixture.

1. Swap the two genuine bundles and rebuild binding index maps. The complete
   public projection and state journal must remain byte-identical. Reusing the
   same bundle twice must reject duplicated NFs. These use existing public
   proofs, not a synthetic proof callback.
2. Construct declared, full-tree-consistent public predecessor contexts at
   counts 5, 7 and 65,531, retaining the genuine count-5 historical anchor.
   Derive roots independently and preserve raw-lex public NF order versus
   numeric-LE indexed-set order. Compare exact next state/J336. These are local
   transition assertions, not accepted genesis/history/backing claims.
3. Replace insertion 2's predecessor/append witness with one authenticated
   against the original pre-insertion root. Require the precise root/occupied
   rejection, rather than relying only on arbitrary bit flips. Check both
   history appends against their sequential roots and count n+2/n+4 tags.
4. Exhaust legal odd CM count and even NF count boundary arithmetic with an
   independent wider-integer oracle; test n=65,531 accepts four appends while
   65,533/65,535 reject, and retain existing initialized/sentinel conventions.

Earlier 14-group state tests and the 163-case independent corpus already cover
many malformed paths, prior roots, comparator cases and capacity examples.
Do not rerun or duplicate that corpus merely to inflate counts. Fresh-instance
tests above target genuine-proof metamorphisms and self-consistent wrong-root
controls. Existing equality/replay controls remain intact.

## Execution and stop rules

Root permits bounded CPU work after merge completion. Use the warm Rust 1.95
toolchain and exact `/src`/`/cargo` mount convention, a private target/cache, and
no simultaneous writes to old targets. Announce target/command before building.
Start with one baseline full-constraint child, record wall/CPU/max-RSS, then run
the frozen cases serially in fresh child processes under an owned cgroup capped
at 8 CPU, 10 GiB RAM, zero swap. Per-case `/usr/bin/time -v` distinguishes actual
constraint cost from compilation and setup. No trusted-setup timing is included
in any wallet/proof-cost claim.

Save source/plan/case hashes before execution, each child's expected/actual
satisfaction, constraint count, diagnostic, exit status and resource record.
Report a mismatch immediately; do not tune an expectation or omit a failure.
An infrastructure abort remains incomplete evidence. Passing establishes only
the checked implementation behavior, not cryptographic correctness or safety.
