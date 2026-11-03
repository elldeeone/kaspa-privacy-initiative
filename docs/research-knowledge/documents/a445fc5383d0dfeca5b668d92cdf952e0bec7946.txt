# Next owner-private construction gate

2026-10-24 UTC. **Decision question, not an accepted relation or execution
authorization.** The sealed ADR0061 packet and sum-api09 packet are unchanged.

The [actual MASCOT gate](sum-api/RESULTS.md) closed the exact-Jubjub-field
secret-input/addition/checked-opening API uncertainty. Four fixed sums and the
actual aggregate-to-Binding consumer passed; wrong-prime and participant-loss
controls produced no accepted sum. It did not build an owner-private payment
protocol, prove note validity, or authorize KAS. Public synthetic inputs did
not test transcript secrecy, adaptive corruption or retry unlinkability.

## The concrete blocker

The installed KAS relation couples an action's two input witnesses to that
action's complete output list. Current owner workers submit those groups; the
relation itself permits independently authorized input owners. It hashes the
output list into Auth528 and proves conservation for that action
([circuit.rs:435–488](../../../../poc/four-wallet-profile/prover/src/circuit.rs)).
Auth also carries the original NFs and ciphertext digest; the outer consumer
verifies and retains those grouped child records
([Authorization](../../../../poc/four-wallet-profile/prover/src/lib.rs),
[outer consumer](../../../../poc/four-wallet-profile/proof/common/src/lib.rs)).
Shuffling these records retains the groups. Removing them only from L1 retains
the assembler's original submission map. The current SHA-committed Note has no
homomorphic value commitment or blinding field. Adding a mixer and sum therefore
requires a new financial statement, not a transport-only adapter.

**Recommendation:** review a relation-split ADR before further implementation.
An ordinary Sapling integration would remain comparison evidence; it would not
replace the installed BN254/native predicate. Select the actual curve, existing
commitment implementation, proof/native compatibility and parameter provenance
explicitly. No new cryptographic primitive or setup is selected here.

## What that decision must specify

1. **Independent financial components.** A spend proof binds an authorized,
   range-bounded note under an accepted membership root to its original
   positioned NF and a value commitment to that same value. An output proof
   binds a range-bounded value commitment to the exact note CM and delivery
   ciphertext. Neither proof's public statement identifies an owner's output
   subset. Reusing existing SHA notes, introducing a new note version, and
   retaining backup scanning/unilateral exits need explicit compatibility rules.
2. **One global balance.** For the selected established generators and scalar
   field, verify `sum(CV_in)-sum(CV_out)-public_native_debit*V = Delta*R`.
   Define fee/payout signs exactly, canonical point/scalar decoding, subgroup
   checks, count/range limits preventing modular inflation, and exact-once
   component/NF checks. Only global Delta is released. Individual beta or
   beta*R recreates the demonstrated output-subset certificate. The checked
   MPC sum does not prove that a malicious party supplied its correct beta.
3. **Exact effects and authority.** Every spender independently checks the same
   canonical roster/session, domain/network/version, accepted predecessor and
   state, complete NF/CM/CV/ciphertext sets, reserve changes, native destinations,
   integer-sompi payouts/fee and validity limits before authorizing them. Select
   an existing authorization mechanism that binds those effects without a
   proof/signature self-reference cycle. Output proofs must remain compatible
   with generation before the final mixed set exists. A public Delta lets
   anyone form a Binding signature; that signature cannot serve as spend
   authorization. CSPP's generic confirmation signs only RevealSecrets.
4. **One construction attempt.** Bind the anonymous complete tuples and the
   MPC contribution/result to that same fixed context. Define how each honest
   owner derives beta from its local selected components and checks its own
   output inclusion plus every public proof/global balance before signing.
   MASCOT is a different engine from ValueShuffle's SumDC: its checked scalar
   output alone does not implement the paper's joint transcript commitment or
   transfer the paper's composition argument.
5. **Irreversible disclosure and retry rules.** A whole attempt may abort; no
   surviving-subset sum, individual-beta recovery or automatic roster reduction
   is required. Before releasing any financial authorization, permanently close
   that attempt's secret-reveal path, including reconnect/error/retry paths.
   Retry with fresh attempt/session/mix/MPC ephemeral keys, output-note
   randomness, complete tuples and private contributions. Preserve the original
   backup, accepted input-note openings and authority, and financial setup.
   Retain any earlier publishable signed body in the
   adversary's state: timeout cannot revoke a valid authorized body, which may
   still settle. Reconcile current accepted state/NFs before retry or
   independent exit; unknown settlement remains INCOMPLETE. Only an accepted
   output becomes a claim, and current NF checks must prevent both competing
   bodies from settling.

## Smallest decisive implementation after that review

Construct **one unfunded, genuine financial body with three separate owner
workers and two outputs each**, using the selected spend/output proofs, actual
complete-tuple mixing, existing checked private sum, and exact-effect
authorization. The assembler receives public components and protocol messages,
never foreign openings, owner-output upload maps, individual beta points or
owner-local logs. The observer retains the full assembler transcript, timing,
counts and one colluder's permitted secrets; at least two eligible honest
owners are an explicit assumption. This is a functional construction gate,
not an anonymity score from public fixtures.

Pass requires all six tuples recovered exactly once, all genuine component
proofs and global conservation verified, every owner's required outputs
included, the same complete effects authorized by all spenders, and acceptance
by the actual selected unfunded native financial predicate. Measure its actual
proof time, body size and fee; the previous W measurements do not transfer.

Freeze a finite negative matrix before execution: wrong note/CV/range proof;
wrong Delta; omitted/duplicate/substituted tuple or ciphertext; duplicate/replayed
original NF; stale root/predecessor; changed domain, reserve, payout, fee or
roster; equivocated effects; loss before/after sum; post-authorization secret
request; and confirmation timeout followed by next-run blame. No altered body
may acquire usable honest authorization. No failure path may disclose a
previously undisclosed honest owner's already authorized tuple map or reuse
those tuples/private sum inputs under a changed roster. Incomplete or invalid
construction must not create new usable authorization or authorize a reserve
release. An already authorized valid body remains allowed to settle exactly
once under current NF/native checks, even after local timeout or loss. Losing
or misclassifying that accepted settlement fails recovery. Retain that old body
when evaluating late disclosure; there is no rollback promise for signatures
already exported.

Stop if this requires an unselected relation, unsupported native verifier,
foreign-witness collection, a weakened financial check or invented primitive.
Failure to finish for a resource limit is INCOMPLETE. Do not add more standalone
sum/mix benchmarks or count a mock proof/body as completion. Strong privacy
qualification comes later with realizable owner worlds and the original frozen
observer, priors, singleton failures and thresholds unchanged. Long-term
independent recovery storage remains a separate requirement.

## Established source boundary

[ValueShuffle's official paper](https://fc17.ifca.ai/bitcoin/papers/bitcoin17-final6.pdf),
579,603 bytes, SHA256
`5b5217e0641211e53434d6372ac516ba9f7e43ea80a527d97ae55a130b3cde6f`:
pp.10–12 describe complete output triples, secure sum, global checks and final
transaction signatures; pseudocode lines20–25 and42–52 jointly commit/open
the mix and sum before confirmation; lines167–175 sign the full transaction;
the unlinkability argument requires a revealed tuple never be signed and
fresh complete tuples on retry. It assumes CT inputs and a bulletin board;
it does not supply hidden-membership native KAS proofs or this MASCOT
composition. See the pinned [design](DESIGN.md), [review](REVIEW.md),
[component source decision](sum-review/DECISION.md) and
[RFC0026](../../../../docs/rfc/0026-owner-private-multiparty-construction.md).
The conservative whole-attempt-abort candidate claims neither identifiable
blame nor robust termination, fairness or adaptive-corruption security.
