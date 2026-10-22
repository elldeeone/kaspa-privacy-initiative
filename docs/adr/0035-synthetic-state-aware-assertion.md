# ADR-0035: Test a synthetic state-aware assertion without funding

**Status:** Accepted — bounded local assertion experiment; NONFUNDABLE.

**Date:** 2026-10-23 Australia/Sydney.

The [reviewed RFC-0018](../rfc/0018-paired-native-settlement-experiment.md)
identifies the missing state assertion in
[ADR-0034](0034-public-proof-composition-experiment.md)'s successful binding
experiment. Its immutable J42 receipt checks a common hidden count/anchor but
cannot authenticate a host-supplied anchor, current spentness or reserve
transition. Test that missing assertion in a separate `poc/two-v6-state`
package using the existing genuine public proof pair and fixed development VK.
This is within the owner's sustained local engineering authorization. It is
neither a deployable pool nor evidence of permissionless exits or KAS backing.

## Alternatives and reason

| Alternative | Disposition |
| --- | --- |
| Add a count/anchor/path beside the old J42 receipt | Rejected: those extra fields are not authenticated by that receipt's existential P binding. |
| Native Succinct receipt plus two native inner verifications | Rejected as a transaction candidate: its 545,000-gram verification floor exceeds the pinned 500,000 compute cap before state work. Additional fees cannot repair it. |
| Two ordinary v6 transitions | Useful separate control, but neither atomic composition nor a state assertion by the old receipt. |
| New deterministic state core and new guest/image/journal | Selected for this synthetic experiment. Reuse established verification, hashing and tree algorithms while checking the complete declared transition once. |

The [independent source/design review](../../research/intensive-2026-10-22/review/RFC0018-AND-GAS-SECOND-PASS.md)
checks count/anchor binding, sequential current nullifiers, prefix history,
range/fee arithmetic, comparator ordering and the owner-exit boundary. A
Groth16-wrapped outer plus two direct inners has a different 450,000-gram floor;
it is not a silent substitute or a qualified full transaction.

## Decision and exact boundary

1. **Reuse the existing public instance without a new setup.** Keep both inner
   SPEND bundles unchanged, development domain
   `d47cb91ef9ac74dda71c7db1519381526c3dfac5f525b904f744b97a7df713bd`
   and 328-byte VK SHA-256
   `2a9acd1639fb7b454384c65fb317a139695f5a2cbb3ebd941dd13b5f6045a2f4`.
   Preserve the checked shared binding relation and P[1,088]. Generate no new
   primitive, inner circuit, setup or wallet authorization. The existing
   single-party development setup remains an unreviewed soundness assumption.
2. **Assert only the designated synthetic predecessor.** Independently freeze
   its outpoint, descriptor/policy identity, state roots, witnesses and integer
   amounts. Initial target: `n=3`, `m=2`, `R=1,700,000,000`, `F=80,000,000`,
   `R'=1,620,000,000` sompi; the two predecessor NFs and reserve are declared
   fixture context. They are not reconstructed genesis, accepted history,
   authenticated liabilities or proof of initial backing. An optional offline
   native-context checker must derive this context from the actual supplied
   input UTXO/locking script, rather than trust an echoed host success flag.
3. **Check every state step.** Verify both inner authorizations against the
   fixed instance and authenticate their actual common historical anchor under
   the supplied prior history root. Apply four sequential current-root indexed
   NF insertions and four authenticated CM appends, using each intermediate
   root. Preserve complete record multiplicity. P's raw-byte sort is distinct
   from the indexed set's little-endian numeric predecessor comparator.
   Authenticate empty append slots and explicit count/tree-capacity bounds.
4. **Preserve the prefix-history equations in a separate version.** For
   `h=(n+1)/2`, append `history_leaf(n+2,r2)` at h and
   `history_leaf(n+4,r4)` at h+1, where r2/r4 are the independently rebuilt CM
   roots after two/four sorted records. Authenticate both empty slots and
   intermediate history roots. r2 is a commitment prefix covered by the complete
   synthetic assertion; it is not an independently accepted transaction or
   reserve checkpoint. Existing v6 bytes and replay semantics
   remain unchanged.
5. **Bind the new assertion with a new journal and image.** Freeze canonical
   encodings, including outpoint endianness, before guest execution. The scoped
   journal is 336 bytes:

   ```text
   "KPI2V6S1" || u16le(1) || SHA256(P)[32] || fixed_pool_id[32]
   || prior_outpoint[36] || prior_state[105] || next_state[105]
   || u64le(R) || u64le(R')
   ```

   Select the pool identity independently of a transaction containing its
   script. Check P's fee u128 before conversion: upper eight bytes zero,
   `F <= MAX_SOMPI`, `F < R <= MAX_SOMPI` and exact positive `R'=R-F`.
   A native diagnostic must reconstruct the journal from the actual supplied
   predecessor and exact proposed successor, with independently pinned image
   and compatible control. Old J42 receipts cannot substitute for this image
   or state assertion.

## Qualification and limits

First freeze independent public vectors, all intermediate roots and the exact
new journal. Compare the pure core against them and require meaningful semantic
rejections for substituted anchors/counts, stale or occupied NF state, replay,
wrong CM/history paths or capacity, omitted/deduplicated records, comparator
disagreement, fee overflow/underflow and changed predecessor/successor policy.
Then qualify the new guest with the same vectors before a bounded proof run.
Proof/native checks must use the resulting new image/journal and actual proof;
resource failures, fake receipts and host-only acceptance never close a gate.
Local proof/test scheduling is internal coordination, not a new user-permission
requirement. Record completed outcomes in the
[results register](../../research/intensive-2026-10-22/RESULTS.md).

This experiment remains **NONFUNDABLE even if all assertion checks pass**. The
published pair supplies only SPEND authorizations and its proving key was not
retained. There is no genuine new owner DRAIN evidence, durable new proving
capability, accepted genesis/lineage or independent-exit qualification. A future
funded candidate requires those mechanisms, public reconstruction, native
branch continuity, capacity/replay checks and complete resource/fee evidence;
the synthetic reserve cannot serve as their substitute. No collector, other
user, privileged rescue key or outer prover may become an owner-exit authority.

Reconsider or stop this construction if complete state binding fails, source
and guest diverge, a genuine receipt/control is unavailable, or the complete
native diagnostic exceeds pinned size/mass/fee bounds. Preserve a failed
80m-fee fixture; do not alter its inner authorizations, add incidental sponsorship
or weaken checks to make it fit.

No source, execution or receipt result is implied by this decision. The
[security invariants](../../SECURITY-INVARIANTS.md),
[adopted privacy requirements](../rfc/0012-useful-privacy-requirements.md),
[ADR-0033](0033-price-baseline-evaluation.md), completed 512-ledger result and
rejected withdrawal policies remain unchanged. No architecture selection,
reserve migration, production-security or privacy-benefit claim follows.
