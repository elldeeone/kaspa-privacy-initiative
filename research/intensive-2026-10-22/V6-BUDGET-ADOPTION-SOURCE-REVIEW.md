# Independent source review: v6 budget default and replay

**Verdict: no correctness blocker found in the reviewed diff.** The proposed
1600 factory default changes operational budget selection; the replay change
preserves a supplied typed version1 reserve budget while retaining exact
transaction reconstruction, native proof/signature execution and conservation.
Final adoption still requires the owner's successful retained runtime check.
This review performed source/artifact reads only: no build, tests, proof, RPC,
funding or broadcast, and no implementation edits.

Reviewed integration baseline: `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`.

| Reviewed source | SHA256 |
|---|---|
| `poc/shared-pool/src/two_input/covenant.rs` | `52f11865f8a6fd92cd0046c859c9e49e501c6fe1bda6cc27adbf0c6ef2c17abe` |
| `poc/shared-pool/src/two_input/replay.rs` | `d1b025a002f98ad242de7f31a3b72fa8a30bc5df9988b9940853eb24732cc3b4` |
| `poc/shared-pool/src/bin/kpi-v6-budget-adoption-check.rs` | `90cc4c52e63eccac1b3918356a9cb71ab62270c86f81aac343097c01d0f270a9` |

The diff changes only the v6 `BUDGET` constant/comment and replay's budget
selection/finalization/mass checks. `native.rs`, v6 `settle`, tree and circuit
sources are unchanged against the baseline. The adoption checker/wrapper are
additive validation tools, not an alternate authorization path.

1. **The authorization surface remains fixed.** `BUDGET` is consumed by
   `settle` when constructing the reserve transaction input; it is not embedded
   into the redeem-script generator, authorization, proof, VK, state or reserve
   SPK. No branch, withdrawal condition, destination, fee equation, nullifier,
   commitment/history check or accepted parameter changes with this constant.

2. **Replay permits exactly the intended operational difference.** After
   `settle`, lines314–318 copy only input0's `ComputeCommit::ComputeBudget`
   value; other variants reject. Existing ADMIT input1 signature copying remains
   unchanged. The reconstructed transaction is always finalized, contextual
   storage mass is recalculated from resolved entries, and its complete
   canonical JSON must equal the supplied body. The parser remains version1,
   canonical and fully compares its generated envelope. Output values/SPKs,
   authorization/proof/ciphertext/state/witness bytes, outpoints, sequences,
   additional-input budget, storage mass and all other body fields remain
   constrained. An arbitrary supplied state/body is not trusted.

3. **A budget is not a proof bypass.** Full `native::validate` still executes
   after exact reconstruction. Its engine uses the input's actual committed
   allowance. The exact native fee must still equal the authorization fee;
   checked reserve subtraction and cumulative integer accounting are unchanged.
   The added helper uses recomputed metrics and enforces compute/storage
   <=500,000 and transient<=1,000,000. It does not call relay policy or add
   standardness, fee-rate or roster gates to replay. Too little budget fails
   metering; excessive declared budget fails mass even if its predicate passes.

4. **Historical compatibility is intentional and source-supported.** In pinned
   upstream `01b532e8b553523216471682649693af92f0fd16`, V1 ID encoding excludes
   mass commitment (`consensus/core/src/hashing/tx.rs:227`), and V1
   `SIG_HASH_ALL` omits compute budget (`hashing/sighash.rs:250–270`). The full
   transaction hash includes the changed budget. Thus a budget-only change can
   retain IDs, descendant outpoints and ordinary signatures while changing full
   hashes. Retained3000 bodies are preserved, not rewritten to1600. New explicit
   mass caps deliberately exclude over-cap bodies; this is not a claim that
   every formerly parseable body remains valid.

5. **The adoption checker exercises the actual seams.** It pins the public
   input SHA, reconstructs all13 operations through the real factory, compares
   every canonical field except input0 budget, explicitly asserts unchanged
   storage mass, ID, proof/redeem bytes and all per-input `SIG_HASH_ALL` values,
   requires different full hashes, and executes full native validation at both
   budgets. Complete old/new lineage replays must match state and accounting.
   Its five controls reach reconstruction (fee/output), actual pairing
   (another genuine proof), precise typed underbudget cause and full-transaction
   mass rejection at65535. The stdlib wrapper independently compares bodies,
   retained native hashes/units, exact rejection layers and frozen identities.
   Report booleans alone are not the review's evidence; successful execution of
   this frozen checker remains a separate prerequisite.

Existing retained boundary artifacts report48 synthetic-context cases at both
budgets with identical units, including sentinel/middle/tail and capacity
boundaries. They corroborate but do not replace the independent source bound:
15,857,502 <=16,009,999 units, leaving152,497. That argument applies to the
unchanged fixed redeem script/native pin, not arbitrary future code or fees.

No production/security audit, chain acceptance, new cryptographic qualification,
privacy improvement or resolution of the minimum-note high-fee exit problem is
claimed. Accepted-chain authentication remains external to offline replay.
