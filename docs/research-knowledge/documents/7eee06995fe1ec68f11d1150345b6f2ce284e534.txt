# Candidate C incremental privacy contract

**Status: prospective, awaiting the parent review and exact recipient trace pin.**
This is a bounded deterministic leakage screen, not RFC-0012 qualification. No
evaluation has run. It changes no workload, numerical gate, note floor or exit
availability requirement. All work stays offline; there is no proving, native
execution, wallet RPC, funding or broadcast in this workstream.

## Question and hypothesis

Candidate C adds public receive-invoice fields and a revealing exit to a future
private-payment relation. Which observations disclose additional linkage, and
which reuse rules must the recipient enforce before accepting value?

The narrow falsifiable hypothesis is: under fresh note-authority fields for each
accepted note, O/K/native_PK do not create an equality link to a different
invoice/note **before a revealing publication**, beyond the records explicitly
given to the observer. The proposed incoming delivery key is domain-stable, so
equality of incoming deliberately fails this claim if it is extended to the
whole descriptor. Report that channel separately. This is only a byte-equality
property. It is not a
computational hiding argument or a claim about timing, amounts, network access,
cryptographic strength, people or the 32-role workload.

The revealing branch necessarily discloses the selected note's opening, value,
position, CM, native public key and note-local nullifier key. An observer can
derive that note's NF. Reusing the same key across notes extends that computation
to **every public CM/position**, then matching computed NFs identifies other
spent notes sharing k without knowing their openings. A future matching spend
is recognizable too. Sharing a stable incoming key does not make distinct
per-invoice O equal when s varies; it is a separate direct equality channel.

The old common-price workload remains unqualified: its permitted prior has
within-10% amount accuracy `21103/100025 = 21.0977255686%`, above the unchanged
20% absolute cap. Passing this screen cannot change that analytical lower bound.

## Inputs and observer boundary

Pin the exact candidate relation, recipient descriptor/acceptance specification,
and actual new recipient/reveal trace before running. Hash source and raw trace
files, and identify which bytes come from a native transaction versus an offline
recipient fixture. An unresolved or missing input yields **incomplete**, not pass.
Normalized exports retain source path, source SHA-256 and record pointer.

| Profile | Allowed inputs | Withheld until scoring |
| --- | --- | --- |
| C | Public accepted operation fields, CM list/order/count, NF list/count, mode, fees, native payout fields and public ciphertext bytes. | Owner labels, seed, s, k before publication, sender/recipient mappings, invoice directory and undisclosed openings. |
| C plus named invoice disclosure | C plus that participant's sent/received invoices and exact declared owner-to-descriptor mapping. | Other participants' records. Facts legitimately already known are excluded separately. This is a P or I addition, not C. |
| C plus publication | C plus all transmitted revealing witness/opening bytes, even when rejected, unconfirmed or later orphaned. | s and native signing secret remain withheld. No chain rollback removes previously published information. |

The receive proposal is an interactive one-time invoice with public
`D, u64 index, O, incoming, K, native_PK`. The exact index serialization, receiver
derivation, authenticated delivery and reuse rejection remain upstream design
inputs. An index alone does not identify a recipient; a directory association,
repeated descriptor, fingerprinting side information or timing can add linkage.
No arbitrary hash byte is treated as an owner label.

The latest proposal uses per-index s/k/native signing keys and a **domain-stable
incoming delivery public key**. Invoice directories therefore link recipient
invoices even when O/K/native_PK never repeat. Incoming is encrypted inside the
receipt plaintext, not exposed by the chain ciphertext wrapper; its appearance
in a later revealing opening makes repeated reveals linkable. A participant
knowing one incoming-to-recipient mapping can label other matching reveals.
Neither the ciphertext wrapper nor an index alone is assigned that association.

The native cost proposal additionally considers **public hash-only ADMIT** with
`O,incoming,K,native_PK,rho,V` in the ingress witness. If that route is selected,
C observes incoming at admission and can directly link it to later revealing
openings and the admission's public funding ancestry, without an invoice
directory. The encrypted private-transfer wrapper does not hide a key already
published at ADMIT. This remains a conditional source-level channel until actual
ADMIT bytes are supplied; this workstream will not manufacture a native trace.

## Frozen diagnostic cases and falsifiers

1. **Actual fresh recipient and payout trace.** Verify canonical public field
   lengths and exact field correspondence between receiver invoice, committed
   opening and revealing publication. The receiver's pre-payment backup must
   derive its fields; the privacy scorer uses exported commitments only. Audit
   the observer export for secret/owner labels not present in the stated source.
   Every source-derived exact equality is reported. Any absent real trace or
   unbound public export makes this case incomplete.
2. **Descriptor reuse control.** Construct counterfactual distinct CM/position
   records sharing the actual invoice's K/native_PK/incoming/O individually and
   together, and a fresh-field control. Report exact equality equivalence classes;
   do not turn the four nominal owner labels into a probability or people count.
   Individually edited fields are byte-channel/malformed-descriptor canaries,
   not claimed relation-valid notes: for example, a reused k necessarily has
   the same derived K. The HMAC scan control preserves this k/K consistency.
   The recipient must not automatically credit a second distinct CM/position
   for a used one-time index. The first owned claim remains actionable; later
   duplicates do not retroactively freeze it. Preserve all accepted liability
   positions and owner handles; do not erase backing obligations by quarantine.
   A control not exposing its deliberately repeated field invalidates the screen.
3. **Disclosed-k control.** Using the selected candidate's exact NF encoding,
   scan the public CM/position set under the disclosed k and match against
   public NFs. Include a distinct CM sharing k and a CM with different k. The
   former must match its reference NF; the latter is a negative diagnostic,
   not a collision bound. The observer is not given which sibling reuses k.
   This recognition needs public CM/position/NF, not the sibling's opening.
4. **Preacceptance/orphan knowledge.** Publish the actual reveal, remove its
   transaction/state effects, then observe an ordinary private spend's same NF.
   The observer retains its old CM/position/k and recognizes that NF. A scorer
   resetting knowledge on rollback is invalid. This is disclosure persistence,
   not a new native or private-spend authorization test.
5. **Arity/counter controls.** Compare declared one-real and two-real input shapes.
   If public NF/count deltas differ, exact arity is observable. If both use the
   same two opaque insertions, counter equality alone discloses no difference.
   Fixed deltas do not establish dummy indistinguishability, valid backing,
   capacity sufficiency, receipt encryption or source-byte conformance. Record
   the actual chosen rule; do not inherit the old even-count rule.
6. **Historical direct-payment value.** When an authenticated trace declares the
   ordinary payment amount equals the revealed note value, compute `V=P+fee`
   and report the exact historical amount disclosure through the later horizon.
   Public payout value and facts legitimately known to a counterparty are
   separate exclusions. A revealing exit is not an automatic waiver for an
   ordinary historical payment target. If the binding is absent, classify this
   proposition unknown instead of assuming an economic allocation.

The counterfactual controls are synthetic diagnostics derived from the actual
fixture; they are not new accepted native transactions or qualifying ledgers.
The actual fresh descriptor case and all constructed counterexamples are kept
separate. No prior workload, held-out data or old attack suite is rerun.

## Thresholds, outcomes and stop rules

All checks above are exact deterministic conformance/canary checks. There is no
sampled rate, confidence bound, statistical power, retuned seed or changed
threshold. Retain every failure and counterexample. A control failure or missing
source binding is **incomplete** and stops scoring; do not alter an observer or
erase a case to pass. A deterministically exposed supported historical target
is a **failure of that named claim**, even when another diagnostic passes.

Stop after one frozen evaluation and its source/data integrity review. New
protocol versions require a separate prospective contract; do not mutate this
one after results. Existing RFC-0012 identity 10%, amount 20%, five-point
advantage, selective-precision and zero forced-disclosure gates remain open.

At most two CPU cores and 2 GiB RAM are used. Only Python standard-library hash,
HMAC, integer arithmetic, JSON, file hashing and exact equality operations are
allowed. No network, subprocesses, private-proof/native execution or new
cryptographic construction. Root review of this contract and exact frozen input
manifest is required before the evaluation.

## Sources and interpretation limits

- [RFC-0012](../../../../docs/rfc/0012-useful-privacy-requirements.md), observer
  profiles, R2/R3/R4/R6/R7 and unchanged measurement/qualification contract.
- [Prior floor](../../../privacy-target-consistency-2026-10-22.md), retained
  analytical result, not a newly run study.
- [Candidate C](../../exit-fee/ARCHITECTURE-OPTIONS.md), two-secret authorization,
  unresolved recipient contract and monotonically retained reveal knowledge.
- [Native public feasibility source](../../../../poc/future-exit-feasibility/src/main.rs),
  exact new candidate hash/HMAC encodings. This supplied-UTXO prototype is not a
  private proof or accepted-chain backing trace.
- [Current native integration proposal](../native/INTEGRATION-PROPOSAL.md),
  conditional public hash-only ADMIT opening; distinguish proposal from actual
  accepted bytes.
- [Orchard nullifiers](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note/nullifier.rs#L1-L7)
  and [diversified addresses](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/keys.md#L75-L100).
  Orchard's key/address construction is different; diversified address reuse is
  not candidate C's emergency-key publication model.
- [MWEB reusable stealth-address design](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/stealth-addresses.md#L1-L5)
  illustrates that reusable public destinations can generate fresh outputs under
  a different construction. This work does not implement or claim its properties.

No descriptor encryption or cryptographic hiding theorem is established by this
analysis. Full privacy qualification requires the actual private relation/native
bytes and declared C/P/A/I observations through complete drainage, including
appropriate held-out workloads and the unresolved prior information limit.
