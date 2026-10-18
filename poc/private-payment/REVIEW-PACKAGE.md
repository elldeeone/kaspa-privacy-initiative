# Composition review handoff

Current status: the owner-selected [separate-agent AI review](REVIEW-RESULTS.md)
is complete. Four offline design findings were fixed and re-reviewed under
[ADR-0019](../../docs/adr/0019-separate-agent-prototype-review.md); unfunded
offline implementation proceeded. [Four full-wallet GPU receipts and restore
checks](WALLET-RESULTS.md) now pass. External audit, proved outer transitions
and native qualification remain unavailable. The original question
package below remains useful for later code-level and external review.

## Material to review

1. [RFC-0003](../../docs/rfc/0003-private-payment-proof-and-settlement.md):
   economic statement, credit authority, spentness, invalid-operation handling,
   full-tree exits, native settlement and P1–P5 acceptance conditions.
2. [RFC-0004](../../docs/rfc/0004-private-payment-suite-and-encoding.md):
   exact candidate primitive/version choices and public intent bytes. The
   [source review](../../research/private-payment-source-review-2026-10-18.md)
   records reuse, alternatives and rights. Cargo locks and vector provenance
   identify the actual libraries used in these compatibility measurements.
3. `vectors/`: upstream public key/note/nullifier/encryption/tree data,
   independently computed depth-32 cases, and structural intent golden bytes.
   Golden intent fields do not jointly form valid payments. Primitive receipt
   inputs are published upstream test keys: **never fund them**.
4. [Local controls and limits](ADVERSARIAL-REVIEW.md). Native vector checks,
   Python/Rust byte agreement and VM receipts are implementation observations.
   They do not establish soundness of the proposed new composition.

## Questions requiring an explicit answer

| Area | What the reviewer must assess |
| --- | --- |
| Spend authority | Is full spending-key knowledge plus exact recipient derivation sufficient for this relation? Can viewing material, mixed derived keys, internal/external scope or a zero-valued dummy authorize a real note? Are canonical encodings, nonidentity rules and repaired post-NU6.2 constraints all preserved? |
| Two-slot relation | Are old-note reconstruction, hidden depth-32 membership, derived nullifiers, distinctness and `rho_new[i] = nf[i]` inseparable? Can dummy handling or an output associated with the other slot bypass ownership, delivery or conservation? |
| Conservation | Are all values u64 sompi and all two-slot equations checked in u128? Do credit authority, no-real-input credit, private change, fee, exit and zero-value semantics preserve the same native-KAS liabilities? |
| Delivery | Does proving the complete established V2 encryption computation constrain the exact recipient, rho, seed, ephemeral key, memo and all 580 ciphertext bytes? What assumptions change when outgoing ciphertext and Orchard's Halo2 bundle/value commitments/signatures are omitted? |
| Full tree | Does `exit_only`, with two exactly zero new values and no append, retain every old-note ownership/nullifier/delivery/conservation predicate? Can capacity, wrap, a dummy note or a failed credit strand or create a liability? |
| Authorization and domains | Does the complete canonical intent bind every field and immutable pool/network/lane/statement/proof identity? Does private knowledge demonstrated by a proof prevent destination/fee/ciphertext substitution and cross-domain replay without a separate Orchard spend signature? |
| Credit/refund | Do the proposed recovery signatures bind exact deposit, principal, pool and mutually exclusive consumption? **Final native descriptor encoding and recovery-key-to-outpoint authentication are unresolved**, so this part cannot be signed off as implemented. |
| Proof boundary | What must the fixed wallet journal and outer ordinary verifier enforce for total valid/invalid classification? The offline wallet image is built and recorded; native accepted wallet/outer/verifier-control identities remain unqualified. The public primitive probe has a separate identity and authorizes nothing. |
| Recovery/privacy | Can authenticated ciphertext history plus the user's own retained secrets reconstruct spendable notes and spentness? What can full-view/incoming-only keys recover? What leaks through anchors, fee funding, amounts at entry/exit, timing, RPCs or proving? No network anonymity claim is made. |

## Expected review output

Record reviewer identity/independence, exact reviewed revisions and artifact
hashes, assumptions, counterexamples, required changes, unresolved items and
which predicates were actually checked. Review existing primitive assurance
separately from this protocol's new composition. A comment that Orchard itself
is established is not sufficient. Code-level review and later proof/native
qualification remain necessary after a design review.

## Work that remains after or alongside review

- Finish native descriptor/script binding and bootstrap; qualify native accepted
  wallet/outer/verifier-control identities. The exact private packing, offline
  wallet image and bounded P2 proof/restore corpus now exist.
- Build P3 using the full wallet receipts and total ordinary classification,
  retaining current spentness, policy and valid-invalid-valid semantics.
- Qualify P3 real-private R13, then P4 accepted-lane/native payout rehearsal.
  Diagnose the owner's node's failing `getSeqCommitLaneProof` capability before
  counting it as a witness source. A working Full history RPC does not replace
  lane-completeness authentication.
- Calculate a test-KAS budget from actual transaction shapes and fees. Create a
  fresh unfunded trial in one command; confirm the real terminal payout before
  declaring readiness. Then P5/R16 requires actual separately restored users.

No external message or review request has been sent. No wallet has been funded
and no native transaction has been submitted by this package.

## P1 continuation: precise inputs and recovery authority

[RFC-0004](../../docs/rfc/0004-private-payment-suite-and-encoding.md) now adds
proposed exact private witness/journal bytes and a restricted canonical
prime-order Ed25519 validation profile. The
[recovery-auth supplement](RECOVERY-AUTH-RESULTS.md) measures established-library
signing/verification and CREDIT tuple interoperability. That supplement was native-host-only. The subsequent offline wallet guest
now proves exact CREDIT authorization; accepted native deposits and proved
outer enforcement remain open. The signature profile and incoming-note composition received the bounded
separate-agent design review; implemented proof enforcement still needs
code-level qualification, and external audit remains unavailable.

The source inspection isolates additional questions for that review:

- Shared delegate-entry script binds covenant ID, not a per-deposit key. A
  stable registration must be authenticated from the accepted funding
  transaction itself, or the actual script must bind the key. Host metadata
  supplied only on later CREDIT cannot establish deposit ownership.
- Deposit terms cannot include their own funding transaction ID inside that
  transaction's payload. Split terms from the subsequently derived native
  reference; review all bootstrap descriptor/program/script identity edges.
- CREDIT's recovery signature is outside the signed intent. The actual public
  operation envelope must validate/bind its authorization consistently with the
  wallet proof; the existence of some different private signature cannot make
  arbitrary public envelope bytes valid.
- The proposed guest cannot hardcode its own image hash. The immutable outer
  policy must bind the actual built wallet image, descriptor and complete
  journal. Review witness scope/dummy/membership encodings and full-tree exits.

C1 authorization binding and C2 policy allocation are now corrected at design
level. The native registration obligations remain open; no deployment follows. Final descriptor/rent/refund-envelope bytes,
actual reviewed artifact IDs and external review remain unavailable.

## Current execution checkpoint

ADR-0019 records the owner-selected separate-agent review route. C1 public
authorization binding, C2 generic guest/outer policy, C3 genesis anchor and C4
explicit boundary conservation are closed at design level. The exact approved
I-2 wording is applied. Unfunded offline implementation may proceed; this does
not resolve the native authority/bootstrap obligations. The later P2 wallet
receipts are actual proof evidence; a complete outer proof remains absent. The prior external-review-only stop is superseded for this
bounded scope. Earlier sealed evidence retains that historical checkpoint.

| Goal requirement | Authoritative current evidence and remaining work |
| --- | --- |
| P1 exact suite and review | Candidate suite and corrected public authorization/journal format have a bounded separate-agent design review. External audit, final native descriptor/key-to-outpoint binding and bootstrap identity qualification remain open; P1 as a whole is incomplete. |
| P2 full private wallet relation | The full offline guest and native relation now implement ownership/membership/nullifier/balance/delivery checks under ADR-0020. The actual wallet image and four genuine GPU receipts pass saved CPU verification; eight isolated own-backup restores and a spend reconstructed from restored internal change pass. Current-spentness replay and altered-signature/journal controls reject. This is separate from native admission and a complete outer proof. |
| P3 real-private R13 | Earlier proxy classification and public primitive receipts do not verify full private operations. No full-private valid-invalid-valid outer receipt exists. |
| P4 private native lifecycle | The fresh read-only node recheck is indexed below. No private deposit/transfer/exit/terminal-payout rehearsal has run. Final native descriptor, scripts, fee/rent/mass and confirmed payout qualification remain necessary. |
| P5 independent real R16 | Earlier model recovery and separate local processes do not establish independent operators or real private/native recovery. Separately restored users, full proofs, confirmed exact payouts, restored duplicate rejection and final principal reserve drain remain unproved. |

Fresh node observation at `2026-10-18T09:41:14.702Z`: Testnet-10, synced and
UTXO-indexed; Full history returns five added groups and 93 accepted
transactions. The lane-proof request uses the current pinned upstream field
names and two 32-byte hashes but still fails with a WebSocket error. This
does not establish why the server fails or which consensus features it runs.
The default configured SSH login cannot authenticate (`publickey`); no running
binary/source inspection or node change was possible. Retain a node-operator
investigation as a native-integration dependency, rather than guessing a node
upgrade or weakening the witness requirement.

[Node recheck evidence](evidence/2026-10-18-node-recheck.json) pins the source
schema, raw responses, node observation and exact diagnostic limits. Zero
native transactions, zero private wallets and no funding request. Earlier
proof/vector archives remain unchanged.

The next offline step is P3: integrate the full wallet receipts into the
ordinary proved outer classifier. The [P2 result](WALLET-RESULTS.md) supplies
actual wallet proof enforcement and bounded host admission/restore evidence,
not native consensus or a complete outer proof. Native authority/bootstrap, actual code/artifact review and
node witness qualification remain prerequisites for native trials. The full
P1–P5 goal is incomplete. No public review request has been sent.
