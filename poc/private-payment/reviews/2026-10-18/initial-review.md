# Separate-agent cryptographic composition design review

Date: 2026-10-18. Reviewer: separate Codex agent `/root/crypto_composition_review`.

**Decision: conditionally suitable for an unfunded, offline research implementation after the four specification corrections below. The frozen specification is not ready unchanged. No native testnet credit/refund/payout gate is cleared.**

I found no concrete inflation, theft, or unauthorized private-spend counterexample to the *fully enforced* note relation as written. That is a bounded design-review result, not a cryptographic soundness result. There is no full wallet relation implementation here to demonstrate accepting an attack. Four issues need explicit correction before treating the wallet/state specification as settled: public authorization binding, descriptor-policy responsibility, the initial allowed anchor, and the literal I-2 equation. Native authority and bootstrap gaps are substantial but can stay isolated from an honestly labelled offline wallet prototype.

This is an AI review by a separate agent sharing the same platform, host and underlying model. It is **not an independent human/external audit**, independent operator test, or certification of cryptographic soundness, privacy, production safety, or readiness for funds. I did not inherit the author's acceptance conclusions.

## Reviewed identities and boundaries

The authoritative initial inputs are the frozen files under `/tmp/kpi-crypto-composition-review-20261018`, not subsequent working-tree edits. All 13 SHA-256 values in `manifest.json` were independently recomputed and matched. The repository base was `c2037893936508d6d61dcb9ee78aea6ba4515aab`, with extensive pre-existing uncommitted/untracked work. A Git commit alone therefore does not identify this review. Exact frozen identities are reproduced at the end.

Primary local upstream identities checked:

- Orchard `616a669df8c9a59c33d47064d3ce04b25d026b2e`, source root `/tmp/kpi-private-payment-606py7g2/sources/orchard`; actual compilation cache checkout at `/home/luke/.cargo/git/checkouts/orchard-670bc51eb4ca002f/616a669` resolves to the same commit. Key/note/nullifier files used in the small experiment were byte-compared with the inspected checkout.
- vProgs `f9b84a863a7c7c20586a9cf947550475e894f72e`, `/tmp/kpi-private-binding-M2xERlsE/vprogs`.
- Ed25519-dalek release checkout `8016d6d9b9cdbaa681f24147e0b9377cc8cef934`, `/tmp/kpi-private-binding-M2xERlsE/dalek`.
- Compiled curve API source was inspected at `/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/curve25519-dalek-4.1.3`; its earlier release-byte comparison is supplied evidence, not a release comparison repeated by this reviewer.
- Relevant RISC Zero 3.0.3 receipt APIs were inspected in `/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/risc0-zkvm-3.0.3/src/receipt.rs` and `receipt/{composite,segment}.rs`.

RFC/ADR/invariant locations below refer to line numbers in the **frozen** copies. Additional tooling locations refer to the working-tree sources read during this review. I inspected public P1 vector/checker code; I did not review every dependency, prove the new relation, build native scripts, or refresh all upstream HEADs. The mature-protocol comparison was read and challenged against relevant selected Orchard/vProgs source; it was not an exhaustive fresh audit of Aztec, RAILGUN, Monero, MWEB, or Kaspa consensus.

## Findings and required dispositions

| ID | Impact and prerequisite | Result |
| --- | --- | --- |
| C1 | Medium binding/correctness; offline wallet specification blocker | Public CREDIT signature bytes are not bound to the signature checked privately. |
| C2 | High **if** omitted from composition; offline policy-boundary specification blocker | Wallet descriptor admission is required but no descriptor/policy reaches the generic guest; explicitly assign all admission checks. |
| C3 | Medium liveness; offline state/genesis specification blocker | The empty-tree genesis root is not explicitly included in allowed anchors. |
| C4 | Specification inconsistency; offline conservation specification blocker | CREDIT and EXIT contradict the literal private-only equation in I-2. |
| N1 | Critical theft/inflation **if implemented without binding**; native testnet gate | Actual native deposit key/principal/outpoint recognition is still undefined. |
| N2 | High safety/liveness **if instantiated incorrectly**; native/artifact qualification gate | Complete descriptor/program/script bootstrap dependency graph remains unresolved. |
| N3 | High double-payment/recovery **if omitted**; native/state qualification gate | Current-state, permission consumption, paid markers, and canonical history remain obligations, not demonstrated integration. |
| R1 | Medium recovery/privacy; before accepting liabilities or making privacy claims | Exact secret backup inventory, receipt leakage policy, and honest randomness policy need implementation decisions. |

The conditional labels matter: N1–N3 are not discovered deployed exploits. The RFC already identifies their missing enforcement and prohibits claiming those gates. Leaving them explicit does not prevent constructing a generic offline wallet relation with synthetic policy/deposit fixtures.

### C1: bind the actual public authorization envelope

**Location:** RFC-0003:123–137, 143–153; RFC-0004:148–156, 190–204; suite candidate `publicAuthorizationEnvelopeBinding=null`.

**Counterexample:** Obtain a valid CREDIT proof for intent I using genuine private signature S. Replace the public operation's signature with zero bytes or a different signature while retaining I and its proof. The proposed journal contains only context IDs and `intent_id`; neither commits the signature. A verifier that relies only on that proposed journal proves that *some* private signature authorized I, not that the public envelope was valid. Invalid public authorization bytes could be accepted, contradicting deterministic operation validity and the explicit envelope requirement.

This does **not** on its own demonstrate theft: the original proof still requires a genuine signature covering all of I, and current pending-state consumption should still prevent duplicate credit. Do not overstate its severity as a signature forgery.

**Smallest correction:** Define exact canonical `auth_bytes`: CREDIT is flag 1 followed by exactly 64 signature bytes; TRANSFER/EXIT are exactly flag 0. Compute `auth_id = SHA256(fixed distinct ASCII authorization-domain tag || auth_bytes)`. Add that digest to the exact wallet journal. The guest verifies CREDIT using these same auth bytes; the outer decoder independently derives the same digest from the actual accepted operation and requires complete journal equality. The signature continues to sign only the existing G-hash/intent tuple. This introduces no signature/proof/native-ID cycle and requires no duplicate signature-verification algorithm.

**Closure controls:** Valid CREDIT; every signature-byte mutation; flag substitution; omitted/trailing authorization bytes; TRANSFER/EXIT with a signature; altered context and intent; changed `auth_id`; a valid receipt paired with another valid signature on the same message; exact complete-journal comparison. Public codec tests can close the format issue; only the later guest and outer implementation/proofs close enforcement.

### C2: define who authenticates the immutable policy

**Location:** RFC-0003:75–81, 157–172; RFC-0004:164–204.

The relation says it has a pinned descriptor and must accept the exact allowed descriptor/suite. The proposed witness packing supplies I and note/auth material only. It supplies neither G nor authenticated policy, while a guest must not embed its own image or the final G hash. An implementer must otherwise guess whether the guest trusts I's duplicated context fields or some host-owned policy.

**Conditional attack:** A self-consistent proof can carry an attacker-chosen `D`, lane, network, statement, or wallet hash if these bytes are merely hashed/copied. If the outer verifier treats the journal's G hash as sufficient and fails to compare all context fields against authenticated immutable state, that proof can target the wrong spent-resource universe or wrong pool. It is particularly unsafe to select `N[D]` directly from unchecked I.

**Smallest correction:** Explicitly make the wallet guest generic. It enforces the fixed selected algorithms/versions/encodings and fully binds supplied IDs in I and its journal. The **proved outer transition**, before any effects, authenticates the immutable policy and compares each of `G_hash,D,network_genesis,pool_id,lane_id,statement_id,proof_suite_id,wallet_program_or_vk_hash` to its authorized policy. It verifies the receipt against the actual permitted image, rather than trusting the journal's image string. It enforces a single canonical economic spent set for the admitted D. There is no need to invent a new note hash/KDF or put versions into nullifiers.

An offline fixture may specify an explicit synthetic policy and actual locally built wallet image. That fixture does not recognize a native deposit, authorize reserve release, or constitute a deployed G. State that distinction in the relation API and documentation. A guest-only receipt is a conditional assertion about I, not proof of pool admission or native backing.

**Closure controls:** Independently mutate every duplicated context field while holding the authenticated policy fixed; use a real receipt from a different wallet image with a forged matching journal string; admit one old note through two supposed version routes and require the same consumed key `(D,nf)`; reject an attempted caller-selected D. These must be checked at the explicitly assigned enforcing layer.

### C3: admit the genesis empty root explicitly

**Location:** RFC-0003:246–249, 259–269, 280–284; RFC-0004:67.

Allowed roots are described as canonical **post-operation** roots. CREDIT has no real input membership, but it still supplies an anchor and passes the outer allowed-anchor check. If genesis initializes A to the empty set, no first operation can succeed and hence no post-operation root can be added.

**Smallest correction:** Define genesis `C` as the canonical Orchard depth-32 empty tree with count zero, and `A={C.root}`. Then add only complete canonical post-operation roots; never a root between the two appends. Define reorg restoration back to that initial anchor. This exception is not a skip-membership rule for positive notes.

**Closure controls:** First genuine CREDIT at the empty anchor succeeds; a positive fabricated old note on that anchor fails membership; unknown/caller-provided root fails; root after first append fails; correct post-second-append root succeeds; rollback to genesis restores exactly the genesis state/anchor.

### C4: reconcile I-2 explicitly rather than silently reinterpreting it

**Location:** SECURITY-INVARIANTS:24–32, 118–123; RFC-0003:181–198, 311–324.

Literal I-2 requires `sum(private inputs)=sum(private outputs)+fees` for every valid private transition. CREDIT deliberately has zero private inputs and positive private outputs; EXIT removes public principal in addition to fees. The broader monetary accounting is reasonable, but the frozen literal statements cannot all hold simultaneously.

**Smallest correction:** Explicitly review and record the conservation boundary as `private_in + authenticated_deposit_principal = private_out + exit_principal + authorized_private_fee`, with the existing exact kind restrictions and backed unpaid-claim rules. Alternatively retain I-2's equation only for internal transfers and state the two boundary-transition equations explicitly in the invariant. This clarifies accounting; it must not introduce an unauthenticated public input, hidden fee, negative amount, or sponsor subsidy. Record the change as an explicit reviewed clarification under the repository invariant rules.

**Closure controls:** CREDIT with no authenticated p fails at outer state; real-input CREDIT fails; hidden deposit/exit fields on TRANSFER fail; EXIT principal remains a backed unpaid liability; field-wrap attempts and u64/u128 boundaries fail appropriately. No change should permit the ledger sum to exceed reserve.

### N1: native recovery authority remains an absolute native gate

**Location:** RFC-0003:123–137, 190–198, 304–329; RFC-0004:95–100, 206–238.

The supplied recovery key and principal in I are not authority. The existing vProgs delegate-entry address commits its covenant ID, not this per-deposit key. Source inspection confirms the example derives the expected script from committed config and parses the funding output from the same transaction (`runtime-processor/src/action/deposit.rs`:38–64,76; `deposit_policy.rs`:122–137; `zk/abi/src/delegate_script.rs`:15–24).

**Conditional theft attack:** If a later host can attach an attacker key/descriptor to another user's earlier output, the attacker signs a CREDIT to its own recipient, or a refund to its own native script. A perfectly sound wallet proof then helps steal the real deposit. If p is accepted without actual output-value authentication, the same gap can inflate private liabilities.

**Minimal path:** Keep registration recognition distinct from inner proof support. Either authenticate stable terms from the accepted funding transaction or use an actually key-committing script. Stable terms must bind pool/network/lane context, output index, actual script version/bytes, exact principal and recovery key. Derive the funding outpoint afterward from actual native data. Deduplicate actual outpoints, not descriptor aliases. Require an accepted native signature/transaction construction that really commits the intended terms. One current pending record arbitrates credit versus refund; no independent owner-key bypass survives credit.

Full native registration/refund bytes, rent accounting, native identity rules, malformed registration outcomes, and proof binding need their own qualified implementation. The wallet may prove a synthetic CREDIT statement offline; that must be labelled conditional on an authenticated pending record and cannot fund a liability.

### N2: artifacts and bootstrap are separate from generic wallet implementation

**Location:** RFC-0003:75–81, 143–153; RFC-0004:196–204,220–238; ADR-0018:28–35.

A guest cannot embed its own image hash. Likewise a funding payload cannot include its own final transaction ID. Additional cycles can arise if G commits an outer image/script, while that image/script hardcodes G or a covenant identity derived from the same bootstrap. The frozen text warns about individual edges but does not specify the complete deployment graph.

**Required native resolution:** Draw and validate a finite dependency graph: generic guest builds -> actual permitted artifacts -> parameterized immutable policy/native script/bootstrap -> authenticated genesis/reference. G must not contain its own hash recursively; its initial-state commitment must likewise avoid embedding an already-final G hash. Any native covenant/genesis identity derived from a transaction must be bound using the upstream supported post-bootstrap/state mechanism rather than a guessed fixed point. Resolve this before any native deposit is fundable.

**Offline allowance:** A generic wallet can be built without native identities, with its final image inserted into external fixture policy only after build. Unknown real IDs must remain unavailable and incapable of passing native qualification. Do not fill deployment fields with zeros or relabel synthetic IDs as accepted. This separation is sound only with C2's complete outer policy checks.

### N3: replay, credit/refund race, paid state and final drain need actual integration

**Location:** RFC-0003:244–300,302–367,369–402.

The specified algebra and atomic state effects address the obvious replay routes. It is still necessary to implement and prove them against real accepted operation identities, not just wallet journals. A re-encoded/rerandomized receipt or another native wrapper must not create a new economically consumable input. Claim IDs may change with accepted identity; authorization must still first consume the same deposit/nullifier exactly once.

In particular: current N is shared across anchors and versions; old-root membership never resets spentness; pending is atomically consumed once; refund requests retain unpaid backing; paid markers and native UTXO/permission consumption both survive restore; each native output is assigned once to exact principal; last payout does not require a positive reserve successor. Complete root state includes these ledgers and cursor. Missing data/artifacts means unavailable, not invalid. These are substantial native/state gates with no demonstrated passing integration in this package.

Before implementing the ordered state adapter, also select exact expiry semantics: e.g. canonical operation ordinals begin at an explicitly chosen value, increment with checked arithmetic for success and rejection, and a present bound is valid iff `ordinal <= bound`. The wallet only binds the optional bound; it cannot determine actual accepted order from its private witness.

### R1: pin recovery inventory and proof/privacy behavior before user-facing claims

**Location:** RFC-0003:215–242,369–402; RFC-0004:18–30,164–204.

The selected incoming-only delivery is sufficient in principle to recover **incoming** V2 notes from complete authenticated operations: rho is public per action slot; the ciphertext carries diversifier/value/seed/memo; local full decryption checks epk and cmx; full-viewing/spending material supplies own nullifiers. It is not sufficient for outgoing payment audit history. Internal and external incoming scopes must both be scanned; one scope's IVK does not cover the other.

Before any liability, specify the exact backup: per-pool Orchard SK (or a reviewed documented derivation), software/profile identifiers, and **each pending deposit's independent Ed25519 signing seed/secret** plus recognized registration/reference data. The Orchard key does not derive an independently sampled Ed25519 recovery key. Public deposit metadata and an Orchard seed alone cannot recover an uncredited deposit. Do not promise seed-only recovery.

Honest wallet code must use an established OS CSPRNG for fresh secret keys, rseed and dummy material, rejection-sample through the established constructors, and fail closed on entropy failure. The proof validates relations, not entropy quality. Do not weaken nullifier duplicate checks to allow reused dummy material. Receiving-address exchange should authenticate the intended pool/network context as well as raw Orchard address.

Pin the receipt serialization/allowed variant, verifier parameters/control identities, halted successful execution, absence of unresolved assumptions, and dev-mode prohibition before considering the proof implementation qualified. RISC Zero 3.0.3 has a FakeReceipt/dev-mode verification route (`receipt.rs`:554–588,901–995). The P1 package's `disable-dev-mode` feature is good evidence of intent, but the later actual guest/verifier build must inherit the restriction.

Do not infer all observable leakage from the wallet journal alone. Composite receipts expose segment count and per-segment claims (`receipt/composite.rs`:38–62; `receipt/segment.rs`:38–63); execution/proving time and allocations can vary when positive-input membership is performed and dummy membership is skipped. Pin/measure the chosen proof envelope or explicitly scope this leakage. No specific witness extraction from those fields was demonstrated. A fixed two-slot relation alone does not prove constant shape or constant-time execution, which the RFC already disclaims.

## Adversarial assessment of the principal composition

1. **Full spending-key authority and scopes:** `SpendingKey::from_bytes` rejects invalid ask and both invalid incoming scopes (`keys.rs`:100–123). `FullViewingKey::from(&sk)` supplies the dependent components. Derive the old recipient with `fvk.address(d, scope)`, rather than trusting a supplied FVK/IVK/pk. Internal derivation changes rivk/IVK while preserving nk (`keys.rs`:529–543), so `note.nullifier(&fvk)` is appropriate for either properly derived scope. Scope changes alter the address/commitment and cannot authorize the original positive note without its matching path. The known historical circuit weakness is not preserved merely by computing checked full-key dependencies ordinarily, but this newly translated program still needs review; it does not inherit the Halo2 audit result.

2. **Zero dummies and two slots:** Classifying zero as dummy is safe for value conservation only because every value is range checked and zero contributes no entitlement; old membership is the *only* skipped condition. Full key/note reconstruction and deterministic nullifier derivation remain. Both dummies and positive inputs must pass within-operation and current-global nullifier uniqueness. An input/output slot swap cannot be accepted unless all derived nf/rho/commitment/encryption bytes and the full intent are recomputed consistently. Arbitrary zero dummies can consume public space and cause liveness costs; that is not inflation.

3. **Note/nullifier/economic domains:** Orchard V2 commitment/nullifier functions contain no KPI pool/version domain. That reuse is deliberate only if outer admission is exact, each economic D has one authoritative spent set, accepted versions do not fork that set, and pools use separately retained keys as selected. The consumed resource is `(D,nf)`, not `(G/version,nf)`. Do not silently add a version to the derivation to make tests pass. Creating another pool or domain does not allow claims against this pool's reserve merely because a commitment is copied. Initial support remains one note version; later migration needs new review.

4. **Membership:** Use all 32 checked siblings and the entire u32 position. Recompute from the derived extracted commitment to I.anchor. Outer current state decides whether that root is accepted, including canonical genesis and post-operation roots, and checks current spentness separately. Position independence of Orchard nullifiers helps prevent one duplicated leaf from creating two economic spends; a second appearance must still encounter the same consumed nullifier.

5. **Encryption, seed, rho and memo:** `RandomSeed::from_bytes` checks the dependent nonzero esk; `Note::from_parts` alone is explicitly not received-note validation (`note.rs`:270–294). `rho_new[i]` must come from the same public nf slot, not witness data. `OrchardNoteEncryption::new(None, same_note, same_memo)` with derived esk supplies full incoming computation; compare exact epk and all 580 bytes, not just cmx. `note_encryption.rs`:260–330 shows recipient key, rho-dependent esk, KDF and serialized plaintext responsibilities. Omitting outgoing ciphertext avoids an outgoing-audit facility, not an incoming decryption predicate. Receiver still calls the established full decryption/validation path and verifies its hierarchy/version/current spentness before crediting payment.

6. **Integer conservation:** Two u64 input/output totals fit u128, but every operation must explicitly use checked u128 conversion/addition; never use wrapping arithmetic or a proof field. EXIT's x+f must also be promoted before addition. Ledger/native u64 limits are additional constraints, not justified by the private sum. Kind equations plus current authenticated deposits/claims conserve the complete liability sum; C4 makes the invariant statement match that boundary.

7. **Full tree:** `pre_count` needs a representation that can store `2^32`, while positions remain u32. Full append checks `count+2 <= 2^32` before effects. `exit_only` must prove both output values zero and still check their full computations, consume both current nf values and create backed exit/fee claims. It appends none and retains the same commitment root. Pending credits at capacity remain refundable. I found no specific inflation or unauthorized-exit counterexample to this branch when these predicates hold.

8. **Knowledge, intent and proof binding:** Require the proving system's relevant knowledge/execution soundness and zero-knowledge assumptions, rather than treating proof of bare existence as an authorization definition. Full private SK computation plus a completely bound journal can replace the original Orchard surrounding spend signatures in this distinct research relation, conditional on those assumptions and the selected verifier. Complete intent authorization prevents destination/fee/ciphertext substitution. C1/C2 are necessary parts of that composition. Verifier success with an unresolved recursive assumption, wrong successful-exit claim, wrong control parameters, or a host valid/invalid flag must never substitute for full ordinary verification.

9. **Native/recovery/privacy:** No private proof alone authenticates a funded outpoint, permission, paid claim, canonical root, complete accepted sequence, or replacement archive. Those require explicit outer/native evidence. Spending/view keys stay local, including with a replacement prover. Complete-history scanning and authenticated artifact distribution are declared trust/availability assumptions, not established independent operators. Missing history cannot be presented as zero balance.

## Reviewer checks and meaningful next evidence

Read-only/static work included the full frozen RFC-0003/RFC-0004/ADR-0018/invariants/suite/handoff, the two supplied source notes, relevant pinned Orchard key/note/nullifier/tree/encryption/circuit code, vProgs native deposit policy/parser, strict Ed25519 verification, P1 primitive and auth checker implementations, and public intent encoders.

I added and executed only `scope_experiment.rs` under this review folder, linked against the existing pinned Orchard library. It checks an explicitly public synthetic SK for external/internal recipient distinction, exact hierarchy recognition in both scopes, wrong-key nonownership in both scopes, zero/one/u64-max note construction, different commitments/nullifiers across values, and wrong-FVK nullifier differences. It passed. This is a primitive sanity check with no private proof, native operation, wallet, funding, or soundness claim. Its compiled Orchard key/note/nullifier source matched the inspected source byte-for-byte. No private key for any funded wallet was created.

Required subsequent positive/negative proof evidence should include one exact valid CREDIT -> private TRANSFER with change -> EXIT; one-real-plus-dummy and two-real cases; wrong key/scope/path/position/root; caller-selected/duplicate/stale nf; all encryption/recipient/memo/rho mutations; checked arithmetic boundaries; full-capacity exit_only with both zero outputs; and C1/C2 mutation controls. Then qualify the real total outer classifier on valid -> cryptographically false -> valid receipts and restore/batch replay. Only afterward can native registration, claim payout and terminal drain be rehearsed with test KAS.

No protocol/tooling source was altered by this reviewer. No wallet creation, funding, broadcast, mainnet operation, infrastructure change, external message, commit or push was performed. Only review/evidence files inside this task folder were written. Parent-author fixes discussed during review are proposals until separately frozen and re-reviewed.

## Exact frozen SHA-256 identities

```text
c605a5c07d1edbdee45ada102e0c21913e663a506219190818d846179bc6d6fb  AGENTS.md
44cf983d06c8895c61a492107f65487725331a1b2f93d1c89e7353fb5399733d  SECURITY-INVARIANTS.md
b3c1f38944852677b7335decf4edcd8cbbb3f182cd16c86bc25a7c8e4c9edb1b  docs/rfc/0003-private-payment-proof-and-settlement.md
5171ac5fc6e75f4b88889a233a8ca372c0ab074fb0070462cb3220288e26e1a6  docs/rfc/0004-private-payment-suite-and-encoding.md
d2d69284bab263ded1ef2c4e1f8edeca4151e2c68f8a29581a5d291a9f8ae6eb  docs/adr/0018-private-payment-implementation-package.md
115cd86e16b14f21c8ec0f227b323f829bbf613a93187a1128817116f89f39de  poc/private-payment/REVIEW-PACKAGE.md
14e2d435179f036e52fbdec39536bec4f9d37a3e9093eb45b114fd99bb57ba28  poc/private-payment/suite-candidate.json
7b1a02c73bdd0d23f4859269f81cc25fab5d5208267a0c3afa01405a83ef4150  poc/private-payment/recovery-auth-vectors/src/lib.rs
76a96d423b12932b1814480f24811862e459acb637379363803f74b44ba3088a  poc/private-payment/recovery-auth-vectors/src/main.rs
0d0314ec09d0c79167632be2133bfbff3b25d45d9d6acd938dc3dd501cb2fe5b  poc/private-payment/primitive-vectors/src/main.rs
b46859327e1b0a225c509286ce8df31ca031a755cd94795a12f07047602b1c6c  poc/private-payment/primitive-probe-guest/src/main.rs
0fef13de191ba6c02194fa51d974ae14f7e9130d074d28ca3f07b47df212614e  research/private-payment-source-review-2026-10-18.md
2097435c0bae8a95bbb35f5ae08b94206f111fbdd5c4a9a2aaea0dcd76c8c702  research/private-payment-recovery-binding-2026-10-18.md
```

Source hashes for experiment correspondence:

```text
ed5c26bc7907a928134f07612af322c2f55dd5da28b452660bff77f959c287ba  Orchard src/keys.rs
fdd312b64b14071c15b6a460776bc9a94d7d3cc245b3b379aff42c28830e22cc  Orchard src/note.rs
860747577a477fa387af512262c7f391593d74f4ac619a86b5c6c897bf18c659  Orchard src/note/nullifier.rs
```
