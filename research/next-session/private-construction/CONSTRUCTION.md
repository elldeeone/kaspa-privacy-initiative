# Owner-private construction: exact API gate and established candidate

Research at continuation commit `b7b41ab066807d7859499b3491a663ab110fedf9`,
2026-10-24 UTC. Native KAS remains the only asset. This document changes no
funded instance, cryptographic relation, parameter, old privacy study or success
threshold. No private backup, witness or PK was read. No proof/setup/GPU job ran.

**Decision input:** direct Orchard/Sapling PCZT role separation does not provide
the required owner-private multiparty construction. The strongest established
construction found is the ValueShuffle family: confidential components,
anonymous output mixing, a private aggregate of value-commitment blindings, and
each owner authorizing the complete result. There is not yet a reviewed,
implemented native-KAS composition of those parts. Selecting that composition
requires an ADR and further API/observer tests; this note does not adopt it.

The useful next experiment is a small existing-library API and transcript
falsifier, specified below. Another full wallet circuit or larger heldout study
would not answer this construction question.

## What the construction must hide

Retain the observer in the [prior decision](../independent-payments/privacy-next/DECISION-NEXT.md):
the public chain, legitimate payer/recipient facts, and the assembler's complete
submission transcript, including timing and network/session identities. An
owner necessarily knows its own payment and change. The target is unrelated
honest owners' spend/output associations, not erasing that legitimate knowledge.

The current W body publishes ordered Auth/NF/CM/cipher groups. Wrapping their
verification in another proof does not remove these groups from either the
body or the assembler's earlier submissions. Removing them only from the chain
would weaken the tested observer if the assembler still receives them.

The original singleton-funding ancestry and amount-prior failures remain. Even
an ideal construction layer cannot hide an only possible earlier funding source
under complete-history assumptions, or lower an already-too-successful
transaction-independent amount predictor. No new distribution, honest activity,
threshold or heldout draw is silently substituted here.

## Actual APIs, rather than role names

| Existing interface | Observed implementation | Consequence |
| --- | --- | --- |
| Orchard `pczt::Bundle::create_proof` | Iterates all actions, builds every private circuit and invokes one `Proof::create` over the resulting vectors. Each action needs its spend FVK, recipient, value, rho, rseed, path, alpha and rcv, and output recipient, value and rseed. | Sending the bundle to one ordinary prover collects unrelated owner witnesses. Separately proving partial action bundles is not an exposed proof-combination operation. |
| Sapling `SpendProver` and `OutputProver` | Separate low-level circuit preparation, proof creation and proof encoding interfaces exist. Their proof type uses BLS12-381; note/value commitments use Jubjub. | These are concrete reusable component boundaries. They are not current BN254 KAS relations, and their native cost/support must not be assumed. |
| Sapling PCZT `Bundle::create_proofs` | Unconditionally loops every spend and every output, obtains their private fields, and overwrites each proof field. | A PCZT with foreign pre-existing proof bytes does not make this high-level call selectively owner-local. A separate exact insertion/combination contract is needed. |
| Orchard/Sapling `finalize_io` | Requires every component rcv, sums them into a binding secret and checks it against public commitments. | The high-level finalizer is not a private secure-sum protocol. Removing one rcv causes `MissingValueCommitTrapdoor`. |
| PCZT `Combiner` | Merges compatible optional fields for the same transaction; conflicting values fail. | Combining records does not prove missing private statements, unlink submission provenance or securely aggregate blindings. |

Pinned primary code:

- [Orchard prover](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/pczt/prover.rs),
  Git blob `6e3c8d2a3fe5db50238eda6bd6d287c901e936f8`.
- [Orchard IO finalizer](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/pczt/io_finalizer.rs),
  Git blob `6b591125251fcdfce5624c9c1a84b2ae67afb826`.
- [Sapling component prover interfaces](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/prover.rs),
  Git blob `36dee36aaf271fb66742c522238ce8d04a3b731b`.
- [Sapling PCZT prover](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/pczt/prover.rs),
  Git blob `7aa9e6d26a9e3dbb8d616efb162a81349c988a19`.
- [Sapling IO finalizer](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/pczt/io_finalizer.rs),
  Git blob `1a3a93cf142571d36ade0001b638f750e11957e4`.
- [PCZT IO finalization](https://github.com/zcash/librustzcash/blob/146a08fc779678f6b81997da5f9b7c3378ffccb9/pczt/src/roles/io_finalizer/mod.rs),
  Git blob `3c23f22f0b319d651a42b490c902d0f96ecd0470`.
- [PCZT combining](https://github.com/zcash/librustzcash/blob/146a08fc779678f6b81997da5f9b7c3378ffccb9/pczt/src/roles/combiner/mod.rs),
  Git blob `c01b2b5a1be5d3fd78c20fcb78e5be635a109d32`.

These files were fetched from the official repositories during this review.
The exact commits are the research dependency selection; no moving branch is
substituted for an execution dependency.

There is a concrete lower-level reassembly seam: Sapling's public
[`Spend::parse`, `Output::parse` and `Bundle::parse`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/pczt/parse.rs)
accept proof-bearing records with optional private fields absent, and an
externally supplied canonical binding-key scalar. Its
[`TrapdoorSum::into_bsk`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/value/sums.rs)
is the actual scalar-to-Binding-key conversion used by the ordinary finalizer.
The [signer](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/pczt/signer.rs)
can apply an externally generated signature after checking its randomized key
and supplied digest. Thus the high-level failures are not an impossibility
result for a separately constructed low-level Sapling integration.

Parsing/extraction must not be mistaken for final validity. The transaction
[`extractor`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/pczt/tx_extractor.rs)
assembles proof bytes and a binding signature; it does not establish
that the Groth16 proofs are valid or that a supplied binding key matches the
commitment-derived verification key. Full standard proof/binding verification
is a separate required consumer boundary. A source-level external-scalar API
does not resolve the protocol-level consequences of making that scalar public.

## A binding contribution can itself reveal the partition

This is an algebraic construction attack, not a claim of a vulnerability in
Zcash. Write a value commitment as `CV = v*V + r*R`, using the established
independent generators and subgroup arithmetic. Suppose the assembler knows
which spend components belong to owner i and its public fee allocation f_i.
If it also receives that owner's blinding difference
`beta_i = sum(r_spends_i) - sum(r_outputs_i)`, it can enumerate candidate output
subsets T and compare:

```text
sum(CV_spends_i) - sum(CV_outputs_T) - f_i*V == beta_i*R
```

For the owner's actual value-conserving output subset this is exact. A scalar
beta_i or its public group element therefore supplies a partition certificate
without exposing a note opening or solving a discrete logarithm. For a small
batch, enumerating subsets is cheap. Collisions or alternative assignments must
be reported, not assumed absent.

A generic FROST replacement is not established by saying that secret keys stay
distributed. In particular, directly making each owner's beta_i a DKG dealer's
constant coefficient can publish beta_i*R in a Feldman commitment. Ordinary
FROST verification shares after a genuine resharing are not necessarily those
original contributions; the exact DKG and public transcript must be inspected.
Using a default DKG instead generates a key unrelated to the required value
balance. Both points rule out a casual API substitution, not distributed signing
as a research area.

The actual [FROST DKG](https://github.com/ZcashFoundation/frost/blob/0966bd1529aa062ad3b621af99e277f976b1c0f0/frost-core/src/keys/dkg.rs#L359-L397)
generates a new random signing key and publishes coefficient commitments;
Git blob `bdef0790107e61148972aacb580834c659eb0165` was checked. The current
[RedDSA key parser](https://github.com/ZcashFoundation/reddsa/blob/04e973bcf8d46819db055ebd0d44304c24a156a4/src/verification_key.rs#L103-L111)
allows identity/small-order verification keys, with spend-key restrictions
handled separately. Thus a zero aggregate binding key is not itself a
source-level incompatibility; ValueShuffle nevertheless uses a released
aggregate offset, not an assumed zero offset. Neither fact settles the proposed
public-offset/binding-signature composition.

The narrow requirement is to expose an authorized global balance result while
keeping each owner's contribution and output membership hidden from the
assembler and permitted colluders.

## Established construction: what ValueShuffle contributes

[ValueShuffle, FC2017](https://fc17.ifca.ai/bitcoin/papers/bitcoin17-final6.pdf)
combines confidential commitments and one-time output addresses with DiceMix.
Its construction includes a masked secure sum of input/output blinding
differences, so participants reveal the aggregate offset rather than each
owner's difference. Owners check the whole transaction and their own outputs
before signing. Failed runs expose blame information; subsequent outputs must
be freshly generated. The paper's underlying CT inputs are publicly identified
UTXOs, so hidden-membership KAS adaptation is a separate obligation.

| Phase | Local owner data and exchanged messages |
| --- | --- |
| Establish run | Authenticate participant/session keys and derive separate pairwise pads for mixing and summation. |
| Prepare | Produce fresh confidential output tuples and retain their openings locally. |
| Commit/exchange | Commit to anonymous mixing vectors and masked blinding-sum messages, then exchange them. |
| Resolve/check | Recover mixed tuples and only the global offset; verify balance, proofs and own-output inclusion. |
| Authorize/retry | Sign the exact result; otherwise blame/exclude disruptors and regenerate outputs for another run. |

Retrieved PDF: 579,603 bytes, SHA256
`5b5217e0641211e53434d6372ac516ba9f7e43ea80a527d97ae55a130b3cde6f`.
Pages10–12 and15–18 contain the relevant construction. The browser PDF fetch
timed out after its initial extraction; the same official PDF was downloaded
over HTTPS and extracted with a temporary `pypdf==6.1.1` parser outside the
repository. No source/protocol dependency was installed into the project.

### Exact candidate boundary for KAS review

The following is a proposed adaptation contract, not implemented cryptography
or a claim made by the existing KAS code:

1. Each owner prepares independent spend and output components with established
   note-membership/authorization, range and encryption rules. It supplies no
   seed, plaintext note, Merkle witness, individual output set or per-owner
   blinding difference to the assembler. Public participation may remain visible.
2. A complete anonymous-mixing protocol carries fixed-length output components,
   including the exact commitments, ciphertexts and output proofs. Uploading
   those same components through labeled connections before mixing would defeat
   the objective. Fixed receipts, hashes, purpose tags, per-owner cardinalities
   and retained retry identifiers belong in the observer transcript.
3. A separate masked secure-sum result gives only the aggregate blinding offset.
   In an explicit sign convention, define
   `beta_i=sum(r_spends_i)-sum(r_outputs_i)`. Pairwise masks cancel in
   `Delta=sum_i(beta_i+pad_i)`, yielding `sum_i beta_i`. Individual beta_i,
   beta_i*R and unmasked per-owner sum vectors must remain absent from the
   successful assembler transcript. At least two appropriate honest
   non-colluding contributors are necessary; participant count alone is not
   evidence of that condition.
4. Verify the global commitment balance against the exact public fee/native
   amount. This is not permission to expose a Sapling binding secret or replace
   its finalizer without review. The paper's public-offset CT contract and
   Zcash's binding-signature contract are distinct API/security interfaces.
   Their KAS composition needs one explicit, reviewed rule.
5. Every spender independently verifies the final complete financial body and
   its own obligations before authorizing it. The authorization digest must
   cover the selected network/domain, actual accepted predecessor, old/new
   states, entire NF/CM/cipher sets, native destinations and values, exact fee,
   proof/version roles and payload. A server-selected digest or arbitrary caller
   message is insufficient. All signatures must agree on that same body.

This arrangement is intended to remove direct construction grouping. It does
not by itself eliminate the declared arithmetic, invoice, sparse-history or
network participation attacks. A statistical privacy claim requires its own
subsequent frozen experiment with realizable owner worlds.

### Native obligations that cannot be delegated to the mixer

- Prove every real spend's ownership and hidden membership under the correct
  accepted anchor; preserve original positioned nullifiers. Check all NFs once
  against current spentness, including cross-owner duplicates and replay.
- Establish nonnegative integer sompi ranges and the absence of modular
  wraparound. Bind every output commitment exactly once, with no omission,
  duplication or unproved cipher replacement. Recipient delivery must remain
  recognizable/spendable from its own backup.
- Tie private commitment balance to actual native reserve, native payouts and
  exact fees. Accepted-state and native-body verification cannot be replaced by
  a mix server's success response. Cross-state/domain/lane replay must reject.
- Retain a unilateral exit from an accepted note when the mix, another owner,
  prover or server disappears. Unaccepted mixed outputs are not liabilities.
  Mixing failure must not consume real NFs or require an admin recovery key.
- Publish sufficient accepted CM/cipher/NF/history and exact software/parameters
  for backup recovery. Missing/reorged data yields INCOMPLETE, not an invented
  empty balance. No transport or mix transcript selects financial authority.

The current inline verifier and private relation are not these independent
Sapling component verifiers. Curve/proof/native execution compatibility,
setup/parameter provenance, byte costs and low-demand fees remain unmeasured
for this candidate. Existing W fee measurements do not transfer to it.

## What maintained mixing code actually offers

Official [Decred CSPP](https://github.com/decred/cspp/tree/9fa40f7e22ba1a0168f38221aff1b2d1ef042c85)
was observed at commit `9fa40f7e22ba1a0168f38221aff1b2d1ef042c85`.
Its [README](https://github.com/decred/cspp/blob/9fa40f7e22ba1a0168f38221aff1b2d1ef042c85/README.md)
states that its CoinJoin configuration shares ordinary inputs/change with the
server and restricts anonymous outputs to equal values when blame/retry is
used. That is not our confidential-variable-value construction.

The actual [`GenConfirmer` / `Session.DiceMix` interface](https://github.com/decred/cspp/blob/9fa40f7e22ba1a0168f38221aff1b2d1ef042c85/dicemix.go)
uses `MessageSize=20`, sends an unmixed marshaled record in its pair request,
and relies on each client checking its own result. Source blob:
`11b39bc449859bab3d4fd51dadefcc43db3d3af0`. Mixing a 20-byte hash does not hide
the provenance of a larger output component previously uploaded through a
labeled connection. Supporting complete KAS output tuples and the masked scalar
sum requires a reviewed integration, not simply changing the output order.

The newer official [dcrd mixing tree](https://github.com/decred/dcrd/tree/3360ae4dbef8ccfd5880016cadd03a41af0aad9f/mixing)
was observed at commit `3360ae4dbef8ccfd5880016cadd03a41af0aad9f` (2026-10-19).
Its actual [CoinJoin constructor](https://github.com/decred/dcrd/blob/3360ae4dbef8ccfd5880016cadd03a41af0aad9f/mixing/mixclient/coinjoin.go#L20-L70)
still has `msize=20` and accepts an ordinary `wire.TxOut` change output,
`mixValue` and message count; blob `379a7980d988d8a4dddac5a3925b3bf1581c2651`
was checked. This is a maintained implementation lineage and a concrete typed
interface to adapt, not existing native-KAS or ValueShuffle support. The older ElementsProject/dicemix
API URL redirects and the old documented protocol file was not readable via
the connector; it is not silently treated as a current usable API.

The prior [MWEB experiment](../independent-payments/privacy-components/recipient-extension/RESULTS.md)
retains a useful owner-local confidential-component precedent, but exposes
spent output IDs and preaggregation mappings. It remains rejected as a direct
substitute for hidden-membership notes. RAILGUN's selected public joinsplit
signals retain transaction-local NF/output partitions, as recorded in the
[source review](../independent-payments/privacy-next/DECISION-NEXT.md).
These are component comparisons, not privacy qualifications.

## Smallest decisive existing-library experiment

Proposed scope before any new circuit or protocol implementation:

1. **Actual PCZT API failures.** Construct public test-only component records
   through the selected upstream parsers. Retain a component with a proof field
   but without its private prover fields. Call the real high-level prover or
   finalizer and record the exact missing-field error. A panic-on-use RNG and
   mock proof backend can prove that failure precedes RNG/proof work; any mock
   bytes must be labeled non-proofs and never counted as valid transactions.
   Include a positive redacted-record parse/reassembly control: the point is
   the high-level method's witness requirements, not claiming that all
   component assembly is impossible. Also retain an extracted wrong-binding-
   key control that fails the actual public commitment-derived binding equation;
   extraction alone is not acceptance. This needs no proving parameters or
   genuine Groth16 generation.
2. **Actual-curve partition control.** Use the upstream Sapling value commitment
   implementation and public synthetic values/blindings. Expose one owner's
   beta_i or beta_i*R, enumerate fixed-cardinality output subsets, and retain
   every exact matching subset. Permute outputs and repeat the same attack;
   permutation is not success if the certificate still matches.
3. **Masked-transcript boundary.** Before implementing an adapter, map every
   successful and failed-run message in the chosen existing mixing and secure-
   sum code to the observer. Test a complete tuple, two independently source-realizable honest
   executions/distributions, all-but-two collusion, all-but-one collusion, an
   abort/retry and selective output omission. Two different openings of one
   binding commitment are not admissible alternate worlds. A hand-written shuffle or one masked-sum toy
   does not stand in for a successful established protocol execution.

Stop if a missing private input requires witness collection, a labeled
submission or binding contribution restores the partition, a complete tuple
has no supported, reviewed full-message adaptation, or the native conservation/ownership/
spentness/recovery obligations have no concrete implementation seam. Preserve
that failed API/control; do not fill the gap with a novel primitive.

The experiment can close an implementation-feasibility question or reject a
candidate. It cannot qualify financial privacy, production security, fee
targets, an accepted KAS transition or independent long-term recovery.

## Executed bounded result

The [actual ADR0061 gate](RESULTS.md) now exercises those API and existing-curve
boundaries. The high-level calls require missing private fields even with proof
bytes present. Exposed per-owner binding contributions identify all three exact
output groups despite permutation. Redacted component assembly and the correct
aggregate Binding equation pass; wrong aggregate keys can assemble but fail
actual public Binding verification. No genuine Groth16 proof or valid
transaction is claimed. The complete ValueShuffle/message/native composition
and original privacy qualification remain open.
