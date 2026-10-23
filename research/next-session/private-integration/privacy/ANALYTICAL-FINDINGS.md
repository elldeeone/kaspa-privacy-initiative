# Candidate C: privacy findings before execution

**Status:** analytical pre-execution findings on the proposed recipient design.
No privacy evaluation, protocol runtime, proof, funding or broadcast was run to
produce these conclusions. The proposal is not a qualified private-payment
system; [the contract](CONTRACT.md) specifies a narrower screen awaiting review.

## 1. Domain-stable incoming links otherwise fresh invoices

The current proposed interactive invoice contains
`D,index,O,incoming,K,native_PK`. Its per-index O/K/native_PK can all differ while
incoming is the same domain-level encryption public key. Anyone obtaining two
invoice records can test incoming equality without a cryptographic attack.
With a known mapping for one invoice, the observer learns the recipient of the
other invoice under the design's assumption that the receiver controls that
delivery key. Equality alone establishes shared key control, not a legal name
or a count of independent people; a declared directory supplies the owner label.

The private-transfer chain ciphertext wrapper does not expose incoming in the
proposed design. Do not give the chain-only observer invoice fields it does not
possess. However, the [native integration proposal](../native/INTEGRATION-PROPOSAL.md)
also considers public hash-only ADMIT with O/incoming/K/native_PK/rho/V in its
ingress witness to avoid an admission proof. If adopted, this gives C incoming
at deposit: a later private-receipt reveal carrying the same incoming links to
that public admission and funding ancestry even without an invoice directory.
This is a source-level conditional finding, not an executed ADMIT measurement.
Conversely, candidate C revealing witnesses contain incoming. Repeated revealing
openings are consequently linkable by C even when O/K/native_PK are unique.
A sender or directory observer knowing one invoice-to-recipient association can
label later matching reveals. Sealed-box ciphertext randomization does not
remove equality of the separately revealed destination key.

This is an explicit privacy/recovery tradeoff of the proposed stable delivery
key, not evidence that all reusable addresses must leak. Orchard hides its
shielded destinations in transactions and supports diversified addresses;
MWEB uses a different curve-based reusable destination construction. Their
properties are not inherited by candidate C. Sources:
[Orchard keys](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/keys.md#L69-L78),
[MWEB stealth addresses](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/stealth-addresses.md#L1-L4).

## 2. Reusing k exposes NF linkage over the complete public CM set

Candidate C defines

```text
NF = HMAC-SHA256(k, NF_TAG || D || CM || u32LE(position)).
```

After a pending, rejected, accepted or later orphaned reveal publishes k, an
observer can evaluate this expression over every public CM and its position.
Matching those results against public NFs identifies spent notes sharing k.
The observer need not know the matching note's opening or K, and can recognize
future matching spends. Uniqueness of native payout keys does not stop this
channel. Keeping s private protects a separate authorization obligation; it does
not make the exposed NF relation private.

Therefore per-invoice derivation and receiver verification of k/K are required.
A sender-selected k, reused invoice, or accepted duplicate with shared k can
break isolation. A receiver may flag/quarantine a malformed receipt, but cannot
erase a liability already accepted into the reserve. Privacy rejection and
backing/recovery accounting are separate obligations. These are inferences from
[the exact candidate encoding](../../../../poc/future-exit-feasibility/src/main.rs)
and [the candidate review](../../exit-fee/ARCHITECTURE-OPTIONS.md), not a claim
about Orchard's distinct [nullifier construction](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note/nullifier.rs#L67-L74).

## 3. Orphaning an exit cannot restore the note's old privacy

Let an observer state be the union of all previously transmitted records. A
revealing witness adds `(CM,position,k,opening)` to that union before inclusion.
A rollback can remove the chain's spend and restore the note to unspent state;
it cannot remove the observer's earlier information. A later ordinary private
spend publishes the same canonical NF, which the observer can recognize.

This remains true with perfectly fresh per-note k: one-time derivation confines
the disclosure to that note but does not reverse it. A recovery client must not
label the restored note private merely because its emergency transaction was
orphaned. New transaction authorization and secret knowledge have different
rollback semantics. The two-secret design still needs its s guard after such a
rollback; private theft resistance is outside this observational screen.

## 4. Fixed private arity hides only the counter distinction

The current proposal is two NF insertions for private operations, including
constrained dummy slots, and one NF insertion for native reveal. The latter
distinguishes the public revealing branch, which is already declared public.
If both one-real and two-real private operations insert exactly two opaque NFs,
NF-count delta alone does not reveal which real arity occurred. It does not
prove dummy indistinguishability, ciphertext/output shape uniformity or timing
privacy. A publicly recognizable dummy or different CM/output counts reopens
the distinction. Counts/capacity must also remain sound for both branches;
privacy padding cannot excuse an unsupported liability or exhausted exit.

## 5. A revealing exact-note payout discloses that note's historical value

Whole-note reveal enforces `V = payout + fee` and publishes V anyway. For a
historical ordinary payment target whose amount is authenticated to equal that
note's V, the later observation horizon has exact amount disclosure. Calling
the native payout intentionally public does not erase this historical target.
Where the note combines or splits value, no unique economic allocation follows
without additional constraints; report the uncertainty rather than inventing
one. Participant-known payment amounts and public exit values require separate
eligibility exclusions. Sources: [RFC-0012 historical horizons and gates](../../../../docs/rfc/0012-useful-privacy-requirements.md)
and [the fixed candidate accounting](../../exit-fee/TERMINAL-ACCOUNTING.md).

## Qualification remains open

These direct disclosure channels cannot be fixed by more samples or GPU time.
They require an explicit format/trust/leakage decision, followed by tests of the
implemented bytes. No new privacy target is adopted here. The previous
common-price workload's `21103/100025` prior-only accuracy exceeds the unchanged
20% amount gate even with no transcript leakage; [that retained failure](../../../privacy-target-consistency-2026-10-22.md)
is unaffected. The 32-role C/P/A qualification, network observations, recipient
encryption/privacy analysis and full drainage horizon remain open.
