# Separate-agent composition review, 2026-10-18

**Four offline design blockers were corrected and passed focused re-review.
Unfunded offline wallet implementation may proceed with synthetic policy and
deposit fixtures.** No full wallet proof or native payout was implemented.

The owner selected a fresh-context separate AI reviewer under
[ADR-0019](../../docs/adr/0019-separate-agent-prototype-review.md).
Reviewer `/root/crypto_composition_review` shares the author's model/platform/host.
This is a separate-agent design review, not an independent human/external audit,
a proof of cryptographic correctness, or readiness for funds.

## Findings and disposition

| Finding | Correction | Current disposition |
| --- | --- | --- |
| C1: public CREDIT signature not bound to the proof journal | Canonical authorization bytes and a distinct SHA-256 digest become the final journal field; guest verifies those exact bytes, outer compares the complete expected journal | Design closed; public codecs tested; actual proof enforcement pending |
| C2: unclear pool/domain admission layer | Generic wallet binds all intent fields; proved outer authenticates immutable policy and compares all eight context fields plus the actual receipt image/parameters before selecting spentness | Design closed; outer enforcement pending |
| C3: first credit could lack an allowed anchor | Genesis admits the exact depth-32 empty Orchard root, then canonical post-operation roots | Design closed; independently computed root matches; state implementation pending |
| C4: conservation text omitted native entry/exit terms | Explicit boundary equation preserves authenticated single-consumption credit and unpaid backed exit liability | Exact reviewed invariant bytes applied; design closed |

C1 is a binding/correctness gap; the reviewer did not demonstrate theft or a
signature forgery. C2's high impact is conditional on omitting the required
policy checks. These are design findings against a candidate specification,
not exploits demonstrated against a complete wallet.

Read the [initial review](reviews/2026-10-18/initial-review.md) and
[focused re-review](reviews/2026-10-18/focused-rereview.md). The latter explicitly
approves the I-2 proposal, conditional on exact application. The
[application record](reviews/2026-10-18/invariant-application.json) confirms that
SECURITY-INVARIANTS.md now has the approved SHA-256
`35e180449636d24abe40a117fc291f6b897d1592fcdaa43ba795a40a4ca55331`.
Other invariants are unchanged. This satisfies that review condition.

## Checks and their limits

- Nine Rust/Python expected journals agree; original intent bytes are unchanged.
- Rust rejects 182 malformed authorization frames; Python rejects 191. Their
  corpora differ, so these are separate counts.
- 128 signature-byte mutations fail strict verification and change the journal.
  Python binds 209 context/authorization substitutions to different journal
  bytes. These checks establish byte binding, not immutable-policy rejection.
- The reviewer rebuilt the frozen Rust checker offline, reproduced its outputs,
  reran the Python checks and computed the exact genesis root using pinned
  Orchard. Earlier scope/key/value controls used public synthetic notes.
- The modified shared auth library still passes five published signatures and
  134 negative cases; libsodium signing/verification also matches five standard
  and nine CREDIT-tuple cases. Its point-validation API is not qualified here.

Reproduce the new public binding checks using fresh output paths:

```bash
cargo build --locked --release --manifest-path poc/private-payment/recovery-auth-vectors/Cargo.toml
poc/private-payment/recovery-auth-vectors/target/release/binding_vectors \
  poc/private-payment/vectors/intent-golden.json \
  poc/private-payment/vectors/rfc8032-ed25519.json NEW_BINDING_VECTORS.json
python3 poc/private-payment/check_public_binding.py \
  poc/private-payment/vectors/intent-golden.json NEW_BINDING_VECTORS.json NEW_BINDING_REPORT.json
```

Only published fixture keys are used; never fund them. There is no real wallet
guest/outer proof in these checks. In particular, a real receipt paired with a
second valid signature on the same intent, actual wrong-policy rejection,
first-credit state initialization, capacity, reorg and restored spentness must
be tested in their enforcing implementation layers.

## What remains

1. P2: implement the full wallet relation, complete recovery-secret inventory,
   fresh entropy handling and adversarial proof corpus; record actual program
   identities and proof-envelope leakage/receipt assumptions. Review that code.
2. P1/P3: qualify native key/principal/outpoint recognition and the finite
   bootstrap identity graph; implement proved outer admission, shared current
   spentness and total valid/invalid classification.
3. P4/P5: qualify authenticated lane witnesses, credit/refund ordering, paid
   markers, restored duplicate rejection, confirmed payouts and final reserve
   drain. External specialist review remains unavailable.

Full P1, real-private R13 and independently restored native R16 remain open.
Zero native transactions, no wallet funding and no mainnet or real funds.
No test-wallet top-up is needed for this offline work.

## Retained evidence

The [manifest](evidence/2026-10-18-agent-composition-review.json) indexes the
[review archive](evidence/2026-10-18-agent-composition-review.tar.gz).
It retains the exact original and fix snapshots with their manifests, both
review reports, public test vectors/checks, invariant disposition and applied
source snapshot. Reports refer to their original temporary task paths;
`original-inputs/` and `fix-inputs/` in the archive retain those exact inputs.
The applied source includes subsequent status/link updates; the reviewed
cryptographic helper bytes and approved invariant are unchanged.

No executables, compilation caches or funded secrets are included. The three
prior primitive/auth/node archives are unchanged and preserve the earlier
review checkpoint as historical evidence.
