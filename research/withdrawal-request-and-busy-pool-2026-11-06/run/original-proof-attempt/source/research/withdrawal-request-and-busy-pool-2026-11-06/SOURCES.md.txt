# Withdrawal requests, busy pools and proving: source record

Reviewed 6 November 2026. **Decision supported by the sources:** keep the existing
whole-set withdrawal relation; test anonymous submission of eligibility as well
as output registration, then measure stale approvals and the existing immutable
verifier-key optimisation. These are application/wallet/prover changes on the
current L1. No consensus change, MPC, new asset, privileged exit key, real funds
or mainnet deployment is proposed. This is source/design evidence, not an
executed transport, active-pool or speedup result.

Read first: [project status](../../docs/PROJECT-STATUS.md), the
[privacy](../../docs/research-knowledge/privacy.md),
[proof](../../docs/research-knowledge/proofs.md) and
[reuse](../../docs/research-knowledge/reuse.md) guides, and the existing
[result](../batched-payment-costs-2026-11-06/RESULT.md),
[review](../batched-payment-costs-2026-11-06/REVIEW.md) and
[sources](../batched-payment-costs-2026-11-06/SOURCES.md).

## Smallest useful privacy change

The current [issuer](../../poc/batched-payment-costs/host/src/registration.rs)
accepts an index in a predeclared three-claim roster and logs `owner(index)` next
to the economic nullifier, exact exit value, eligibility proof and blinded
request. Its cryptographic check needs authority over an eligible unspent note,
correct round/context/value, and one issuance per note; it does not need a human
name. **Design inference:** replace the identified roster API with verified
note eligibility and duplicate-nullifier admission, submitted anonymously. Do
not merely remove `owner` from an otherwise identified service log, or erase an
owner/nullifier map that another retained interface already disclosed.

Reuse the genuine RFC 9474 randomized SHA-384/PSS library and existing separate
issuance/redemption phases. Keep one expected issuer key/mode per round, fresh
client randomness, canonical round/denomination/key messages, verification after
unblinding, duplicate prevention and the issuance barrier. The RFC provides
cryptographic blindness under its assumptions; it supplies neither anonymous
transport nor a hidden amount. Its signing key must be exclusive to the selected
protocol/encoding. Issuance must not receive the randomizer or plaintext recipient
message. A signer can deny coordination; no signer credential authorizes KAS
release. [B1], [B2], existing [registration source](../../poc/batched-payment-costs/host/src/registration.rs).

Use an actual Tor onion service and SOCKS5 client as the established transport
candidate. Onion traffic is authenticated/encrypted to the service and remains
inside Tor; the coordinator still sees application messages and their arrival
times. SOCKS must receive the hostname, rather than locally resolving it. The
current Tor spec recommends username `<torS0X>0` and a fresh password isolation
token; this also has the intended isolation effect on older implementations.
Distinct eligibility, redemption, polling and approval contexts need distinct
tokens/connections and no cookies, owner aliases or application session handles.
Check isolation is enabled and prohibit silent direct-network fallback. [T1],
[T2], [T3] (transport requirements are design inferences from these interfaces).

WabiSabi is a useful phase/identity reference: separate input, output and polling
roles; common round parameters; each owner checks the complete transaction
before signing; one input/output per network identity; fresh identities after
failure. Its own specification assumes traffic-analysis protection and warns
about amount/script/address reuse, Sybils, targeted failure, intersection and
timing attacks. **Adapt those separations and controls; do not import its
credential system, Bitcoin custody or blame policy.** RFC 9474 is sufficient for
this fixed-denomination coordination experiment. [W1]

## What anonymous transport cannot establish

Tor does not defend against an observer correlating both ends' timing; stream
isolation does not create independent honest participants. Do not score a
same-host test as global network anonymity. [T3], [T4]

Retain every service timestamp, request size, nullifier/context, round membership,
retry decision, native output amount and legitimate counterparty disclosure.
Score at least: operator logs alone; operator plus known deposit/payment facts;
one participant; all-but-one participants; and an observer with client-side timing.
Fixed public phase windows can remove immediate issue/redeem order, but are no
proof that latency patterns or selective aborts are harmless. Repeated rounds
with overlapping groups can narrow a user's possibilities. A known old payout,
reused key or known owner/nullifier remains known. Unequal payouts can identify
their owners even when cryptographic registration remains blinded. [W1], [A1],
[T4], existing [privacy corrections](../../docs/research-knowledge/privacy.md).

Count owner-to-payout assignments **and complete payment facts**. A permutation
of three equal keys is not three independently plausible financial histories.
Measure late remainder exits and later key disclosure as additional observations;
never delete the earlier public record to improve the score. This follows the
existing [result's scoped claim](../batched-payment-costs-2026-11-06/RESULT.md)
and [I-16](../../SECURITY-INVARIANTS.md).

## Busy pool and dropout test

The existing [effects context](../../poc/batched-payment-costs/common/src/lib.rs)
hashes the exact bank root, predecessor outpoint, input value and every output.
The joint authorizations bind that hash. Therefore an unrelated accepted update
can make them stale while their economic nullifiers remain unspent. Native
proof/current-state binding must stay intact. [K1], local source (inference).

Freeze a four-wallet fixture: three intended equal-value withdrawals, while a
fourth wallet performs a real unrelated private self-transfer. Exercise arrival
before approvals, during approvals and during outer proving. Assert old-state
refusal, unchanged funds on failed application, current-NF replay refusal and
successful fresh authorizations against the successor. Record discarded wallet
proofs, outer cycles/time, queue delay and native fee quotes separately.

For dropout: retain the missing-approval safe halt; retry under a fresh round,
key and anonymous identities; exercise the existing independent solo exit.
Never keep a two-person joint route's three-person anonymity score. Include
selective abort/retry logs and observer knowledge across rounds. If modest
activity repeatedly wastes complete proofs, report the observed limitation;
do not loosen the exact native context to force success. These are proposed
tests, extending the existing [adversarial review](../batched-payment-costs-2026-11-06/REVIEW.md).

## Existing proving optimisation to adapt

[Private-note-chain common](../../poc/private-note-chain/common/src/lib.rs)
already hashes and checked-decodes the canonical compressed key before pinning;
its [native generator](../../poc/private-note-chain/host/src/main.rs) serializes
validated uncompressed bytes. The zkVM loads those immutable program bytes
without repeating subgroup validation, reserializes/hashes them and checks arity.
The program image binds the embedded data. Submitted proof points remain checked
and canonical in the [accelerated verifier](../../poc/accelerated-bn254/common/src/lib.rs).
The current batched guest instead checked-decodes its dynamic compressed wallet
key in every proof. These are existing implementation facts, not a new primitive.

Adapt this path to the **digest-packed relation's arity three**, rather than
copying the old relation's arity fifteen. Validate the original key with full
consumption and canonical re-encoding before building; bind its digest to the
ledger and every operation, preserve submitted-proof checks, and independently
bind the new guest image in native validation. Never apply unchecked decoding
to service-supplied keys or proof points. A changed pin/image is a new artifact,
not permission to accept an old proof under a different program.

Minimum comparison: identical accepted operations/effects under dynamic and
pinned variants; equal journals/state/principal/fees; wrong key/digest/arity,
trailing bytes, malformed/identity/subgroup proof points and changed public
inputs reject at the intended layer. Keep stale outpoint/root, changed output,
payload, nullifier replay and native-image controls. Measure complete genuine
outer receipts, cycles, peak memory and wall time on the same hardware/settings;
the earlier ~18-minute work is a baseline, not a guaranteed saving. No reduction
is priced until that complete comparison passes. Source contracts: local files
above and [proof guide](../../docs/research-knowledge/proofs.md).

## Current upstream checkpoint and reuse boundary

Official GitHub heads were resolved read-only on 6 November. Decisive files were
read at these pins; the earlier [replacement review](../common-set-withdrawal-2026-11-05/SOURCES.md)
and [five-protocol review](../native-kas-shielded-value-sources-2026-11-03.md)
remain the detailed mechanism record. All heads below match that review except
Aztec, whose privacy-considerations file was refreshed at its newer head.

| Source / exact commit | Reused or adapted; excluded |
| --- | --- |
| Kaspa docs `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` [K1] | Exact program/state/effects binding; no new verifier tag or output format. |
| rusty-kaspa `4863866fce8439d0305b410fc4d802e7261d54d0` [K2] | Existing native verifier/transaction ABI; no consensus patch. |
| vprogs `f9b84a863a7c7c20586a9cf947550475e894f72e` [K3] | Prototype/runtime reference; no requirement to add its whole runtime. |
| kaspanet/research `c923faca11a49148fa7d912d27ce00197a5c5a4a` [K4] | Ordered state/accounting reference, not a deployed implementation claim. |
| Orchard `616a669df8c9a59c33d47064d3ce04b25d026b2e` [O1] | Membership, nullifiers, balance and effects as separate obligations; exclude native Halo2/Pasta rules. |
| Aztec `c03bf6c776bcef428e9247fff8a5c385ab7ae994` [A1] | Timing, public-boundary and query metadata review; exclude its L2/PXE runtime. |
| RAILGUN `36bcf5ed7cf94bfafb6e1a303e1832c769c16780` [R1] | Validate/nullify before release; public unshield disclosure; exclude EVM custody/admin powers. |
| Monero `b14fae7bca4099cea56205e44c1005602834b7bd` [M1] | Bounded balance plus separate authorization/spentness; exclude native RingCT/CLSAG consensus. |
| Litecoin `ec1b6489a900d09cf5991e220dce089c77a232a2` [L1] | Explicit reserve/peg-out accounting; exclude extension-block consensus and forced maturity. |
| WabiSabi `1e6deb989f58bc6edce91bc300252d2bed18db30` [W1] | Phase and network-identity separation only; no new credential architecture. |

A matching head is source freshness, not a security audit, deployment match,
accepted-chain proof or full rereview of every repository. Any successful local
test must keep these distinctions and the existing independent-recovery,
fee-allowance and public-history availability limitations.

## Primary references

[B1]: https://www.rfc-editor.org/rfc/rfc9474.html#section-7
[B2]: https://github.com/jedisct1/rust-blind-rsa-signatures/blob/640084d82abd5bbe48c65c3d8e6f647c8963ec73/src/lib.rs
[T1]: https://community.torproject.org/onion-services/overview/index.html
[T2]: https://spec.torproject.org/socks-extensions.html
[T3]: https://spec.torproject.org/path-spec/stream-isolation.html
[T4]: https://support.torproject.org/about-tor/security/attacks-on-onion-routing/
[W1]: https://github.com/WalletWasabi/WabiSabi/blob/1e6deb989f58bc6edce91bc300252d2bed18db30/protocol.md
[K1]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx
[K2]: https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/crypto/txscript/src/zk_precompiles/tags.rs
[K3]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md
[K4]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex
[O1]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/bundle.rs
[A1]: https://github.com/AztecProtocol/aztec-packages/blob/c03bf6c776bcef428e9247fff8a5c385ab7ae994/docs/docs-developers/docs/resources/considerations/privacy_considerations.md
[R1]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunLogic.sol#L312-L357
[M1]: https://github.com/monero-project/monero/blob/b14fae7bca4099cea56205e44c1005602834b7bd/src/ringct/rctSigs.cpp#L1358-L1540
[L1]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/consensus.md#L101-L163
