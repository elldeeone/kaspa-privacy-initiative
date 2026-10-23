# Future private payment relation

**Core coding authorized by ADR0041 and the reviewed NOTE-STATE-CONTRACT.**
New-format synthetic DO_NOT_FUND research only. The full relation has been synthesized and checked; fresh setup/proving is
owned by the separately authorized lifecycle harness, not duplicated here. The selected domain is
`9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c`. This is separate from the immutable old note
formats, keys, public reveal experiment and parked owner/replay workflow.

The module exposes the private ownership/conservation relation behind a
small interface and emit the standard BN254 Groth16 format accepted by the
native verifier. It imports no Kaspa native engine, wallet, service, SDK
prover or old proving material. Root owns the ADR, instance identity, setup
release and complete native integration.

## Shared bytes

The reviewed architecture contract selects the exact candidate-C SHA256/HMAC
hash formulas and tags, a fresh domain and new state/authorization framing:

- Note168: `O32 || incoming32 || V_u64LE || rho32 || K32 || nativePK32`.
- O=`SHA256(KPX1OWN\0 || D || s32 || incoming32)`.
- K=`SHA256(KPX1KEY\0 || D || k32)`.
- CM=`SHA256(KPX1NOT\0 || D || Note168)`.
- NF=`HMAC-SHA256(k32, KPX1NF\0\0 || D || CM32 || position_u32LE)`.
- CM leaves are **raw CM32**, folded with
  `SHA256(KPX1CMN\0 || left32 || right32)` at depth16. Empty leaf is
  `SHA256(KPX1CME\0)`. The old v6 `SHA256(0 || CM)` leaf is not reused.
- Dummy NF=`HMAC-SHA256(dummyKey32,
  KPX2DMY\0 || D || dummySeed32 || slot_u8)`; fixed slot order0 then1.

The Auth484 transcript is:

|Offset|Bytes|Field|
|---:|---:|---|
|0|8|`KPX2AU01`|
|8|32|domain|
|40|36|actual prior outpoint: raw txid32 plus index_u32LE|
|76|112|prior state|
|188|8|actual prior reserve_u64LE|
|196|8|explicit fee_u64LE|
|204|64|NF0 then NF1|
|268|64|output CM0 then CM1|
|332|32|SHA256 of exact two ciphertexts|
|364|112|derived next state|
|476|8|derived next reserve_u64LE|

State112 is `KPX2ST01 || D32 || CMroot32 || n_u32LE || NFroot32 || m_u32LE`.
SHA256(Auth484) maps to two public scalars using its first and last16 bytes as
**little-endian128-bit integers**, preserving all256 bits without modular alias.
The native module must reconstruct the same transcript from the real transaction;
a prover-selected transcript alone is not authenticated context.

## Relation and visible assumptions

Private SPEND only: two fixed input slots, at least one real, exactly two public
NF slots, and two output CM appends. No private admission or public payout mode.
A real input proves both s and k, exact note CM, membership at its position in
the prior CM root, and the exact positioned NF. The same position supplies the
Merkle directions and HMAC bytes. Real positions are distinct; public NFs are
distinct and nonzero. Input padding canonicalizes the entire note, s/k, position
and path to zero, and separately constrains its dummy HMAC. Real input dummy
credentials are zero; generating padding credentials uses a caller-supplied
cryptographic RNG.

For outputs the sender knows descriptor O/incoming/K/nativePK, value and fresh
rho; it **does not know or prove the recipient's s or k**. A positive value is
at least60M sompi. A zero-valued output has O/incoming/K/nativePK zero and fresh
private rho, avoiding a publicly constant dummy CM. At least one output is
positive; the two output CMs differ. The recipient must first decrypt locally, then derive/validate the entire
descriptor from its own backup and receipt index before crediting a received
note, including the committed native key, and recompute CM. The circuit does not
prove encryption correctness or native-key secret ownership for a recipient.

All amounts are integer sompi. MAX is2,870,000,000,000,000,000; fee is1..MAX.
Use bounded u64 variables/slacks and field equalities, not wrapping arithmetic:
input sum<=MAX, input sum<=actual reserve, input sum=output sum+fee, and
Rprime=R-fee with60M<=Rprime<=MAX. State counts obey n<=65535 and m<=2*n+1,
where m includes the NF sentinel and has **no parity rule**. Private transitions
append two CMs and insert two NFs; n+2<=65535 and m+2<=131071. The native module
must authenticate and apply every current indexed-NF insertion and CM append,
bind actual outpoint/reserve/fee/next policy, and preserve backing. The circuit
binds those exact prior/next bytes without substituting a host verdict for their
native checks. Shared current NFs are what exclude a subsequent reveal/private
spend; private membership alone does not establish current unspentness.

## Interface

- `Note::{parse,bytes,commitment}`, and standard host owner/key/NF hash helpers.
- `Authorization::{parse,bytes,public_inputs}` for exact canonical Auth484.
- `InputWitness` and `TransferCircuit` with a `check` returning measured size and
  satisfaction. The selected instance/domain is fixed and constrained as DOMAIN in source.
- Fresh `setup` with a caller RNG, `prove`, and a fully checked
  `Verifier::new(trusted_vk328)` / `verify(auth, proof128)`.

Native/public descriptor consumers should cross the byte interface, not import
private witnesses or prove a sender knows recipient secrets. The root-selected
VK/domain must be trusted outside submitted proof bytes. Key/proof decoding
uses established checked Arkworks canonical deserialization, full consumption,
roundtrip and point/arity checks; no invented verifier arithmetic.

## Reuse and measured resource gate

Use pinned Arkworks0.6.0 BN254/Groth16/gr1cs/SHA256 gadgets. Adapt the small
owner/hash/HMAC, constrained position, bounded-sum and public-digest helpers in
`poc/shared-pool/src/two_input/circuit.rs` (SHA256
`59071901c3abc25daab68c982ef065f8755c09abbb2ce30e6010d821813dd2a7`).
Do not copy its modes, old note/tree encodings, setup or native policy. Earlier
`poc/private-note-wallet` is Arkworks0.5 and is a conceptual comparison only.

Source review found these reusable-gadget limits: Boolean gates suppress
relations, not SHA/HMAC synthesis; require exactly32-byte HMAC keys; convert
only explicitly bounded u32/u64/128-bit fields; avoid the registry's problematic
conditional-not-equal helper and use `is_eq` then guarded equality-to-false.
Neither wrapping nor saturating UInt64 addition proves conservation.

The retained old two-input relation has4,372,824 constraints and109 SHA blocks,
with prior proving peak6.44GiB. The new relation measured **4,650,533 constraints**,
4,612,281 witness variables and two public inputs plus the constant-one variable.
The selected V2 one-real+padding sizing vector is satisfied. Full synthesis and
checking took 42.27 seconds under4CPU/12GiB/swap0, with 1,080,448 KiB process RSSpeak.
Its transcript-bound NF/next-root placeholders are not a native-positive fixture.
See [the measured result](evidence/measurement-01/result.json).

Eight cheap unit/cross-language checks passed. All17 prospectively selected
full-R1CS mutations are unsatisfied, as required: wrong s/k, copied k without s,
padding, paths/position, real/dummy NF, output CM, subfloor/overflow, domain,
fee/reserve and count capacity. The serial suite took 263.03 seconds at2CPU,
with 1,080,352 KiB RSSpeak and no swap; resource errors did not count as rejection.
See [the exact cases](evidence/controls-01/result.json). Production lib/circuit
bytes remained unchanged throughout. Both-real and dummy-output positive cases,
actual native roots/context, genuine parameters/proof and native verification
belong to the lifecycle harness before an integrated claim is made.

The new count still requires a2^23 evaluation domain, as did the old relation;
this is sizing evidence, not a measured setup/prove memory or latency guarantee.
Fresh setup/proving requires root's reviewed source/input/resource freeze, and
must not be duplicated by this module. No CUDA/alternative proving backend
detour is planned.

Forge launch convention is the existing user systemd unit plus read-only
source/tool/cache mounts, private target and temporary storage, network
isolation, explicit CPU/memory/swap limits, retained logs and owned-process
cleanup. Inspect `research/next-session/exit-fee/future-exit/build-03/build.sh`
for the existing source-only build arrangement. Compiled software remains local
with hashes; public sources, locks, selected vectors/proofs and logs are retained.

The existing primary-source comparisons in `research/{zcash-orchard,aztec,
railgun,monero,litecoin-mweb,kaspa-toccata-vprogs}.md` support separate spend/view
credentials, receiver reconstruction, positioned nullifiers, current spentness,
bounded conservation and explicit DA/fee assumptions. No restricted RAILGUN
circuit code or incompatible Orchard/Monero primitive is imported. This is a
new composition to review, not inheritance of those protocols' security results.

Required controls include wrong s, wrong k, copied revealed k without s,
wrong position/path/domain/context; amount/fee/aggregate overflow; duplicate NF
and real position; malformed framing/points; dummy semantics; output CM or
ciphertext substitution; and genuine proof verification under the exact selected
VK/domain. Native review separately covers shared-NF cross-path rejection,
actual-state binding and complete fees. Tests/proofs do not establish security.

A direct two-public-input Groth16 check already costs147,500 native mass grams.
One useful payment plus change cannot meet the existing10M reference100 fee cap.
A two-genuine-recipient/no-change trace under one payer can test a separate
economically relevant operating point. It must allocate actual native and
complete-lifecycle fees per useful payment; a change output is not a payment.
Batch/admission amortization, latency, witness availability and scoped financial
privacy remain separate requirements and may retain negative results.

The retained recipient V1 core-hash vector is explicitly named as such; it tests
unchanged Note168/O/K/CM/NF formulas only. Root-selected recipient V2 separates
opaque per-invoice incoming from the stable delivery key and uses Invoice208.
The final genuine proof fixture will use the new V2 values. This library does
not parse invoice objects or publish the delivery key.
