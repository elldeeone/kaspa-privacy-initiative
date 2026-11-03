# Public two-action settlement gate

**Two independently generated private actions now settle through a genuine
compressed zkVM receipt accepted by the actual native wrapper in supplied
constructed contexts.** All five unchanged-proof tampering controls reject.
There is no accepted-chain, complete fallback or privacy qualification.
Unchanged-policy aggregation remains falsified.

## Fresh two-owner wrapper prototype

ADR59 selected a separate, unfunded wrapper. Each owner made their own fresh
compact private proof without exporting their note witness. Their exact public
records are joined by an8108-byte payload. Python, Rust host, native-body codec
and the selected zkVM guest independently reproduce the same424-byte journal,
SHA256 `057187fff69c8b6929ab9b2ecbe2347a325a803ab4bc32690ddb2a1045e44249`.
The actual guest executed107,317,810cycles in2.071s. Its genuine Succinct proof
took408.730s; established SDK compression took4.436s without rerunning the
guest. Independent SDK verification accepts the same selected image/journal,
with development mode disabled and no unresolved assumptions.

The [genuine native result](genuine-native-01/RESULTS.json), SHA256
`7b25030bc14498fb57a68da19e1cd3b8051403dfeff0f049be8b0d42f3e779e3`,
then inserts the verified128-byte receipt proof into the excluded signature
slot. The complete canonical public body, ID, mass, payload and journal remain
fixed. Actual native Full validation and its separate input engine accept the
real wrapper at15,646,440script units. Its exact native output is index0 of
`14a3ec5f3215b8186740584496a8762b02a916cccdf14be60925765e7b6c8d52`.

All five controls keep the genuine outer proof unchanged and pass transaction
isolation. Altering CF data or an inner proof rejects with `ZkIntegrity`;
altering reserve, current outpoint or adding an unauthorized native payout
rejects with `VerifyError`. These are actual native runs, with no hash-oracle
substitution. The six validation cases took738ms service time,744ms CPU and
45.6M rounded memory peak under2CPU/3GiB/swap0.

The [source/execution packet](genuine-native-01/SOURCE-AND-EXECUTION.json)
retains seven selected SDK reports, the public128-byte native proof and an
externally pinned [29-file source capsule](source-02/MANIFEST.json). Source
hashes matched before and after execution. A host-only SDK coordinate metadata
conversion error was corrected and peer reviewed before the successful
native-proof conversion; the guest, receipt and financial body were unchanged.
Native acceptance is evidence about this tested implementation and supplied
contexts, not a cryptographic correctness or production safety claim.
The [public material map](genuine-native-01/MATERIAL-MANIFEST.json) separately
pins exact pretty-printed case files and their canonical compact-JSON digests;
the result's `public_case_sha256` uses the latter. The added1sompi unauthorized
output incurs enormous storage mass but is also rejected by the exact native
output-count guard; no relay qualification is inferred from that control.

The [genuine-child body result](native-body-codec-01/RESULTS.json) checks both
installed-key private proofs, canonical virtual IDs, NF/CM transitions, exact
fee allocation and an independent8301-byte native financial projection. The
final public body reconciles the earlier sizing quote exactly:

- Constructed starting reserve4,000,000,000sompi, ending3,981,492,000sompi.
- Outer fee18,508,000sompi at reference rate100; each owner authorized9,254,000.
- Actual wrapper mining mass185080, storage mass1, selected compute budget1600.
- Each recipient's gross note1,018,023,200sompi includes provisional18,023,200
  exit credit for a requested useful payment of1,000,000,000sompi.

The [native binding result](native-binding-01/RESULTS.json) records16 validation
cases. The actual wrapper with a zero outer proof passes isolation and reaches
its unconditional final verifier, then rejects with `ZkIntegrity` at15,646,439
script units. A separately marked, distinct-script hash oracle passes its
codec-only positive;14 unchanged-hash mutations reject. That oracle supplies no
financial authorization and is never accepted as the real wrapper. Full and
separate input-engine execution counts are not conflated with validation-case
counts. Two gas/subnetwork controls also fail isolation, as recorded.

The pricing artifact is explicitly an
[invalid-record sizing skeleton](pricing-skeleton-01/RESULTS.json), not quote
authority. Its outer fee was subsequently reconciled against the genuine
private actions. Continuing and terminal private-fallback prices, backup
recovery, sender-change closure and an actual ordered fallback remain later
gates. No new chain funding, accepted backing, currentness, confirmed payout,
complete lifecycle fee qualification or financial privacy is established.

## Initial unchanged-policy gate

The existing genuine wide32 action followed by its genuine compact successor
forms a valid public ordered transcript. Both exact original fees remain1000:
`32000001000 = 31999999000 final reserve + 2000 fees + 0 payouts`.
Replacing the combined fee with1000 while preserving the old authorized effects
fails exact conservation. There is no new aggregate proof, native VM acceptance,
live/current-chain observation, private-recovery or financial-privacy result.

The [executed result](attempt-03/RESULTS.json), SHA256
`8c87f1465575e576f0d2099b1e970f2f953e7c2465890d5c7a2b3ceeb35e9db1`, records:

- Actual installed-key G16 verification for each relevant Auth/proof, separate
  from public semantic and selected-profile results. No report boolean substitutes.
-43 individual controls, including a genuine privately valid occupiedNF and
  wrong-next-CM-root proof rejected by byte-derived public checks; coherent
  re-IDed body/header/output tampering; witness/CM/CF/path/order corruption;
  role/domain binding; strict malformed types/flags; and false live-currentness.
-3 combinations where every ordinary proof verifies but the transcript rejects:
  mutually exclusive same-NF alternatives, a repeated action and reversed order.
- Canonical official v1 IDs, sequential strict indexed-NF absence/update,
  authenticated aligned empty CM subtree replacement, exact successor template,
  native amounts/destination and whole-transcript reserve/fee reconciliation.

The [source/execution packet](attempt-03/SOURCE-AND-EXECUTION.json), SHA256
`77369c33952ba029a577760dfa5e4cc15051d25e2cfb50cab2c04af2e3a5cb8e`, retains
nine exact executed public source preimages. The final run used4CPU/4GiB/swap0,
2.750s service time,2.934s CPU and45.8M rounded cgroup peak. Eleven focused unit
controls passed separately. The first systemd launch's missing working directory
and earlier successful run remain retained. No private data was read and no new
proof was generated; existing public proofs were reverified.

## Retained adversarial failure and scope

Independent review actually found four coherent native-header mutations accepted
by the initial mirror: gas, locktime, subnetwork and sequence. Their ordinary
proofs remained valid. The missing guards were added independently from budget
profile checks, and all four now reject at `native_fixed_header_and_sequence`.
Both [observed failure](../review/SETTLEMENT-HEADER-GAP-01.json) and
[independent correction check](../review/SETTLEMENT-HEADER-GAP-02.json) are
retained. The [reconstructed failing preimage](retained-failures/header-gap-01/PREIMAGE.json)
matches the peer-observed source hash exactly; it is labeled reconstruction,
not a new historical execution.

Starting-head reachability, empty-suffix induction, accepted backing/currentness
and complete retrievable public data remain external assumptions. The post-
REVEAL negative starts from an independently selected synthetic head; this
checker does not newly verify the REVEAL Schnorr branch. Current canary fees are
deliberately underpaid at rate100; no complete-fee qualification follows.

## Concrete next design

The [two-P0 virtual-chain contract](VIRTUAL-P0-CONTRACT-01.md) proposes a fresh
native wrapper, two local-owner compact proofs, complete public state/body
execution inside an established outer proof, and exact preallocated shared
fees. It retains original shared NFs and explicitly distinguishes virtual child
template contexts from the actual wrapper UTXO. It neither migrates old funds
nor reinterprets old Auths silently.

The [R0/native plan](../fees/PLAN-R0-SETTLEMENT-01.md) makes the payload/journal
projection acyclic before implementation. ADR59 records the fresh prototype
selection; its selected image and child keys remain external authority rather
than request-supplied choices. Actual private unilateral fallback, capacity behavior,
operator/data loss, low-demand complete costs and fresh live rehearsal remain
required gates; an accepted two-action transcript alone does not satisfy them.
