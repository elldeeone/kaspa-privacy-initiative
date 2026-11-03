# ADR-0074 native payment and direct-exit policy

Source integration following RFC-0030/ADR-0074. This fresh subtree reuses the
selected native dependency closure and the unchanged genuine R0 verifier
fragment from `../../verification/native`. It does not alter an old funded
template, reuse an old profile image or financial-component VK, or supply a
host validity oracle. The standard RISC Zero outer verifier key is deliberately
the unchanged upstream verifier key used by the retained genuine fragment.

## Public codec

The JSON request has `operation`, `parameters`, and either `state_hex112`
(`emit`) or `case` (`body`, `normalize`, `canonicalize-control`). The exact
`parameters` object is:

```json
{
  "domain_hex32": "<selected fresh D>",
  "chain_hex32": "<selected chain ID>",
  "pool_hex32": "<selected pool ID>",
  "profile_hex32": "<selected profile>",
  "service_hex32": "<selected service context>",
  "outer_image_hex32": "<new R0 image ID>",
  "component_profile_sha256": "<new complete component-manifest SHA256>",
  "exit_vk_hex328": "<new direct AuthExit verification key>",
  "component_manifest_hex": "<exact public component manifest bytes, hex>"
}
```

Every value is canonical lowercase hex of its stated byte width. All eight
identities are embedded in the immutable redeem-script tail. The raw component
manifest must have its exact SHA256, selected research schema, matching context,
ABI and ranges, three distinct canonical two-input keys and the selected exit
key. The actual new guest image must additionally be authenticated by the outer
selection; nonzero bytes are not qualification. `emit` returns the script, P2SH,
zero-proof witness and exact metadata offsets. It creates no funds or proof.

`body` checks a supplied public case and returns its projection, effects
digest, journal and mass/fee accounting. `normalize` additionally canonicalizes
the transaction ID and storage mass. `canonicalize-control` only repairs those
two derived fields in malformed test cases so actual native-VM rejection is
not replaced by a stale-ID rejection. All three operations explicitly report
that no native VM or cryptographic acceptance occurred.

## Payment branch

The sole native output is the same immutable policy with reconstructed
`KPBAST01 || D || CMroot || CMcount || NFroot || NFcount` state. The payload is
`KPBAEF01` plus the exact 3-NF/6-output body, 10,492 bytes. Public state fields
are split; old/new State112 cannot be read as contiguous payload slices.
Counts advance by six commitments and three nullifiers.

The script reconstructs `KPBAFX01` native projection from actual transaction
fields (193-byte prefix and 10,492-byte payload), checks actual reserve and
fee, and verifies the genuine selected R0 receipt over:

```text
KPBAJR01 || D32 || component_manifest_SHA256 || SHA256(projection10685)
```

The outer guest must check the actual aggregate proof, all six Output proofs,
all three NF insertions and all six CM appends. A native wrapper cannot replace
those relation checks. The complete outer receipt, including all bytes of the
final aggregate proof, is bound to the actual projection.

## Independent exit branch

The direct payload is `KPBXEF01`, 1,604 bytes, with common context at the same
offsets as payment. CM root/count remain unchanged; the indexed NF insertion
is checked directly against current native state. The native outputs are either
continuation plus exact ordinary payout, or a terminal ordinary payout with
zero remaining reserve. The continuation preserves every immutable byte.

The direct 128-byte AuthExit proof uses the newly selected 328-byte VK and two
public digest limbs over exactly:

```text
KPBPEX01 || D32 || old_CMroot32 || NF32
  || SHA256(KPBXDG01 || actual_native_prefix || exit_body1604)
  || payout_sompi_u64LE || fee_sompi_u64LE
```

The projection tag is `KPBXFX01`; the native prefix is 240 bytes with a
continuation or 192 bytes at terminal withdrawal. No R0 proof, service-history
permission, committee response or private pending-intent journal is required
for this branch. The immutable service field is context, not an approval key.

## Verification still required

On 2026-10-28 the separate package compiled in release mode with its locked,
offline dependencies. Three tests passed: standard genuine R0 verifier-key
identity, immutable metadata identities, and split state layout. Seven actual
public-codec requests refused unselected or inconsistent profiles, malformed
keys, duplicate keys and legacy domains. The qualified executable SHA256 is
`cc498d61898d15e077f483f8786d2b5993e0bd2a89e30a01d8489e03a31103c7`.
These are build/host-interface results, not proof or native-VM acceptance.

The full selected financial profile still requires genuine positive payment/exit
cases and `run_native_controls.py` with the selected real native engine. The runner requires Native Full
plus every input ScriptEngine for positives, and actual input-script rejection
for negatives. Zero proof bytes and source/host checks are not positive native
evidence. Future compiler jobs use the root-coordinated resource window.

Keep fee/payout/reserve amounts as integer sompi. The inherited physical
reserve and payout floors remain explicit constants; no operational timeout
or performance estimate is a financial acceptance predicate. Actual accepted
testnet history and confirmed payouts remain a later, separate observation.

## Unfunded direct-exit component result, 2026-10-28

A separate component experiment now passed the actual native engine: two genuine
AuthExit proofs accepted through Native Full and every input ScriptEngine,
and 21 mutations rejected through the actual ScriptEngine. The terminal case
spends a supplied 200,000,000-sompi reserve to a 180,949,200-sompi payout with
19,050,800-sompi fee. A separate continuing case spends a supplied
260,000,000-sompi reserve to a 60,000,000-sompi continuation,
180,906,900-sompi payout and 19,093,100-sompi fee. These are integer sompi.

Both cases use fresh owner authorization, the genuine new AuthExit key, the
actual emitted 8,211-byte policy, different nonpalindromic outpoints, and new
proofs over their exact native projections. The existing proving key was reused;
setup was not repeated. Source-based mass quotes used budget 1,800 and reference
rate 100 sompi/mass; this is not an observation of a node's minimum fee.

`exit_component_probe.rs` and `run_exit_component_controls.py` require the explicit
classification `UNFUNDED_EXIT_COMPONENT_ONLY_UNSELECTED_PAYMENT_METADATA`.
The probe derives opaque payment-image/component identities internally and
forbids payment body operations. It neither manufactures an aggregate key nor
selects the canonical payment profile. The ordinary financial emitter retains
its selected-manifest requirements.

The controls cover payout, destination, fee, actual head, domain, pool,
corrupt proof, substitution of the other valid proof, successor policy,
missing/unexpected continuation, and stale/spent-state NF context. The last
control supplies the post-exit NF state with the old body/proof; it demonstrates
stale-context rejection rather than an isolated in-circuit nonmembership test.
Only cached transaction ID and storage mass are repaired for negative cases.

The frozen plan SHA256 is
`b5b3fcb133202101bbcd6ae297f6fbfb84f59c63d3bcee00f490576b7a667f19`.
The conditional result SHA256 is
`3101c51517af572b7534b418436ee3935ab96e65273b675aa37ea1471d9ea015`;
the underlying native-control result SHA256 is
`d8d55d8d0481b7ff80a296ccd64f89ea518198f0520647d1c5c69a4b88b6bdc2`.
The [public evidence bundle](evidence/2026-10-28-exit-component/MANIFEST.json)
retains the selected public inputs and actual engine reports. Independent
adversarial review of the exact frozen plan preceded execution.

This establishes the conditional direct-exit branch against supplied unfunded
contexts. It establishes no accepted liability ledger, reserve backing, chain
currentness, payment acceptance, privacy result, funding or broadcast readiness.
The full selected profile, genuine aggregate/R0 path, and complete testnet
rehearsal with confirmed terminal payout remain required.
