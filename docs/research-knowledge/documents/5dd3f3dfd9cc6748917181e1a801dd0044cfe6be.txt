# Independent RFC-0018 and fixed-v6 gas review

Source/design review only, 2026-10-22 UTC. No build, proving, native execution,
private data access or funding. RFC reviewed SHA256
`4713abed161c49248b6f66e35a825e32b7c75ad090258802d539ddf75e457348`;
gas note SHA256
`135e4fa4e66d4380189eea767184de90343a80ca4aa0bb70ed0e04b363921272`.

## Actionable finding, now addressed

The original receipt-plus-two-disclosed-inner-proofs diagnostic cannot become a
valid pinned native transaction: its verifier floor is
`250000 + 2*(140000 + 3*2500) = 545000` compute grams, exceeding the
500000 compute block cap before any transaction bytes or state work. The native
source is `zk_precompiles/tags.rs`, Groth16's per-IC tariff, and
`consensus/core/src/config/params.rs:683`, at
`01b532e8b553523216471682649693af92f0fd16`. More fees do not repair this.

Reported to the author and parent before this note. Current RFC lines 42 and
52–58 explicitly reject that transaction candidate and choose a new state-aware
single-outer statement. This resolves the blocker. A separately qualified
Groth16-wrapped outer plus two direct inners has a 450000-gram verifier floor;
that is only a lower bound, and even that floor costs 90M sompi at 200 sompi/gram,
above the unchanged 80M authorization. Do not substitute it silently.

## Contract checks

- **Count/anchor omission:** correctly identified at lines 24–28. Existing J42
  proves an existential partition of P; supplied A/anchor/path beside it are not
  authenticated by that receipt. A new guest must verify the actual A/Q/C,
  authenticate its anchor under the journal-bound actual predecessor history,
  and apply the transitions. Native reconstruction of J_state must bind input
  outpoint, prior body, amounts and exact successor. Echoing host input is
  insufficient. The proposed 336-byte length independently checks out. Freeze
  outpoint endianness and all byte encodings before implementation.
- **History versus spentness:** historical membership does not authorize reuse
  of an already spent note. Four current-root NF insertions, shared across pair
  and DRAIN branches, are necessary. Every insertion needs the then-current
  predecessor/empty-slot witnesses; four independent witnesses against the same
  prior root would be wrong.
- **Two history appends:** n is odd, so n+2/n+4 stay odd and the new indices h and
  h+1 preserve `history_count=(n+1)/2`. Both slots need authenticated emptiness.
  r2 is safe as an accepted commitment prefix after the whole atomic transition:
  its notes are included in the final accepted append-only CM state, and current
  NFs still govern spends. It must not be treated as a separately backed or
  accepted intermediate reserve. The explicit new version and replay/scanner
  changes are required. Appending only r4 under the old implicit indexing fails.
- **NF ordering:** the public raw-byte lexicographic sort and native little-endian
  numeric predecessor order differ. Concrete example: `01 00 ... 00` is lexically
  greater than `00 01 ... 00`, but numerically 1 is less than 256. Insert in P
  order using the existing numeric indexed-tree comparator and updated root;
  do not deduplicate records or infer predecessor order from P.
- **Old helper reuse trap:** architecture independently flagged, and I confirmed,
  that `two_input/tree.rs:275–280` rejects equal commitments inside each pair in
  `PublicState::witness`. Cross-bundle equal CMs/complete records remain permitted
  by P and may become adjacent after sorting. Do not synthesize two temporary
  Authorizations and call the old helper twice for sorted appends. Reuse the
  lower-level tree/leaf/path primitives in an explicit four-record derivative.
  This is an implementation constraint, not permission to weaken old v6 checks.
- **Fee conversion/backing:** upper eight u128 bytes zero, lower u64 <= MAX_SOMPI,
  F < actual R and R'=R-F are sufficient native range conditions. One actual
  input and one exact continuing output make fee F; backing remains conditional
  on authenticated predecessor liabilities. The synthetic reserve is not proof
  of such backing. Independent arithmetic confirms the 336-byte journal.
- **Direct owner exits:** the RFC correctly blocks funding on a new qualified
  owner DRAIN path, public record reconstruction and durable proving parameters
  or genuine prepared exits. The published SPEND-only fixture with discarded PK
  cannot demonstrate this. No collector, outer prover or other owner may be a
  prerequisite for DRAIN. Every branch must preserve the same pins and NF root.

## Capacity argument checked independently

Let L be the number of positive outstanding notes. Genesis gives
`L <= n-m/2`. An authenticated admission adds at most two positives with n+2.
A SPEND consumes at least one real note and appends at most two positive notes,
so L increases by at most one while n-m/2 increases by one. Two such proofs
increase both bounds by at most two. DRAIN consumes at least one positive note
and reduces n-m/2 by one. Zero-value/dummy output slots consume capacity without
increasing L, which preserves the inequality. These claims require the current
nonzero-real-input and value-conservation circuit checks and authentic lineage.

Thus L>=1 implies m<=2n-2. At maximal odd n=65535, a direct two-NF exit leaves
m+2<=131070<2^17, including the sentinel-index convention. CM capacity does not
block a no-CM DRAIN. A pair's n+4<65536 and the same reachable-state bound also
leave NF capacity. A syntactically valid arbitrary state has no such guarantee.
Retain explicit last-positive-note, zero-padding and full-CM boundary tests.

## Fixed-v6 source gas upper bound

No omitted charged operation found in the stated successful reserve-input-0
scope. Independently recounted: historical path 17 SHA calls; two NF insertions
142; bootstrap history 17; two CM plus history appends 99; final bindings 2 =
277. Each counted Merkle level has two wide CATs, totaling 528; leaf assembly
adds 17 =545. Summing mutually exclusive branches is conservative. The wide
selector list covers the successor suffix/state, admission zeroing, DRAIN
append-witness/ciphertext and final auth/ciphertext slices. Proof128 and VK328
are literal pushes rather than omitted charged copies.

Native opcode/data-stack charging supports the generic 32 units per redeem
byte bound for all remaining runtime-created small results; literal/control
operations do not introduce another uniform per-op fee. P2SH and successor
Blake2b are accounted separately, as are fixed Groth16/IC costs, hash inputs and
large runtime copies. Ran the author's tiny checker without modifying it; all
five source pins match. Independent arithmetic gives 15,857,502 units versus
16,009,999 at budget1600, headroom152,497. This is a manual source proof with
an arithmetic/pin checker, not mechanically extracted compiler verification.

The result supports successful fixed-v6 standard-P2SH reserve input0 at the
specified pin. It does not bound malformed executions, funding input1, the new
RFC branch, final mass/fee or wall-clock cost. Default3000 remains unchanged.

## Smallest useful next experiment

First implement only a deterministic, separately versioned host transition and
independent public state vectors using the unmodified public pair. Freeze roots,
two history leaves, amounts, comparator-disagreement case and J_state bytes.
Then run a new state-aware guest against those exact vectors and semantic
negatives; only after that source equivalence review should a bounded new
receipt/native adapter be authorized. The retained J42 receipt remains a
predicate control. A later full native candidate needs measured whole-tx mass,
fee, complete reconstruction and genuine owner exits before any funded trial.
This neither runs nor revives the parked recovery/attack jobs.

Tiny independent arithmetic and comparator example are retained in
`rfc0018-independent-arithmetic.json`. No further correctness blocker found in
the current proposal under these explicit conditions.
