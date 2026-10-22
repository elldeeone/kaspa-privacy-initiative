# Independent S7 state assertion second pass

Reviewed the separate state core, thin guest/host and new one-shot native
diagnostic as source, plus the frozen public fixtures using stdlib only.
No reviewer build, Rust/native execution, proving, network or funding.

Core `integration/poc/two-v6-state/common/src/lib.rs` SHA256
`562c6c80cd92b622f3421a1f9798d5ba3e6bddb91c0d8f7d25544eeabc73222f`;
tests `b6319af4bbe9874397e7e58ca9dc7778289ac01a51fe35ca7057f05e15b430ab`.
All 24 reviewed identities, including source-only placeholder pins, are recorded
in `state-source-identities.json`. No acceptance bypass found in this scope.

## Independent reconstruction

`state_assertion_recount.py` uses a recursive sparse-subtree construction, and
rebuilds all indexed NF leaves from the complete value set and physical insertion
indices after every insertion. It does not import the architecture oracle or
core. Both n3→7 and n5→9 contexts match every byte of input11219, J336, prior105
and next105. Full public roots and every predecessor/empty-slot/CM/history path
agree. The second fixture authenticates genuine count3 under later n5 history.
Real raw-lex NF order differs from little-endian numeric order, as required.

`state_corpus_path_check.py` independently folds all supplied paths for all128
frozen corpus positives, reproducing full J336, next state and all intermediate
NF/CM/history roots, including n65531→65535, nonnumeric physical layouts, sentinel
and tail gaps, R=F+1 and R=MAX. This path check is distinct from reconstructing
every full large tree. Checked all35 negative file identities. No new proof is
asserted by either Python program; the exact unchanged genuine pair is required.

## Concrete corpus finding, preserved

Before the Rust differential, I identified `nf-equality-wire`'s incorrect frozen
expected family. Its base is the sentinel-shaped positive: pred_index0/value0.
Replacing value with the target NF but retaining pred_index0 violates the
sentinel equivalence check first. Correct result is `NullifierLink(0)`, while the
original plan expects `NullifierOrder(0)`. The architecture author acknowledged
the error and retained the original generator, plan and corpus byte-for-byte,
with `PRE-RUST-EXPECTATION-ERRATUM.md` SHA256
`ccb77c2ea8d518906f47c6ac2e7a861506ad1412a0f6b3f81b7a7a9946d76484`.
This is a test-label defect, not a reason to weaken the correct core check.

Inspected the owner's retained unmodified differential report:128/128 complete
positive outputs match; all35 negatives reject;34/35 original error families
match, with exactly the predicted discrepancy retained. This was the author's
Rust execution, not a reviewer rerun. Original corpus manifest SHA256
`19fc246c682a9545da41bec205535a6c76b6207dd05fdbf98ccf2fe1c9a74e6f`.

I also constructed a separate already-spent control with real pair2846 unchanged
and a full-tree-consistent m2 prior NF set `[sentinel,1,first_public_NF]`. Its
authenticated predecessor has next_value equal to the target, so the strict
upper gap rejects as `NullifierOrder(0)` with valid history, rather than merely
failing stale history. Retained input SHA256
`4613a1d914ec63aa56219052ed7454fc183b551b1dddb5293a2b21cefbbeed4c`.
The core owner incorporated it and retained a14/14 passing host test run. The
architecture's separate authenticated replay variant tests lower-gap equality.

## Core and host checks

- Exact lengths, separate version7, initialized even m>=2 and checked n+4/m+4
  capacity precede path use. Count bounds make every depth16/depth17 index safe.
- The unchanged compiled pair gate verifies both real proofs and complete P
  binding; actual A count/anchor, not a public unrelated handle, drives history.
  Current anchor additionally equals prior CM root; older anchors use history.
- Four sequential NF insertions use little-endian numeric predecessor ordering,
  canonical local sentinel/tail links, authenticated old leaves and intermediate
  roots, and raw-zero append emptiness. Four sorted CM appends preserve duplicate
  multiplicity. Both history appends bind their correct odd counts/prefix roots.
- u128 fee is range-checked before checked u64 narrowing. R<=MAX and R>F imply a
  positive exact successor R-F. J336 binds full P digest, fixed pool ID, supplied
  outpoint/prior, derived successor and both amounts.
- Guest reads at most INPUT_LEN+1, rejects extra input and commits only J336.
  Host pins exact oracle contexts and compiled selected image/program identities;
  swapping an adjacent runtime image file is insufficient. New source-only
  UNSELECTED pins block execution/proving until coordinator selection.
- Outpoint and reserve are declarations in the guest: valid changes produce
  different exact journals, rather than being misreported as rejected native
  context. The nonuniform outpoint/index control removes the reversal blindness
  of repeated33/55 fixture txids. Guest rejections have specific semantic reasons;
  resource errors do not satisfy them.

Prior whole-tree coherence and authentic lineage remain conditional. Neither
State::parse nor a local transition certifies genesis, liabilities or backing.

## Native diagnostic checks

Reviewed `research/poc/public-state-native-check/src/{main,script,receipt}.rs`:

- Actual input execution uses pinned native `TxScriptEngine` with its committed
  input budget and P2SH/redeem authentication, rather than `from_script` bare
  predicate execution. One input/output and transaction metadata are enforced.
- Canonical prefix142/state offset36 and proof/redeem witness offset133 agree.
  Successor script is rebuilt from executed immutable prefix/suffix and exact
  payload next state. Actual amounts, raw txid bytes, u32 little-endian index,
  old state, complete P and successor reconstruct J336 on the native stack.
- u32 indices use NUM2BIN8 followed by a four-byte slice, preserving high-bit
  unsigned values. Native fee checking independently rejects nonzero u128 high
  bytes, noncanonical signed encodings, invalid ranges and R-R' mismatch.
- Official outer key424/five scalar inputs, checked point conversions and
  official successful/assumption-free claim hashing are preserved. Independently
  transcribed SDK tagged_struct hashes reproduce the known earlier claim digest,
  confirming the new script's claim preimage order and zero post-state constant.
- Fifteen native negative controls include coherent prior/next/R changes that
  reach exact Groth16 verification failure, distinct from shape/policy/amount
  VerifyError and payload framing failures. Canonically negated A tests a genuine
  pairing failure. Exact typed expectations prevent resource errors qualifying.
- The immutable suffix pins one literal synthetic predecessor. The same-suffix
  successor retains that old guard and therefore cannot continue as a pool;
  the harness separately checks its txid differs. No DRAIN or owner exit exists.
  It must remain NONFUNDABLE and never broadcast.

At review snapshot, native SELECTED_IMAGE/J were None and its336-byte J pin was
all-zero placeholder, deliberately blocked before loading any receipt. The host
selection was UNSELECTED. These are source-preparation results. Later selection
must replace the native placeholder with exact independently matched J336 and
freeze the new image/source/executable before native runtime qualification.

The harness reports native script execution and actual mass/fee quotes separately
from chain acceptance, authentic predecessor/backing and exits. The paid80M fee
is unchanged; lower verifier mass does not establish a paid-fee reduction or
meet a1% target. Source review and passing local tests remain bounded evidence.
