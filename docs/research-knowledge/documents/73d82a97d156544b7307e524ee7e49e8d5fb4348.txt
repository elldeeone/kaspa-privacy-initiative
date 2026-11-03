# Independent private-change source and artifact review

The reviewed new wallet, source-selected local controller and fresh parameter
artifacts match ADR0055 and the accepted contract. The six selected local
statements were released for genuine proving after independent public-effects
checks. This report records that source/input decision, not completed native or
testnet execution.

Authority is ADR0055 `101738564c05c3ca7fdee35cb475e83c4085d9bfa1573549552c7ca2dbd42b41`
and contract `efa3d2c68a1fb3ec9b3b409c6196aa44304bb4e62eefc426dfa421e702f0c837`.
Fresh public identity is `3669f0aab7d6cd4db661d848d26ed2c741523b7e1fbe7955cf9a0192f73bf37d`;
the constructor reuse selection is `28aa04e172db61a8c75ca10547ab6a95b212d7226101e19f925ae7bd338bd62c`.
The domain derivation was independently reproduced. Historical constructor
provenance is preserved; the new root record supplies the new milestone's
authority. Old funded domains and their source/evidence were not modified.

## Wallet and sizing barrier

The original 12-file source freeze is
`e05922ea0e561412ef9e0c258fcc1807b37fc6547cb85883a3b5a2d9442bdf3b`.
Its action/main/rules/runtime sources were read directly. In particular:

- Integer equations enforce partial `V=P+f+C`, payment `V=T+f+C`, full
  `V=P+f`, and reserve `R'=R-P-f`. Positive note/change and payout floors,
  amount bounds and zero/positive reserve rules are explicit.
- One preparation fixes its private index, rho and input/output permutations.
  The real NF does not depend on slot; the dummy HMAC uses its actual slot.
  Both exclusions/inserts are regenerated sequentially from the current state.
- Uniform OS-u64 change indices reject recognized historical indices and
  receive tuples, including spent claims. Original seed-only backups recover
  encrypted indices through V2. No ownership counter, saved change map or
  derivation lookahead is required. Unseen pending/orphan/concurrent reuse
  remains an assumption; this is probabilistic freshness, not global uniqueness.
- Accepted duplicate claims retain spend authority. Selection uses actual
  unspent claim value and position, rather than treating a zero normal-credit
  accounting field as absent ownership.
- `PublicSizingCandidate` has no witness API. An authenticated prover waits on
  an empty witness pipe while public sizing learns fees. Only a legal
  `ActualCandidate`, after an exact actual-body re-quote, can serialize witness
  material. Fee changes rebuild and revalidate actual material. The final proof
  changes only the designated 128 proof bytes and must pass Full validation.
- Public file/executable metadata is compared against the backup inode before
  any such file is opened or hashed. The invoice is exactly 208 bytes and is
  snapshotted once. Public projections omit private payment/change amounts,
  slots, indices, receipt maps and operational paths. Only the final actual
  quote is exported; sizing/intermediate statements remain private.

The retained isolated 27-control result is
`75bc8ac5ccbbf58c4c3f8f6bab016e34362a8ddd68175544d9c6a2ed31460da3`.
The 16 current/archive control pins and result-linked logs were rehashed. Actual
limits were 2 CPU, 4 GiB and zero swap; cleanup was inactive/dead/PID0. Established
crypto and independent public tree reconstruction ran; native and prover were
mocks in these controls. Development failures remain retained. No test rerun was
performed by this reviewer.

The separately versioned selected release is
`82753fd2cb978ce891b2ee1107e0d4c1c30f6ce3a439d43c26a225337fd128a3`.
All 22 current/archive pins match. The only action-source change is forward
refusal of a requested target matching any recognized own historical receive
tuple; this does not revoke already accepted duplicate claims. Main source is
unchanged. Three targeted tests and the complete public dependency wiring gate
passed in result `b99f2b18e80176519df755700b8f7b0b25b18170e5cdbe44b4f111013b9f3c97`;
all 24 check-packet pins and linked logs match.

The three selected executable hashes, lengths, 0500 files and 0700 release
parents were independently checked against root software selection
`4c867fd49b02f7fc2dc78a7036d2bb78b0641899e8c4194d2b7207cbeceaaca8`.
The payment runtime adds only a single read-only invoice file. The recover-only
runtime omits PK, prover and cashout helper. Execution follows ADR0054 ordinary
file/read-only-release semantics and explicitly trusts host/release immutability;
it does not claim malicious-host protection. No actual cold run is claimed here.

## Fresh proving artifacts

All 17 fresh setup-source files were compared with the selected old template:
only domain and trial-selection metadata changed. The financial circuit and SHA
relation are unchanged. The source manifest is
`0df06d8deff5854828feb0c2eb42ee672f4ad105a923e9087614b1ab2b9b399b`.
The setup/build plans used source-only ordinary executables and preserved the
reviewed parser, authenticated parameter loader and private-path checks.

Setup report `5c17491290fa95d0097a3cbcfa59f4a9a04c521073a6e16f6bfdc62f156a3b22`
records actual finalized dimensions 3,231,025 constraints, 3,195,131 witness
variables and three instances. VK SHA256 is
`dade8f90f1bec1c9b150f5eb126d73a1c8a1959ef1fb9da1178820debf693bae`.
The new PK length/hash are public metadata; the reviewer did not read that blob.

The canonical manifest is
`b440d08fddcdbbfb7d6b8355ab097a7bedd3fb85b8aa228f07070d4fcb3a91d0`,
independently selected by root. Its dimensions, queries, VK, fresh domain,
source/build and setup provenance agree. The 17-file cold clone changes only
three compiled public-selection pins and preserves the original setup source.
Final cold ELF is
`3252c28f2e3b08aa85aab5ff82dc3adf481dec84dbb9d5514e0fb69012250b43`.
Both build closures and their unchanged public pins were checked.

The selected loader's 12 checks passed in report
`d9f5c0fb7554a4b14fa14fca6a13a5b38da2a0550835f1c412895a4837a195f6`.
The full-size positive authenticated the selected actual public parameters.
Missing-PK rejection retained all 302 known public canary bytes with no ready
event/output, demonstrating the before-witness boundary. Cleanup was inactive,
dead and PID0. No private witness, owner seed or proof ran in this loader check.

## Local controller and selected statements

The local financial controller uses the six archived owned wallet modules from
the original source freeze, not later mutable canonical modules. Source bytes
are checked before direct compilation. Each stage reconstructs the receiver
from its original backup; the controller checks spent original/change claims,
exact whole-source accounting and zero recognized private tails. Its synthetic
funding context is explicit and supplies no accepted-chain backing/readiness.

Final materializer source index is
`79eb7fcb6de69d1ec9b715effee68ef75c80330c68dacd5d2bd98017aa374468`.
Its selected source is `fa65e2669f4aae48528b66f75999bb18545356a8efa4c6e79cd8fc7d98be0dcf`.
The independent public synthetic C0 control uses public canary seeds, rho and a
fake outpoint, with its own initial CM/NF tree. Its claims and NFs are disjoint
from the main trace. All unbroadcast main raw statements remain private.

The reviewer read only the explicitly authorized prepared public-type
transactions, contexts, selected actual requests/quotes and synthetic marker.
No profile, backup, seed, private witness or PK was opened or hashed.
For all six selected statements the reviewer independently reproduced the
complete native transaction/all-UTXO-context quote ID, rather than relying on
transaction ID alone. Checks also covered:

- Exact Auth528, payload, zero inactive signature/proof frame, selected VK and
  current redeem/state/amount/SPK/outpoint binding.
- Actual reserve/fee/payout/output-SPK equations and fee/mass reconciliation.
- Both current indexed-NF predecessor exclusions and sequential inserts;
  all continuing CM empty-slot paths/appends; terminal zero CM/cipher/path
  material, SHA256 of the zero cipher, and carried CM state.
- All five main prior-output links and terminal CM9/NF11/R0.
- Exact quote Full/engine typed G16 serialization failures with isolation PASS;
  the quotes reached the intended zero-proof seam, rather than an earlier
  native rejection.
- Synthetic C0's separate fake source and main NF/CM disjointness.

The six statements were released for genuine proving under the selected fresh
resident VK. Their raw Auth/NF/body/cipher/proof packets are deliberately absent
from this public review.

## Privacy finding and evidence boundary

Two preparations of the same real claim have the same real NF and independently
sampled dummy NFs. Publishing both NF pairs can reveal their real-NF intersection
and shuffled slot. This review caught the originally proposed C0 fork reusing a
main claim before it executed. Root accepted the independent-canary replacement.
The initial unexecuted source-selection record and superseded proposal were
preserved; no full byte archive of that initial materializer was made. The fix
preceded execution, so it did not produce a competing statement.

The same rule applies to unbroadcast local/operator/retry statements sharing
later live claims, even if published after cold recovery. Rebinding only an
outpoint does not change that claim's NF. Selected opaque Auth/proof SHA256
metadata is allowed for distinct-statement closure; unselected sizing digests
and raw competing statements remain private. This limits evidence disclosure;
it does not establish an anonymity set or financial privacy.

No reviewer VM, setup, proof, source compilation, RPC, funding or broadcast was
performed. Passing controls and source review remain bounded implementation
evidence. Actual cold-owner repeated spending, terminal confirmations, privacy,
fee viability, durable availability and production correctness require their
separate evidence.
