# H12 adversarial second pass

This is the implementing agent's second pass, not independent review or a
cryptographic audit. Baseline `5cfa94d`, frozen question `a522e59`. The native
relation, covenant, parameter bytes and SECURITY-INVARIANTS.md are unchanged.

## Value, authorization and replay

- **Inflation/backing:** funding equalization conserves the exact total in
  integer sompi. New funding must match four independently signed ordinary
  scripts and exact amounts. `normalization::bind` revalidates every rebound
  transaction with the unchanged native validator; it cannot make a new claim
  by substituting an amount in public metadata. The model rejects relabeled
  unbacked contributions. Native boundary/conservation tests remain passing.
- **Exits/recipient substitution:** each capability pins the exact descriptor
  bytes. Replay verifies the initial native transaction, its source, amount,
  reserve script, each successor, authorization domain and public witnesses.
  The private preparation check additionally matches every exit amount/script
  to its owning wallet's note/payout key. Settlement receives only one selected
  capability, public material and a correct accepted-chain view. It cannot
  choose another payout or add fees without invalidating the existing proof.
- **Single spend:** both old-first/fresh-first alternatives reject the other
  bundle against the resulting current state. This is an adapter/builder check;
  H10 supplies the unchanged hostile native duplicate-witness tests. Partial
  history, repeated funding inputs, missing transactions or a closed reserve
  cannot become a second valid exit. Proof/nullifier state remains unchanged.
- **Wrong state/reorg:** full replay, pinned identity and native checks bind
  public history. A valid old prefix can still be locally valid; live clients
  independently fetch accepted history and require the current reserve UTXO.
  This test does not solve arbitrary reorg recovery or contention starvation.
  It does not claim that a local JSON replay establishes canonical chain state.

## Privacy and hidden assumptions

- Equal credits create a funding-origin permutation symmetry only under the
  declared workload. Unequal or interleaved admissions, payments before all
  deposits, early withdrawals, published fallbacks or external knowledge may
  break it. The policy is not a new covenant rule. Another depositor can use a
  different valid amount, and a wallet must not advertise a guaranteed set size.
- Four logical deposits are not four independent people. TN10 funding comes
  from one allocator, and its observable funding cluster has size one. Each
  wallet's ability to control its own funding and exit is a different question.
- The model omits byte-level cryptographic attacks and RPC/network observations.
  Its age/amount/feasible-history attacks are fixed and limited, not a strongest
  possible adversary. Zero unique deposit assignments is not zero linkage of
  other relationships. Ordinary payout addresses are unique in these tests.
- The controller knows synthetic truth during generation/scoring; isolated
  observers do not. Native test preparation deliberately holds the synthetic
  wallets in one process. It is not evidence that a hosted prover is private.
  Exit processes have no wallet keys, other capabilities or proving parameters.
- Existing single-party setup and public-history/parameter availability remain
  assumptions. A missing correct public source reduces liveness. No special
  operator signature, recovery key or withdrawal bypass was introduced.
- Total backing and topology match across policies, but the common eligibility
  set conditions the workload. It restricts choices for 11/64 sparse payments
  and 42/128 burst payments. This is reported rather than hidden as three
  independent natural-traffic populations. Opaque public labels do not encode
  the private reproducibility seed.

## Controls corrected during review

The first adapter test rewrote a logically identical descriptor using JavaScript
serialization. Its hash differed from the original Rust bytes, so three history
negative controls stopped at the descriptor pin rather than replay. This was a
test defect, not a rejected consensus transaction. Copying exact descriptor bytes
fixed it; controls now assert their intended error class as well as rejection.
The still-unfunded rehearsal was stopped, the offline gate rerun, and a fresh
rehearsal identity created. The stopped identity broadcast zero pool transactions.

Corrected checks cover missing history, missing middle transaction, changed
descriptor, inflated reserve, wrong domain, changed payout, malformed proof and
both same-note winner orders. A synthetic unknown/incomplete solver outcome is
never accepted as anonymity. Independent tiny enumeration and Z3/CP-SAT/Flow
checks remain covered by the existing model tests.

The mutated reserve body retains its original transaction ID and is rejected at
canonical-ID parsing. This is evidence for that boundary, not a new hostile
native inflation test; unchanged H10/native relation controls cover the latter.

The first funded rehearsal paid all ten claims, including terminal withdrawal,
but its post-broadcast recorder expected transaction hashes in bare fee metrics.
That field did not exist. A read-only reconciler now derives full hashes from
the exact local transaction bytes, checks them against accepted native bodies,
and reconciles every payout/change output. Nothing from that identity was
rebroadcast. Its record is explicitly marked as having a recorder failure; a
fresh rehearsal is required before the measured trial. Offline validation now
exercises the same hash derivation against both complete alternative drains.

The ordinary funding recycler also needed a lookup fix: v5 payout keys use note
position, which can exceed transaction position because admissions create two
notes. Search now includes the public commitment count and still requires an
exact P2PK ownership match before signing. Failed preparation broadcast nothing.
The recycler has no pool-reserve path; ordinary consolidation fees are reported
separately from the privacy policy's native fees.

## Evidence discipline

All evaluation draws are retained, with no post-result seed, threshold or attack
change. Native calibration uses the first predeclared equal-net case in each
regime. The original H11 binary was copied before adding the TN10 adapter;
its hash identifies the unchanged calibration implementation. The new adapter
has a separate binary/source identity. No previous proof or branch is replaced.

Only fresh public native histories and aggregate paired scores are eligible for
export. Old alternate drains, unused fallback proof/authorization bytes, wallets,
private funding keys and note openings are excluded and checked against actual
secret values. Export injection controls exercise hex and byte-array encodings.
Observed test acceptance is not proof of cryptographic correctness or safety.
