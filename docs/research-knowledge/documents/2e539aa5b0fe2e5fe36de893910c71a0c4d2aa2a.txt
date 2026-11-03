# Privacy diagnostic source second pass

This is an implementation self-review before actual private execution. It does
not qualify cryptographic privacy, captured-view completeness or a financial
lifecycle. Independent integration review and exact source/route selection are
still required before using the workers with actual wallets.

- **Truth leakage:** owner truth is written only in the actual owner namespace;
  the public sidecar is salted. Observer capsules are salted and private.
  Per-owner membership masks/counts remain private to isolated scoring and
  aggregation. Public output contains aggregate counts and histograms, with no
  slot-index vector that could identify the colluder's input.
- **Scoring oracle/replay:** all four views/two rounds freeze before one owner
  query. A durable fixed marker precedes opening truth. The launcher must bind
  that marker to the Original owner's one persistent diagnostics directory;
  caller-selected fresh state roots are not a qualified launcher. A repeated
  query refuses. Candidate-mask intersections prevent a false whole-truth claim
  from three independently nonempty but mutually inconsistent subsets.
- **Wrong identities:** strict trial/phase/attempt/method/selection bindings,
  context joins, whole tuple hashes/CMs, public capsule seals and canonical
  candidate recomputation refuse substitutions. A public Boolean cannot promote
  unknown or missing captured artifacts to a modeled view.
- **Legitimate colluder knowledge:** its own input, created rows, decrypted
  incoming receipt and actual authenticated route all belong in the view. Its
  own Original/record is not classified as an illicit honest-owner export.
  The frozen global creator-swap H1 counterexample is retained unchanged.
- **Incomplete observation:** raw corrupt-server/MAC/group/augmented-B1 material,
  unknown dispatcher schemas and terminal economics remain unmodeled. They
  cannot produce a complete privacy pass. Literal export recognition is one
  bounded strategy, not a proof that unsupported bytes reveal nothing.
- **Financial safety:** these modules create no transaction, proof authority,
  reserve release, native payout, fee override, token or service-history reset.
  Financial acceptance/recovery/fees and actual boundary rejection remain
  separate evidence. Missing diagnostics/tools halt that measurement only.

Public tests cover exact ambiguity, the legitimate known-sender failure,
constructor/pair-tag/individual-Delta negatives, wrong unique predictions,
unqualified raw views, capsule/context/commitment tampering, actual route fields,
global mask intersections, and a real network-off one-owner scorer with a
repeated-query refusal. All truth/capsules in those tests are deliberately
public synthetic fixtures; no actual Original or private view is used.
