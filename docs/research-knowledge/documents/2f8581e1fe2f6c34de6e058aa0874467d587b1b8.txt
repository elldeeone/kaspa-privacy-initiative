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
- **Legitimate colluder knowledge:** its own input and created rows belong in
  the view. A decrypted incoming receipt's creator/contact edge belongs only
  after an actual authenticated peer route binds it. The current C1 envelope
  explicitly reports `contact_binding_qualified=false`, so the model preserves
  the stage/operation/contact/sequence/time record but does not inject that
  caller instruction as a creator fact. Its
  own Original/record is not classified as an illicit honest-owner export.
  Those known edges remain fixed. The pass predicate requires one common
  alternative that exchanges honest NF input labels and assigns each honest NF
  a created pair different from truth; it never asks known recipient facts to
  disappear.
- **Incomplete observation:** nonliteral corrupt-server share/MAC/randomness/
  masked-opening meaning, physical wire behavior, unknown dispatcher channels
  and terminal economics remain unmodeled. They cannot produce a complete
  privacy pass. The C03 bridge binds exact v8 sixteen-lane wire provenance and
  grammar; it
  does not call opaque cryptographic bytes harmless. Literal export recognition
  is one bounded strategy, not a proof that unsupported bytes reveal nothing.
- **Per-field coverage:** every captured field is constraint-modeled with a
  positive field-specific count, covered by one exact cited source assumption,
  or unmodeled. There is no zero-count/default modeled state. P1 models exact
  grammar/public bytes/literal-ID scans only. Its nonliteral offset,
  preprocessing-share, authenticated-share, MAC, randomness and opening
  implications, plus physical time/length/order/direction/peer/fork/abort/retry
  fields, stay unmodeled. Masked field/G1 intermediates and final A/C/B2
  openings have distinct lanes; there is no raw B1 lane. The legacy
  masked-share/generic-opening names are rejected. Exact source/build/launch/
  role/fixed-FD binding is modeled only after the P1 row joins the selected
  ten-role closure preimage and aggregate digest; dual substitution and MAC-key
  reordering refuse. Conditional DDNNT and
  MASCOT/OT/TLS reasoning is not measured coverage or a selected assumption.
  Authenticated G1/G2 local-state stages, canonical share-then-MAC layout and
  repeated A/B2 identity are captured, but their nonliteral meaning,
  query/MSM correspondence and mixed-protocol implications remain unmodeled.
  The experiment is the pinned passive P1 process plus passive owner1 view,
  not an arbitrary malicious host. The theoretical full-party OT/PRNG tape and
  physical host/covert channels are recorded in a separate out-of-scope,
  unqualified boundary receipt. They are not called modeled or harmless.
  Dispatcher
  timing/length/order/route/cohort/policy fields also keep the combined view
  unqualified.
- **Terminal intersection:** full-vector ambiguity is insufficient. After all
  cross-round/terminal links are applied, owner-local scoring recomputes
  eligible input/output/NF-pair marginals and the unchanged six-pair floor. A
  unique edge in two or more otherwise different workload vectors is a privacy
  failure.
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
