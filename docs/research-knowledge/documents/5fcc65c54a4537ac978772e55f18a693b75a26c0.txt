# Independent linkage source review: public development gate

**ACK for the fixed PUBLIC known-seed two-payer development probe only.**
This permits measuring exact-query tractability before the source/method freeze
for heldout data. It does not permit heldout generation/scoring or qualify
privacy. The reviewer used source only, not generated truth, model keys, solver
execution or real profiles. Date: 2026-10-23 UTC.

Reviewed source snapshot `privacy/SOURCE-PROPOSED-01.json` SHA256:
`8692f2d2f10c4b45bd3efaac45e9a28249ac66084e5ffc3181f5e05dc474ba89`.
It binds eighteen source/dependency files, proposed plan
`337cfbc7ea3bd8241aa74466b958a71d789ebd832f03cf6fa1b8660aefb37298`
and API `47d1c71bdef75d10bf38f398d10928097a481679974f20b848d92601741ad3a0`.

## Public probe and information separation

`public_probe.py` SHA256:
`63d37aa66f77f6cc9a4f6333a8d3838bc4fd0cc8f9c3291fd11fdb7b52778bb0`;
`probe_generate_cli.py`:
`8daca07aff6f9783e9f00b65d241b616bc2dcef41eae15e390609e8cde915037`.
The fixture has fixed public workload bytes00 and material bytes11, overlap
timing, two independent payers each owing32 already selected payment demands,
wide32/serial compact2 arms, final-drain C observer. All outputs are explicitly
public development results, not independent heldout evidence.

The generator, observer and scorer use sibling bwrap namespaces. The observer
receives only schema/certificate/model/observe modules plus public stdin. Its
mounts omit generator, truth, material/seed files, receiver, crypto program and
the repository parent. The scorer receives the exact public/prediction/truth
triple in its separate namespace. The generator receives only selected receiver,
fee-profile and crypto dependencies plus fresh disposable inputs. No existing
wallet/profile or backup is a dependency. The shared read-only Python/toolchain
and host remain trusted components; this is process/mount separation, not
isolation against a compromised kernel or malicious controller.

The generator now derives a dummy NF with the original actual-slot HMAC formula,
uses actual real Note/CM/NF derivation and sealed ciphertexts, and shuffles Note/CF
pairs without publishing ownership. The keyless scorer checks the Note value at
bytes64..72, Note-CM hash, canonical zero Note except rho and ciphertext position
join, plus the claimed real NF's public occurrence. It does not claim independent
secret NF derivation or decryption; selected generation and existing bridge
controls remain that trust boundary.

## Exact-model review

The public model is a conditional one-real-input, full-native-cashout arithmetic
relaxation. It checks every prefix reserve, positive-input selection, strict birth
order, single spend, canonical value bounds and participant-owned disclosures.
Counterparty application labels do not constrain original ingress ancestry.
Human identity is explicitly not modeled. SAT means integer possibility under
these restrictions, not cryptographic realizability, anonymity-set probability
or independent ownership.

At completed zero reserve only, positivity implies eventual consumption. The
positive-Note count identity and forced-input count/value-domain reductions
follow from the same one-real/full-native rules; they are inactive for open
positive reserve. Notes can remain unused only at value zero. Public controls
cover those boundaries. Exact birth-slot automorphisms group only identical
public facts, split participant positions and disable grouping for repeated CMs.
Every SAT witness, including each lifted member, is checked against the original
unsimplified sequential model by independent non-Z3 certificate code.

CM-to-cashout forcedness includes the explicit NONE alternative for dummy,
change, later-private-spent or unspent targets. It requires exclusion of every
other candidate including NONE, with no UNKNOWN. First UNKNOWN makes the view
incomplete and is not a privacy success. Final source must retain that rule.

## Full-study runner reviewed, heldout gate still separate

The then-current `run.py` SHA256 is
`83276a559f26ae04bd683657e5133304dabfcb110a0411090ebefdbbc069ac47`.
It binds a source freeze and exact root release digest before creating fresh
disposable material. It builds all96 public views, applies a generous public-only
one-million-query upper bound before attacks, completes all observer jobs, seals
their hashes in a global prediction barrier and only then starts sibling scorers.
The controller has network sockets denied. Failed generation/scoring is retained
and does not draw replacement material. Four independent workload clusters,
shared arms/timings, exact120 family comparisons and the fixedM128 bounds remain
explicit;256 obligations are not treated as256 independent workload samples.

One evidence-durability correction was sent before heldout release: fsync each
prediction file before fsyncing its barrier. Closing and rereading/hash-checking
files establishes process ordering, but fsyncing the barrier alone does not
establish durable prediction contents. Review the final changed source/manifest
and the public probe result before freezing the heldout study. A source hash
change must remain visible; this ACK is not a heldout run authorization.

The old amount-prior failure `21103/100025 > 20%` remains retained and blocks
the prior qualification. Wide batching, exact SAT candidates, a synthetic source
lineage result, local mirrors and small sample bounds cannot erase it or establish
a complete private native-KAS system.
