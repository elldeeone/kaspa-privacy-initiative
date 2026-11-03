# ADR59 selected guest and genuine-proof launch review

Decision: **ACK the root-authorized genuine outer proof run** after the selected
guest differential. This is not an outer receipt, Native Full financial result,
fee qualification or chain-readiness claim.

The independently wrapped image/program join is retained separately in
`R0-IMAGE-REVIEW-01.json`: selected image633b and program f3e88182 match the
historical authenticated SDK wrapper applied to the new raw ELF. The two
compatible owner-local P0 components are independently joined and genuinely
verified in `PRODUCER-PUBLIC-JOINS-01.json`. That review uses the actual final
cases embedded in COMPONENT.json; the separate public-case.json files are
zero-ID/mass/proof drafting templates.

Actual selected guest execution returned the expected424-byte journal hash
`057187fff69c8b6929ab9b2ecbe2347a325a803ab4bc32690ddb2a1045e44249`
for the selected8301-byte input hash
`bd391038b0e4f6d50ead57cdf302aab6b33e85bca30c4a93d324c4f5e3233d0e`.
Both lengths and hashes were independently read and checked against the frozen
runtime selection. The report records107,317,810 cycles and2.070992036 seconds,
without proof generation. The checked executor requires a successful exit and
exact journal equality with the host predicate. Python/native public projection
and journal agreement are separate gates, not inferred from successful parsing.

The host-only native-proof conversion is reviewed at source. It first requires
a genuine Groth16 receipt, selected-image SDK verification with development mode
disabled, exact424-byte journal and empty assumptions. Checked canonical,
nonidentity Ark0.6 points follow the established G1/G2 coordinate order before
standard128-byte compressed proof encoding. There is no experimental A negation.
No guest/common/profile/image change is introduced by these host dependencies.
Actual same-claim compression and native acceptance remain future evidence.

The root-selected runtime pins the host, program and CUDA worker whole bytes.
The launcher additionally authenticates retained official compression assets.
Source review found and closed three narrow launcher issues before proving:

1. The asset-authentication JSON was read without its own fixed digest. Current
   launcher pins its SHA256
   `cefdd00b2c97342d0d19108f59f240eaef5f417cdf967cb08cce36be376add59`
   before trusting any rows; omitting rows cannot silently weaken that check.
2. Service launch occurred before cleanup's try/finally. Launch is now inside
   that block, so launch exceptions still attempt to stop the owned unit.
3. An empty manager ControlGroup resolved to the root cgroup. Current source
   explicitly treats that observation as unavailable and never reads root
   cgroup process membership as owned-worker evidence.

The reviewed corrected launcher SHA256 is
`b4c7ba5e447d5ccdf12984dbe2552572fb9e6e9549b8676bc9086ed6dd8de876`.
These changes do not require repeating the already successful guest execution;
its original executed source and terminal evidence must remain retained. That
terminal records manager MainPID0 and no remaining observed owned PID, with an
empty final ControlGroup. It does not establish an observed kernel count of
zero. One-second GPU observations can miss peaks.

The authenticated worker handles only the selected public transcript and has
no owner-witness or PK API. Its namespace disables external networking but
read-only binds the host filesystem. The explicit source/backup absence claim
is therefore false; no minimal-filesystem isolation is inferred. The trusted
installation/host premise remains visible.

Next acceptance evidence must be genuine selected-image Succinct verification,
same-claim Groth16 compression, exact claim/journal native conversion, actual W
financial Native Full acceptance and coherent negatives, followed by unilateral
owner exits from that exact actual head. A diagnostic hash-oracle positive is
only a byte-binding check and cannot satisfy those gates.
