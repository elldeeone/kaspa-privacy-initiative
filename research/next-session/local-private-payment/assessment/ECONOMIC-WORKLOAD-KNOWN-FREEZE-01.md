# Conditional public workload arm

Frozen at **2026-10-26 03:19:32 UTC**, before actual final payout input. The
original chain-only policy13444792 remains unchanged. This separate
[policy](ECONOMIC-WORKLOAD-KNOWN-POLICY-01.json) adds one conditional source-publication
assumption: the selected public `optional_volume.py` (SHA256
afb3d20c13909aff6c0b745a256b6ceb058e804200a5ee6c2736b178b6e6948f)
checks, at line51, two outgoing values sorted as200,000,000 and500,000,000sompi.
Root selected three such participant reports for source publication. Thus the
stronger observer is given only the global multiset of three2-KAS and three5-KAS
payments. This source is selected for final publication; it is not assumed to
have already been uploaded or to be on-chain information.

No private plan, owner/action mapping or action/amount schedule is read. At each
candidate payment split, one of its unordered children must match an advertised
value. Both public CM slots remain candidates. Across all six payments there
must exist an assignment with three values of each kind. A forest with several
valid payment/change role assignments is counted once.

For each fixed subtree topology, store the set of feasible counts of5-KAS roles.
Bucket subtrees by this signature. Combine the two child signatures with the
node's allowed contribution {0}, {1}, or {0,1}. At a root cover, require the
combined signature to contain3. The signature is fixed for a topology, so counts
and possible/must ancestry relations remain exact without enumerating or
double-counting role assignments. Compare against the unchanged chain-only
exact arm. No stronger payout-masked arm is claimed.

Controls use an independent forward note-assignment oracle with explicit role
enumeration, a role-ambiguous toy counted once, rejection of an impossible global
count, candidate-set containment and root/CM-slot label symmetry. All test inputs
are public synthetic fixtures. Actual evaluation uses only the same final,
externally selected terminal public ledger as the base arm. No threshold,
posterior or privacy PASS follows. This arm measures conditional asset ancestry;
common ownership and a named founding owner are separate unknowns.
