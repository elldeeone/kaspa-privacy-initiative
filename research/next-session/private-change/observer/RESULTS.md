# Exact public arithmetic observer: v1 results

**The fixed public controls pass. They demonstrate both forced singleton amounts
and arithmetic alternatives in a multi-ingress case; they do not qualify privacy.**

The implementation follows [PLAN-01.md](PLAN-01.md), [API-01.json](API-01.json)
and [SELECTION-01.json](SELECTION-01.json). Source02 is
`3affbf544bcd124df36397a2c66550978e500eb5e971f1e31004c9892cbcf41c`.
The first source/control packet also passed and remains unchanged; source02 only
removes an unused conditional/imports. No model assumption or expected case was
retuned. Independent source review is recorded separately.

## What was checked

[Final results](controls-02/RESULTS.json), SHA256
`d6040cabe261d5390fba3d3ce39310f45baca5d399201b7d3972a8e3c717c475`,
cover8 fixed analytical ledgers,19 malformed/out-of-scope public requests,
4 invalid arithmetic certificates and1 test-only UNKNOWN backend result.
The [27 public requests](controls-02/PUBLIC-INPUTS.json) are independently
reconstructible from the frozen source. No hidden truth/keys/private witnesses
exist in these controls. Each observer subprocess receives only public JSON;
controller expectations are not observer API fields.

| Public analytical control | Exact result |
| --- | --- |
| Whole-claim exit | Consumed value980M=P+fee is forced; its shuffled positioned CM is not fixed by the arithmetic relation. |
| Singleton partial exit | Consumed1000M and aggregate new private value581M are forced by the public history, although each new slot may contain0 or581M. Private change alone is not a privacy success. |
| Multi-ingress change | Checked integer countermodels give different consumed/new-output values and input positions. These are arithmetic alternatives only. |
| All-but-one value prior | Legitimately supplied400M in one output forces the other580M. |
| Terminal drainage | Two required600M/400M full exits force the corresponding positioned inputs; a single-input terminal spend of their1000M total is inconsistent. |
| Repeated CM bytes | Two positions remain separate backed/spendable liabilities, even with identical CM bytes. Their equal600M public values do not identify which position exits first. |
| Large integer |9,007,199,254,740,993 sompi and the derived remainder are preserved exactly. |
| Malformed/UNKNOWN | Private intent/owner/slot hints, bad integer/topology/NF data and invalid certificates reject; UNKNOWN/out-of-scope return incomplete rather than ambiguity. |

M above means1,000,000 sompi. These are analytical public fixtures, not native
transactions, proof witnesses, population draws or measured market amounts.

The final runner took0.58s elapsed,1.47s user and0.40s system CPU, with at most
four independent observer children and one solver thread each. GNU time reports
68,960KiB maximum RSS and zero swaps; this is not a measured aggregate cgroup
peak. No node, crypto helper, proof, PK, seed, funding or network operation ran.

## Interpretation and missing obligations

Each forced amount/position result comes from baseline SAT plus an UNSAT query
for a different value/selection over the complete declared integer model.
Every SAT base/countermodel and queried difference is independently checked with
Python integer arithmetic. The UNSAT result still trusts Z3/model correctness;
no independent formal UNSAT proof checker is claimed.

This version assumes one real earlier positive input, positioned single spend,
all-prefix reserve conservation and one global known wallet-policy arm. Public
events contain no private partial/full intent, owner map or change-slot marker.
There are no identity guesses; owner_link is NOT_MODELLED.

The relation omits cryptographic preimages, equal-CM/value binding equations,
actual ownership, encryption/delivery correctness, setup/proof soundness,
accepted-chain membership, data availability and network/host privacy.
Omitting such constraints is a conservative arithmetic relaxation: a forced
fact remains necessary under the declared assumptions, but a SAT alternative
does not establish another authorized cryptographic history or equal probability.
Repeated hashes do not collapse positions; adding their public value-binding
constraint would be an explicit stronger model version.

No heldout population, old72-case corpus, target threshold or policy was scored
or retuned. The existing amount-prior and fee failures remain unchanged. The
next useful evaluation requires separately frozen admissible priors, fresh
blinded inputs and heldout/scoring separation; these controls do not authorize it.
