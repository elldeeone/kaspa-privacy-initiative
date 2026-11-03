# Method 03: explicit per-note conservation

Date: 2026-10-21 (Australia/Sydney).
Parent: [frozen population specification](POPULATION-PRIVACY-SPEC.md).
This changes the search representation only. Histories, disclosures, targets,
integer domains, eligibility and privacy criteria remain unchanged.

The original Boolean representation creates `picked[i,p]`, the value taken from
note position `p` at event `i`. It is the note's value when that event selects it,
and zero otherwise. A positive note may be selected at most once. Therefore:

```text
sum_i picked[i,p] <= value[p]
```

At terminal reserve zero, every positive note has been consumed, so equality
holds for every note. These column equations are already implied by the original
relation. Adding them explicitly may strengthen the solver's linear relaxation
without removing any valid history. This is a performance hypothesis, not a
privacy result; preserve the attempt even if it does not help.

Reuse the original Boolean arithmetic and ownership encoding, adding only these
checked per-note equations. Keep the original Z3 relation for independent
certification. Reuse only public hypothetical full-history witnesses, following
[method 02's candidate, alternative and cache rules](POPULATION-PRIVACY-METHOD-02.md).
Forced claims still require an unrestricted alternative query to be UNSAT in both
engines; pinned SAT-witness checks must not leak restrictions into that query.

Before held-out inference, compare complete tiny feasible sets with the original
model and independent enumeration, including terminal and nonterminal histories.
Rerun original controls and the witness-handoff checks. Freeze this note, sources,
dependencies and parent input identities. Copy reused original source bytes from
the parent snapshot. Use the same generated histories; sample no new seeds.

Inference receives one public file and one selected participant view. Seal its
predictions before the separate scorer checks pinned generated truth in both
original encodings. An unresolved search remains incomplete. This attempt cannot
produce a rate-qualification pass or a real-world anonymity conclusion.
