# Fresh public terminal closure

The final descriptor-only network acquisition was performed after both new cold
exits confirmed. It mounted no earlier fetch bundle, confirmation marker,
operator directory, seed, proving key or precomputed exit.

Public replay and native Full validate all five pool transitions and reconstruct
4 CM/5 NF, terminal reserve 0 and no current pool head. Eight exact current queries
show only the selected payouts unspent: Bob 55,026,200 sompi at
`043b8919…:1` and Charlie 55,036,800 sompi at `c39d0ca1…:0`.
[RESULTS.json](RESULTS.json) binds these transaction IDs and amounts to the two
independently generated cold-client results. The two claims 120,000,000 sompi equal
the payouts 110,063,000 plus the two REVEAL fees 9,937,000.

Fresh fetch SHA256:
`d96702bf1ce58edf502532dbf521d94d4ae99970854268d797a51944da8ad140`.
The public replay uses the same separately pinned descriptor and approved generic
native validator as the preceding cold-client gates. All five Full positives
pass; the changed-transcript/same-proof negative reaches and fails Groth16.
No further seed is read. The unit's actual caps are 2 CPU / 6 GiB / swap 0; cleanup is
collected/inactive/dead/MainPID0.

This is selected-validating-node/retained-public-data evidence, not independent
consensus or durable DA. The view is not atomic. The exits deliberately reveal
their note data after explicit consent; financial privacy and complete-fee
qualification remain unresolved. See the [method](../unspent-01/METHOD.md) and
[cold-client results](../unspent-01/RESULTS.md) for source and input boundaries.
