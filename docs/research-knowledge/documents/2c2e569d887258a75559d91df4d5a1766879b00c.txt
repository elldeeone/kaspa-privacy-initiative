# Public shared-settlement semantics experiment

This checks public Groth16 predicates and exact ordered state/native-money
effects. It opens no PK, owner witness, backup, main history or hidden privacy
truth. The original gate preserves the old native policy. The ADR59 prototype
adds public codecs/checks for a separate unfunded two-action wrapper; outer
proof generation lives in the separate `shared-settlement-proof` package.

From the repository root:

```sh
python3 -B -m unittest discover -s poc/shared-settlement -p 'test_*.py' -v
python3 -B poc/shared-settlement/run.py --output /tmp/new-public-transcript-result.json
```

The result path must be fresh. Selected checker executables are authenticated
by the separate `shared-settlement-verifier` adapters. If one is unavailable or
has the wrong identity, the run fails as infrastructure, not an invalid-proof
control. Official public normalization recomputes v1 keyed-BLAKE3 IDs; no Python
replacement primitive or stored acceptance boolean is used.

`wire.py` accepts a strict one-input public JSON subset. Its dict API expects a
duplicate-key-rejecting reader when acquiring arbitrary raw JSON; this finite
experiment reads only exact externally pinned public fixtures. `policy.py`
derives strict indexed-NF updates, aligned CM appends, exact native outputs and
fees under the independently selected immutable template. It does not execute
the native VM or establish reachable/current starting state. Budget1600,
synthetic DAA0 and official storage mass are separately labeled profile checks.

The retained [final first-stage result](../../research/next-session/independent-payments/settlement/attempt-03/RESULTS.json)
passes the ordered wide→compact positive,43 individual controls and3 invalid
genuine-proof combinations;11 unit controls cover integer/wire/ID/absence
boundaries. An independently found missing fixed-header guard was corrected,
with its exact failing source/report retained. Ordinary proof validity remains
true for the occupied-NF and wrong-next-CM-root negatives; public semantics
correctly reject them.

The output's public summary is a future contract aid, **not authorization to
omit intermediate transactions or lower their exact fees**. The [new candidate](../../research/next-session/independent-payments/settlement/VIRTUAL-P0-CONTRACT-01.md)
requires a fresh reviewed wrapper policy, explicit virtual bodies/fee allocation
and separately priced private unilateral recovery. Old programs and instances
remain unchanged.

`virtual.py` defines the two-P0 payload,424-byte journal and8301-byte actual
financial-body projection. `selected.py` loads an externally pinned fresh child
profile. `native_adapter.py` authenticates the separate native codec executable;
`native_gate.py` joins genuine child proofs with Python/Rust/native byte equality
and explicitly separates the unsafe hash-oracle diagnostic from the actual
wrapper's unconditional receipt verifier. `pricing.py` produces a labeled
invalid-record mass skeleton; the final genuine body must reconcile its fee.

`finalize.py` consumes an externally pinned genuine128-byte compressed receipt,
inserts only the excluded outer-proof slot and requires the entire canonical
public body/ID/mass to remain fixed. It then runs actual native Full validation
and unchanged-proof tampering controls. Native acceptance in supplied contexts
does not establish chain backing, currentness, private fallback or privacy.
