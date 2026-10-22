# Public development fixture: independent full projection recount

Result: complete public projection P, journal J and full 2,846-byte input were
recomputed independently and match the producer's expected files byte for byte.
This uses a separately selected fresh development instance. It does not close
the original rehearsal instance's missing compatible pair.

Read only:
`/home/luke/projects/kpi-intensive-2026-10-22/observer/artifacts/public-v6-fixture-production-20261022T124051Z/public/`.
No parent directory, wallet secrets, proving key or private evaluation files were
read. Root supplied the trusted domain/VK hash independently before recounting.

| Identity | Independently checked value |
|---|---|
| Domain | `d47cb91ef9ac74dda71c7db1519381526c3dfac5f525b904f744b97a7df713bd` |
| Exact 328-byte VK SHA-256 | `2a9acd1639fb7b454384c65fb317a139695f5a2cbb3ebd941dd13b5f6045a2f4` |
| Bundle 0 SHA-256 | `3f8f0a13f4ce7a73b61fd093c5aad01fc2cb2ea0ca3db65ed4f0d44de72019a9` |
| Bundle 1 SHA-256 | `1cc3094a335dfa94897929fde258d05da2a3270314738919b972838e61e2d7b8` |
| P length / SHA-256 | 1,088 / `9ac720aa55e7bd6eaec674788d418aa3314bc7af1010b7c9f09a493d9aa76ce9` |
| J length / SHA-256 | 42 / `5d667b709f35191c6fc98e6aa0b79bd934e39a40ef4edfea582fcef3b06d4ac7` |
| Full input length / SHA-256 | 2,846 / `7771a2e610d37fdb12b1d668b8e229bd3cd1e5fe83c5993847daa0fef8c93b36` |
| Aggregate fee | `80000000` integer sompi |

The journal is exactly
`4b50493256364a3101009ac720aa55e7bd6eaec674788d418aa3314bc7af1010b7c9f09a493d9aa76ce9`.
`SHA256(P)` and `SHA256(J)` remain distinct; a native boundary must use the latter
as its journal digest where required by its separately reviewed wire contract.

The recount sorted all four NFs and all four complete `(CM,ciphertext)` records,
retained original ciphertext ordering inside each authorization hash, computed
fee sum as exact u128 bytes and constructed both bijections. For this already
public test fixture the index vectors are `p=[3,1,0,2]`, `q=[2,1,0,3]`. Neither
the production journal nor an eventual private-publication claim should expose
those vectors.

As an additional public-data check, reconstructing the depth-16 tree from the
manifest's three public commitments produces
`fec66e79a8b1f41e1684c6d4ad446b6d7fd52aeac5bd9456cb9ad6c0788c8b15`, matching
both authorization count/root pairs. This verifies a synthetic tree calculation,
not accepted chain state or current spendability.

Reproduction:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/intensive-2026-10-22/review/public_fixture_recount.py \
  /home/luke/projects/kpi-intensive-2026-10-22/observer/artifacts/public-v6-fixture-production-20261022T124051Z/public
```

Complete outcomes are in `public-development-fixture-recount.json`. The Python
oracle uses an explicitly marked exact-source callback to isolate binding; it
does not cryptographically verify Groth16 proofs. The producer's proof claims
and subsequent checked generic/compiled host verification are separate evidence.
No receipt, native settlement, backing, recovery or privacy result follows from
this recount.
