# Owner-private lifecycle entry and ordinary funding

ADR0064, TN10 research only. The original unfunded KPX7 prototype and all prior
funded profiles/keys/evidence remain unchanged.

`new_trial.py --label FRESH_LABEL --exclude-old-trial OLD_LOCAL
--exclude-old-trial OLD_LIVE --exclude-private-directory WHOLE_PRIVATE ...`
creates three fresh seed-only wallets through separate network-off owner
processes. It needs no proving setup, miner, funding or broadcast. The measured
`live-01` identity took 1.623 seconds. Partial or existing identities are not
overwritten. Each backup rederives its ordinary funding key at existing invoice
index `0xffffffff`, separately from note payout keys.

## GN3 and initial backing

The externally selected financial profile is pinned separately from the
component profile. `gn3_selection.document(financial_profile_sha256, tail)` makes
the exact new-domain entry selector; all callers pin its whole-file SHA.

`entry_cli.py prepare` accepts three 496-byte public initial records and three
ordinary input contexts. GN3 is 1,576 bytes: tag/profile/domain/trial followed by
the three records. Each record is **public Note168 + CM32 + CF264 + CFH32**.
Its note amount is at offset64; CM is SHA256 of the fixed note tag, domain and
complete note. The parser recomputes all three commitments, roots/counts and
the exact native reserve from those public note amounts. It does not trust an
asserted initial root or liability. Initial `n=3,m=1`; same selected native
policy is in the actual reserve SPK. Values are integer sompi, with total bounds.

The full initial notes, values and positions are intentionally transparent
deposit-boundary data. Only later recovered-note commitments/positions remain
private inside the wallet. Initial plaintext records do not include seed,
spending secret or funding scalar.

`run_signer.py` stages one original backup and original public record in a
network-off namespace. The owner re-quotes exact rate100 fees, checks its full
original initial record and all effects, rederives the decrypted invoice0 note
and own funding key, then signs only its designated input with Schnorr ALL.
Entry fees split `[F//3,F//3,F-2*(F//3)]`. Only the signature receipt is public;
all controller plans/logs stay under the declared whole private parent.

`entry_cli.py combine` accepts exactly three distinct matching approvals and
changes only those signature scripts. Native normalization/ID/mass, official
SDK safe roundtrip and actual Full/all-three-input engines must pass. Source
contexts, founding acceptance and currentness are separate from this local
derivation. `chain/replay.py` must strictly rederive GN3 before admitting any
accepted successor history. Three valid input signatures alone do not validate
an arbitrary created pool policy or initial liability assertion.

The genuine local supplied-context packet is
`public/local-01/gn3-final/{selected-case.json,RESULTS.json}`. All three actual
original owner seeds remained within their own namespace; no root/supervisor
backup read or hash occurred. This packet is not a funded chain observation.

## Actual free test-KAS acquisition

[FUNDING-PLAN.md](FUNDING-PLAN.md) specifies the selected three-owner target,
worker allocation, fresh-identity and durable restart rules. Ordinary funding
destinations come from typed initialization exports and exact SDK addresses.
Mining has no wallet-key input. Each owner's subsequent mature-coinbase
consolidation can pay only that same ordinary key. `run_consolidation.py`
exports a genuine owner-signed ordinary case after exact quotation and Native
Full; the once-only `chain/submit.mjs` handles immediate live-input/maturity
checks and submission. All acquisition fees remain in the lifecycle ledger.

The fresh `live-01` trial acquired 33 ordinary coinbases and consolidated them
through three owner-local signers. All 33 input engines and Native Full passed;
each consolidation was submitted once. Exact selected-node UTXO readbacks
observed all three same-owner outputs beyond 20 DAA, with the selected old
coinbases absent. This is a narrow current-node observation, not a Full accepted
pool prefix or independent consensus proof. The retained integer ledger is:

```
9,615,864,283 mined sompi
= 9,611,990,083 ordinary self-output sompi
+     3,874,200 acquisition-fee sompi
```

`reconcile_ordinary.mjs` performs those read-only ordinary-output observations;
it has no submission path. A later pool acceptance claim requires the complete
`chain/fetch.mjs` and `chain/replay.py` path. The public evidence receipt is
`public/live-01/ACQUISITION-AND-GN3-READY-REPORT.json` beneath the selected
`/var/tmp/kpi-owner-private-lifecycle-01` trial parent. Its signed 60 KAS GN3
packet is preparation evidence and must not itself be reported as pool funding.

Normal tests:

```sh
python3 -B -m unittest discover -s poc/owner-private-lifecycle/bootstrap -p 'test_*.py'
node --test poc/owner-private-lifecycle/chain/test_chain.mjs
node --test poc/owner-private-lifecycle/chain/test_submit.mjs
```

Synthetic public signature controls use known test scalars, nonexistent inputs
and a deliberately dummy OP_TRUE reserve tail. Their Native Full result checks
ordinary signatures only. Do not fund those addresses or promote them to an
actual profile/lifecycle result. Passing controls do not prove cryptographic
correctness, privacy, independent operators or production safety.
