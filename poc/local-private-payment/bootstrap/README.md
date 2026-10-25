# Fresh native KAS entry

Research/testnet only. `GENESIS-SPEC.json` defines the new encrypted three-owner
entry. Old pools, seeds, trial identities and sources remain unchanged.

Create three original seed owners with one command:

```sh
python3 -B poc/local-private-payment/bootstrap/new_trial.py \
  --label fresh-trial-label --assets /absolute/WALLET-ASSETS.json --assets-sha256 HEX
```

This takes separate finite, network-disabled owner sandboxes through genuine
Output proving. Each original BACKUP and INITIAL-PUBLIC stays in its own private
owner directory under `/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01`.
Only encrypted Output520, admission20KAS and ordinary fundingSPK are exported.
The controller never reads or hashes seed backups or private plans/logs.

1. `funding_identity.py --trial TRIAL --trial-sha256 HEX --output FILE` derives
   the three official SDK funding addresses from those public exports.
2. `run_miner.py` defaults to staging; `--plan` only reads a template.
   `--execute-mining` mines free test KAS through a fresh isolated Tor TLS bridge.
   `collect_funding.mjs` records only mature own coinbases. `run_consolidation.py`
   stages an offline own-only original-seed signer and exports its whole signed
   ordinary self-output CASE. Submission uses the chain once-only adapter.
3. `gn3_selection.document(...)` binds financial profile, new native tail,
   relation binary, selected fresh OutputVK and canonical CV(20KAS,zero).
   `entry_cli.py prepare` independently verifies all3 genuine Output proofs,
   quotes the exact native CASE at100sompi/mass and allocates the fee as floor,
   floor,remainder. `run_signer.py --execute` mounts one own original seed only;
   it reopens its own encrypted note and validates exact whole CASE, own funding,
   all3 proofs/CVs and native quote before exporting SIGHASH_ALL. `entry_cli.py
   combine` validates all3 exports, officialSDK roundtrip and actual native Full.

Every funding or broadcasting operation requires its explicit execute flag and
owner authorization. A local native Full result on synthetic supplied UTXOs is
unfunded fixture evidence. It never establishes accepted backing, currentness or
trial readiness. Readiness requires the complete real terminal payout rehearsal.
