# New-profile private Original bootstrap

Create a fresh, unfunded three-owner identity with one command:

```sh
python3 -B poc/local-private-payment/private_batch_trial/new_private_trial.py \
  --label fresh-private-batch-label
```

The command uses the selected ADR-0074 profile and existing genuine new Output
parameters. Three separate network-disabled namespaces generate private seeds,
retain one Original each, and produce encrypted 20-KAS admission Output tuples.
Three new namespaces then reopen one read-only Original leaf apiece and recover
the corresponding genuine encrypted output without a private claim map. The
controller independently verifies all three public proofs with no PK mount.
No setup, mining, funding, broadcast, accepted backing or privacy experiment runs.

The backup schema is `kpb-ak-bound-original-seed-backup/v1`. It binds the exact
new ProfileID, domain and `KPBKDF01` tag; the worker refuses legacy backups,
unknown fields, duplicate keys, wrong profiles, aliases and noncanonical seeds.
The ordinary wallet API retains its existing isolated subprocess transports.
The new worker uses direct transports only inside its outer owner namespace,
because this host does not permit nested user namespaces.

Originals and private logs stay beneath the already excluded parent
`/var/tmp/kpi-owner-private-lifecycle-01/private/private-batch-20261028/`.
Public selections and typed receipts stay beneath
`/var/tmp/kpi-private-batch-bootstrap-20261028/`.
The controller checks Original metadata only; it does not open, hash, copy or
decode any private backup, log, note or witness. It has no runtime operation
that imports a seed or broadcasts a transaction. An incomplete attempt retains
its identity; a retry uses a fresh label.

The first actual execution, `new-profile-original-01`, completed in 52.46 seconds:
three genuine Output proofs, three Original-only recovery probes and three
independent public verifications passed. Its public trial receipt SHA256 is
`2190cac2c541cc8a4acf805d8c65b5eb36fd9347fcd5d279e8d4ad543bcc61d3`;
public receipts are preserved at
`.local/private-batch-private-original-bootstrap-01/`.
Seven public-fixture backup tests also reject legacy/wrong-profile formats,
duplicate/extra fields, noncanonical seeds, broad modes and inode aliases.

## Boundary before a privacy experiment

This bootstrap is a functional preparation step. Its private randomness does
not qualify privacy. Before any actual observer trial, the experiment must
freeze the following contract under a new trial identity:

1. Select the exact source/tool closure, workload, fee calculation, hypotheses,
   observer inputs, prediction schema, thresholds and stop rules. Keep the
   existing 21-KAS useful-payment denominator and failed controls unchanged.
2. Each owner retains its seed, openings, output correspondence and scoring
   truth in its own excluded directory. Owner workers may emit salted truth
   commitments before observation; the controller must not read or hash truth
   bodies. A scorer receives only one owner's truth in that owner's namespace
   and emits typed counts. No controller or global dealer assembles witnesses
   or truth across owners.
3. Run the observer in a separate namespace containing only the frozen public
   transcript and explicitly authorized colluder material. Public egress
   includes unaccepted/orphaned proposals. The active observer additionally
   receives the selected cohort and retry/history information. No honest-owner
   private path, Original, seed, backup, invoice, clear witness or raw engine/TLS
   secret is mounted. Raw private engine logs are not a public transcript.
4. Freeze observer predictions before any scoring worker opens its own truth.
   Aggregate scores disclose only the selected metrics, control outcomes and
   coverage. Preserve failures, abandoned proposals and retries without
   threshold, cohort, workload or fee retuning.

Authenticated confidential invoice routing remains an owner-to-owner channel;
successful sealed-box decryption alone does not authenticate a counterparty.
Accepted complete native history/currentness, real batch/R0 proofs and native
settlement remain prerequisites for a financial trial. The public known-seed
six-output fixtures reveal creator associations and cannot be reused as privacy
qualification evidence.
