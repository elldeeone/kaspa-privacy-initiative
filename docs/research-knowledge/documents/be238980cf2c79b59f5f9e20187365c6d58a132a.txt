# Private-batch observation and isolated scoring

Source integration only. No actual private workload, Original, financial truth
or corrupt-server view was opened while implementing these files. The fixed
prospective method remains unchanged. Its strict global creator-swap H1 is
expected to fail under legitimate recipient knowledge; see the separate
[source counterexample](privacy_SOURCE_COUNTEREXAMPLE.md).

## Reuse and scope

The finite creator-partition enumeration and legitimate incoming-receipt facts
adapt `poc/owner-private-payments/wallet/score_codec.py` and `score_worker.py`.
The salted private prediction capsule, one reserved query, owner-local truth
join and isolated count aggregation retain the existing `SCORING-API.md`
boundaries. New input-owner permutations are scored separately from output
creator assignments and label-invariant output pair partitions. No tie-break
guess is reported as a uniquely recovered fact.

This literal direct-fact strategy does not model all cryptographic transcript
information or terminal economic constraints. Unknown dispatcher artifacts,
complete raw corrupt-server material and unmodeled terminal observations remain
**UNQUALIFIED**. An available but unmodeled file cannot become a privacy pass.
Missing views remain missing even if some modeled constraints retained truth.

## Owner hooks and exact bindings

All records bind `method_sha256`, exact prospective `selection_sha256`, canonical
`trial_id`, phase `private-batch-privacy`, and `attempt_id`. Each truth additionally
binds its round and SHA256 of the exact approved276-byte head context. The final
projection does not exist during owner input preparation; the scorer later
joins the original context, NF and two whole tuple hashes/CMs to that actual
selected public projection.

After the real restricted intent and owner record have been constructed inside
the existing owner namespace, call:

```python
privacy_owner.write_truth(
    config['privacy_binding'], config['owner_component'], round_number,
    head.encode(), claim.nf, [created[0].row, created[1].row],
)
```

The hook checks the one-owner/pay/network-off marker and exact owner config.
It creates only `/owner/PRIVACY-TRUTH.json`0600 and a public0400
`/out/PRIVACY-COMMITMENT.json`. The latter contains common bindings, owner/round,
a SHA256 commitment salted by fresh private32-byte randomness, and the fixed
no-export flag. It contains no NF, tuple/CM hash, fee, Delta, intent hash or seed.
The controller may admit the public sidecar; it must never open or hash the
private truth envelope or its salt.

The owner1 colluder's later isolated role calls
`privacy_observer.colluder_facts(receiver, own_record, round, raw_projection,
actual_routes)`. This verifies its actual input and two created rows, decrypts
all six CFs, and includes its genuinely known incoming creator. The function
requires all three actual invoice route records; it cannot silently substitute
an uncaptured route for complete observation. Save its result only in a private
`kpb-private-colluder-constraints/v1` envelope binding the same context and round.
No honest owner record is an observer input.

Each actual trusted invoice mount must retain this metadata, derived from the
executed command rather than a later asserted count:

```json
{"schema":"kpb-observed-invoice-route/v1","round":1,
 "source_owner_component":0,"target_owner_component":1,
 "invoice_leaf_path":"ACTUAL_PRIVATE_PATH/INVOICE208.bin",
 "source_operation_id":"ACTUAL_PAY_ID",
 "target_invoice_operation_id":"ACTUAL_INVOICE_ID",
 "launch_monotonic_ns":100,"complete_monotonic_ns":200,"worker_returncode":0}
```

The route, filenames, roles and operation timing belong to the declared
dispatcher view; the invoice body stays confidential. Trusted local routing is
the authentication assumption. A corrupt dispatcher is not authorized to
replace that trusted channel, and encryption alone does not authenticate it.
Keep attempted routes when the worker refuses; a nonzero return code is an
observed failed operation, not permission to delete its route or timing.

## Actual diagnostic worker roles

`privacy_roles.py observe|score|aggregate` refuses direct host execution. A
trusted finite launcher supplies `/NAMESPACE.json`, an immutable `/CONFIG.json`,
network-off `/proc`, selected public source leaves and exactly the role mounts.
The marker schema is `kpb-private-diagnostic-namespace/v1`, with operation,
`network:"disabled"`, and exact truth/colluder/corrupt-server slot counts.
The worker refuses visible host private roots and unexpected cross-role mounts.

1. **Observe:** no honest truth is mounted. Reserve fixed
   `/state/OBSERVATION-CLOSED` before private observation. Produce all four
   declared views and both rounds in one invocation. Each view creates a
   salted private0400 `PREDICTIONS-VIEW.bin` and a public count/coverage receipt.
   The private capsule holds complete canonical candidate assignments and all
   extracted constraints. A root/controller must not read, hash or copy it.
2. **Freeze:** the trusted controller writes one immutable public
   `kpb-direct-prediction-barrier/v1` binding the exact observation receipt hash
   and all four already-emitted capsule seals. This public barrier is fixed
   before any owner truth join. An imported success Boolean is insufficient.
3. **Score:** mount only one owner's two original truth envelopes, their public
   commitments, the four original read-only capsule leaves and public barrier.
   Reserve fixed `/state/SCORING-CLOSED` before opening truth/capsules. Score all
   four views and both rounds in this single query. Write private0400
   `/state/COUNTS.json`; the public response gives no per-owner score or masks.
4. **Aggregate:** mount only all three distinct original private count leaves,
   the four prediction capsules and public barrier/receipt. Mount no Original,
   truth, wallet, corrupt-server state or proving key. Intersect the three
   candidate-membership masks before reporting global truth retention and honest
   swaps. Separate correct unique predictions from wrong unique predictions.
   Export global counts/categories only.

The launcher must bind diagnostic state to the selected Original owner's one
persistent diagnostics directory, never a caller-chosen fresh experiment path.
The count/capsule leaves must be regular, single-link0400 original leaves; truth
must be regular single-link0600. Only metadata is admitted in the controller.
Journal/marker creation syncs both file and parent directory. A refused or
interrupted query is retained, not reset to create a scoring oracle.

The finite launcher integration and final source/artifact route selection must
be reviewed before actual use. No standalone launcher that accepts arbitrary
private roots or private file-body input is provided here.

## Counts and retained failures

With the colluder's own input/two outputs fixed and no incoming creator fact,
the direct model has2 input permutations,6 creator assignments,3 unlabeled pair
partitions and12 joint candidates. Its legitimate known incoming creator leaves
2 input permutations,3 creator assignments,3 pair partitions and6 joint candidates.
The honest input swap remains; the full creator swap does not. A pair-tag
control reduces the creator partition to1, while a full constructor map reduces
the joint candidate set to1. These are exact public model counts, not observed
financial results, posterior probabilities or cryptographic privacy evidence.
The NF-to-created-pair relation is separately quotiented by creator labels:
legitimate incoming creator knowledge still leaves6 such joint relations, with
one public NF having1 possible created pair and two having6 each. Only that
histogram is exported; publishing an ordered per-NF vector could identify the
colluder's private input. Correct and incorrect unique pair-link predictions
are scored separately from owner/creator labels.

Required checks exercise the finite full candidate set, actual literal pair-tag,
constructor and individual-Delta control extraction, incorrect unique guesses,
missing/unmodeled views, candidate/context/commitment tampering, joint membership
intersection, exact route records, and an actual network-off one-owner scorer
over deliberately public fixture truth with a repeated-query refusal. The
private actual-wallet study remains held until the root's complete run selection.
