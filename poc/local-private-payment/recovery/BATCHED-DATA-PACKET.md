# Bounded whole-page publication audit preparation

Source-only resource sibling. `prepare_data_packet.py` (239bb48b) and
`prepare_data_packet_tmpfs.py` (e958bd50) remain unchanged. No actual terminal
selection, private original, owner worker, network or publication is selected by
this documentation or producer.

`prepare_data_packet_batched.py` loads only the guard09-authenticated e958
preimage. Its twelve roles, terminal metadata shape, both page-list closure,
private-path exclusions and gzip decoder are reused unchanged. It verifies every
gzip member of every main/post-query page and discards decoded bytes. It emits
the same exact four release object bytes: `data.tar`, `DATA-INVENTORY.json`,
`PACKET.json`, `SHA256SUMS`. Only the new local public audit descriptors differ.
The canonical whole USTAR remains unchanged; multipart transport is separate.

The producer verifies each canonical tar header/name/offset, exact member bytes,
SHA/size and canonical zero trailer against the original pinned public source
leaf. Those read-only aliases supply raw member canary candidates without a
second physical extraction of the raw tar members. Guard09 currently returns
whole selected files; the complete raw archive is authenticated in memory. This
removes simultaneous decoded-page retention and duplicate raw extraction, not
the memory required for the whole archive guard read.

## Prepare once, after Root freeze and review release

```text
python3 prepare_data_packet_batched.py prepare \
  --selection ABS --selection-sha256 HEX64 --output FRESH_PUBLIC_CHILD \
  --decoded-budget-bytes GENEROUS_INTEGER
```

The existing Root selection is unchanged. Output is one fresh direct child of
the two e958 public parents. The decoded budget is explicit and must fit the
largest whole decoded page. It changes audit scheduling only. No page is split,
sampled, omitted or treated as covered because another page was checked.

Optional explicit additional public source/evidence can be bound into BASE:
`--base-extra-allowlist ABS --base-extra-allowlist-sha256 HEX64`, schema
`kpxa-publication-base-extra-candidates/v1`, exactly
`{schema,domain_hex32,files:[{source,path,bytes,sha256}]}`. No directory crawl.

New descriptors, intended for separate public metadata audit:

1. `GLOBAL-CANDIDATE-INDEX.json`, schema
   `kpxa-publication-global-candidate-index/v1`, exactly
   `{schema,domain_hex32,root_selection_sha256,archive:{bytes,sha256},candidates}`.
   Each candidate is exactly `{index,path,bytes,sha256,kind,source,gzip}`.
   Indices are contiguous. `kind=raw` has a public source and `gzip=null`;
   `kind=decoded` has `source=null` and an exact gzip selector
   `{source,bytes,sha256}`. Raw paths are sorted first, then decoded paths.
   `raw/*` selects the four artifacts; `members/*` selects verified tar-member
   aliases; `extras/*` selects explicit additional rows. Every whole decoded page
   is `decoded-gzip/chain/<fetch-page-relative-path>`, preserving its decoded
   artifact pathname for the unchanged workers' path scans.
2. `BATCH-PLAN.json`, schema
   `kpxa-publication-whole-page-batch-plan/v1`, exactly
   `{schema,domain_hex32,global_index_sha256,operator_decoded_budget_bytes,batches}`.
   Each batch is `{batch_id,candidate_indices,bytes}`. BASE contains every raw
   row; D000001 onward greedily partition all decoded rows in index order, each
   nonempty and within the budget. The union is exact and disjoint. BASE bytes
   are logical coverage bytes, including aliases; they are not storage used.
3. `BASE-BATCH.json`, and later D*-BATCH.json, schema
   `kpxa-publication-audit-batch/v1`, exactly
   `{schema,domain_hex32,global_index_sha256,batch_plan_sha256,batch_id,
   candidate_indices,files}`. Files retain `{source,path,bytes,sha256}`.

## Materialize one whole decoded batch

```text
python3 prepare_data_packet_batched.py materialize \
  --index ABS/GLOBAL-CANDIDATE-INDEX.json --index-sha256 HEX64 \
  --plan ABS/BATCH-PLAN.json --plan-sha256 HEX64 --batch-id D000001 \
  --output /dev/shm/kpi-local-private-payment-publication-01/FRESH_CHILD
```

The exact public tmpfs parent must already exist, owned by the operator with
mode0700. This command authenticates pinned descriptors, reconstructs the exact
deterministic plan, reauthenticates selected gzip bytes and writes each complete
decoded file once with mode0400. A batch descriptor is saved beside the global
index only after every complete decoded byte identity passes. Partial files can
remain after failure; no PASS descriptor is emitted. This source never deletes
files or starts audits. The separately reviewed controller owns scheduling and
must release a completed batch before retaining the next when capacity requires.

## Audit and self-reference boundary

The global primary candidate index intentionally excludes its own bytes, plan
and batch descriptors. It cannot include their own hashes recursively. A
separate externally Root-pinned DESCRIPTORS stage must scan **all public global
index, plan and every public batch selector**, for every nine original with both
unchanged literal and derived workers. Primary BASE+D coverage is insufficient
without those eighteen descriptor-stage PASS reports and exact descriptor hash
joins. Original metadata, owner/context routing, audit releases and worker
manifests remain local unpublished operator inputs. Public descriptors contain
no owner routes. No self-audit or all-secret/privacy claim follows.

The controller must bind global index/plan SHA, each batch selector SHA and every
candidate identity, and prove the complete nine-original-by-every-batch coverage
matrix. Existing workers remain unchanged: literal0d3d7cbe, derivede4c466cd.
Accepted-history versus creation-only scope remains the separate launcher's
responsibility. No count or role inferred here supplies financial acceptance,
recovery authority, native execution, future-material or mainnet claims.
