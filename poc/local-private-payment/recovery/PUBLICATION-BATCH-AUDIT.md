# Bounded whole-page publication audit

This is a separate resource workflow. The financial caller, old launcher c465,
literal checker 0d3, derived checker e4c and positive worker b812 stay unchanged.
Actual Original use requires the final, separately reviewed Root release.

The producer pins one global candidate index to the Root selection. The
coordinator independently joins the selection, packet, inventory and **both**
fetch page arrays to that index. A fresh self-consistent index SHA cannot omit
a page. BASE contains the whole raw USTAR, its metadata, and every raw member
alias. Aliases require exact archive header/name/order/size/payload equality;
they do not create a second physical member tree. Decoded candidates preserve
whole page bytes. A page is never split or silently excluded to fit a budget.

The primary plan is an exact nonempty partition: BASE followed by D000001,
D000002, and so on. Every one of the nine approved Originals must run **both**
unchanged checkers against every batch. Per-batch descriptor, release and local
candidate-manifest hashes are distinct from the global index hash. Missing,
duplicate, overlapping or foreign rows, changed source/H-C/assets, missing
decoded verification, a missing worker result or any non-PASS result refuses
the global result.

Each accepted-history batch receives a fresh immutable scope file. Only its
local candidate-manifest SHA changes; all twelve provenance roles and the same
HISTORY and CONTEXT bytes and all twelve original role identities bind the
Root-selected dataset. The original role.assets remains distinct from a
separately Root-selected portable /public/ASSETS.json; that portable manifest
is identical across every actual02 audit and all three positives. Creation-only context
is never promoted into accepted-history context. The same three actual02
Originals also run unchanged b812 once each against that same accepted
context: two use the approved received-input policy and one the change-input
policy. Each positive privately checks its three distinct historical exits.
The coordinator joins those three positives to the same Original metadata
used in every batch. It exports no own NF, key, value, index or owner map.

The public GLOBAL index, plan and all public batch descriptors receive a
supplemental DESCRIPTORS stage, again nine Originals times both checkers.
Additional public metadata, such as DATA-PARTS.json, may be explicitly selected
alongside those mandatory files. It cannot replace a mandatory descriptor.
Transport slices are covered only by a separate exact ordered extent/SHA
reconstruction to the fully scanned raw archive, not as independently audited
new content. The
primary index excludes these later metadata bytes to avoid recursive hashes.
The supplemental release, routes, materialization receipts, execution journal
and per-Original reports remain local and unpublished. A later decision to
publish any additional metadata requires adding its exact bytes to the audit
universe. No self-audit or future-material coverage is claimed.

Execution is serial: one Original at a time, with separate literal and derived
namespaces. The prepared-public launcher derivative admits each public batch
and its fixed contexts once, then supplies that explicit read-only snapshot to
the per-Original jobs. It must retain current metadata/alias checks for both
canonical large leaves and staged small/source leaves, plus the old Original
metadata checks before and after each namespace. The unchanged workers still
authenticate every candidate before reading the Original. There is no helper
override, interpreter shim, private cache, shared Original descriptor or
private worker loop. The selected prepared launcher 80bc uses trusted-host read-only paths for
large ordinary single-link files and stages small candidates and sources.
This is **not sealed storage** and assumes no concurrent host mutation. The
actual prepared source pin and old c465 base pin are recorded separately, with
current metadata checks before and after each worker. Admission/worker-pair
times and physical resource counts are retained explicitly.

Only the current decoded batch is materialized in a fresh approved tmpfs
child. After all nine jobs pass and receipts are saved, the controller removes
only its own decoded tree. Prepared public stages and reports remain; they
are not silently reclaimed by this controller. Reports and
descriptors remain. A failure leaves the current tree and local evidence for
review and emits a generic refusal without private paths.

Capacity planning uses actual archive A, the largest whole leaf, decoded batch
budget and source staging, with generous headroom. Serial execution prevents
four simultaneous A-sized admissions. Root measured one known-public 1,941-byte
c465 admission at 3.154 seconds plus 1.548 seconds for one metadata-set check
under the current host load; that single tiny-file measurement is not a
large-file or overall bound. Source and per-stage elapsed times remain local
until they can be reported without an Original route.

The public result contains booleans and public coverage/source identities.
Local execution receipts are a trusted-controller join, not a cryptographic
attestation that a malicious host executed a particular Original. The known
creation flow and Root-selected metadata distinguish the nine random
Originals from public fixtures and restored copies. This audit is a finite
secret-export canary, not general privacy, security or independent-host proof.

The BASE authority is the externally selected complete fbc producer preparation
report, including the archive identity, exact candidate/page counts and actual
BASE descriptor. The controller reruns its selected exact USTAR/member-alias
byte comparison once before any Original metadata operation. A free-standing
`verified:true` marker is not authority.

Execution has an explicit stop/resume boundary. Primary completion writes a
local checkpoint and **does not** claim global PASS. Root externally selects the
supplemental descriptor release after those descriptors exist. The resume
revalidates the complete primary grid, exact source/context/Original routes and
coverage, then runs all nine descriptor pairs and the three positives. Primary
Original jobs are not rerun to construct the supplemental release.

CLI (all selectors externally pinned; local routes and results unpublished):

1. `publication_batch_controller.py --execution-plan PLAN --selection-sha256 SHA --output FRESH`
   validates public inputs only. Add `--execute` only after Root's final release;
   it stops after the primary checkpoint.
2. If more public metadata is generated, use `--prepare-supplemental SELECTOR
   --selection-sha256 SHA --output FRESH` without `--execute`. The selector schema
   `kpxa-publication-descriptor-preparation/v1` contains `execution_plan`,
   `primary_journal` and exact `extra_metadata` file rows. This public-only action
   creates a new local release for Root to select; it runs no Original workers.
3. `--resume-descriptors RELEASE --selection-sha256 SHA --output FRESH --execute`
   requires externally selected `kpxa-publication-descriptor-resume-release/v1`
   with `execution_plan`, `primary_journal` and `descriptor_release` selectors.

Outputs must be fresh owned local paths under `publication-audits`. Final
booleans claim exactly the primary global union plus the selected supplemental
metadata union. New later bytes require another explicit audit; no future
publication coverage is implied. All per-Original routes, raw worker receipts,
metadata identities and context releases stay local and unpublished.
