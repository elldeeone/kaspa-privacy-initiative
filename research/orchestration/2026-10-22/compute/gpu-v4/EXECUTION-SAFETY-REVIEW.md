# GPU v4 execution-safety and provenance review

**Bounded static acceptance of the exact v4 delta. No new source blocker found.** This review permits the orchestrator to consider a fresh bounded setup allocation; it does not release resources or establish runtime, namespace, parity, performance or CUDA qualification. At review, no v4 authored module, installer, attester, mock, observer or GPU operation had run.

Reviewed source is `/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/revisions/v4`. The [proposal](RUNTIME-PROPOSAL.md), [exact patch](runtime-compatibility.patch), [policy](stdlib-external-links.json) and [manifest](manifest.json) are the source record. V3's [failed runtime](../gpu-v3/RUNTIME-RESULT.md) and [qualification receipts](../gpu-v3/RUNTIME-QUALIFICATION.md) remain unchanged.

| Identity | SHA-256 |
|---|---|
| Raw v4 manifest | `2515abffcb08c0ff2e942e5551c21b017b74c7a862e1e0e693ed35db2daa8e61` |
| Frozen v4 STATUS.json | `acbfdeb98e547c2fc15710ee433c8bbb7e8e272ea5abab559bc1acda4555b001` |
| Exact six-file source delta | `6f6e7976c748ecd166196b43868fe19fb9decf2082b89b37290a0ef4588bf645` |
| runtime_identity.py | `9bee4524af4e0c6e76a21612fbb62ee5f42b276b313f3e3149c4eb4d2ddf0f60` |
| External-link policy | `909e556a0bd314f3b2a18b9cb05e1acd8e6761295df622729c318f3b05d927eb` |
| Canonical proposal | `c677580346c85af6b4c87f04d27655359732f20c95d85a473b39f832e112b752` |
| Preserved v3 manifest | `a9765efdc8bbf427cb896a3c34ec58626be75b180611d0e26447d481ec5bf7dc` |

Independent byte checks verified all 28 v4 leaves, totaling 1,006,136 bytes, plus manifest and STATUS closure. No package leaf or directory ancestor is a symlink. The canonical policy and manifest match the frozen originals. The patch exactly reproduces the six source-file differences. All 27 v3 leaves still match their frozen manifest. Inherited mock receipts remain v3 evidence.

## What the delta accepts and rejects

`runtime_identity.py:39–70` fixes the exception to two exact path keys in the exact `/usr/lib/python3.14` tree. The policy is itself a manifest leaf. `setup.py:11–47` verifies package identity before setup operations; the unchanged benchmark verifies it again and pins the installed runtime before dispatch. The exception cannot grant another tree or venv a general external-link allowance.

`runtime_identity.py:72–143` requires each link path, link text, root owner/group, mode and chain; the exact final path; and a root-owned regular target with exact mode, size and SHA-256. It also requires the exact installed package name, architecture, version and status, with every hop and target present in that package's file list. Metadata reads are bounded, reject symlink ancestors and require root-owned regular 0644 files. Named link objects are rechecked after content/package reads. `:145–174` proactively checks both expected relations, so removal or substitution with a regular file does not silently skip validation. Other external links still fail closed.

Independent read-only inspection of Forge matched both policy entries:

| Target | Verified installed identity |
|---|---|
| `/etc/python3.14/sitecustomize.py` | 155 bytes; root:root 0644; `43d81125d92376b1a69d53a71126a041cc9a18d8080e92dea0a2ae23be138b1e`; `libpython3.14-minimal:amd64` version `3.14.4-1ubuntu0.2`. |
| `/usr/lib/x86_64-linux-gnu/libpython3.14.so.1.0` | 8,247,200 bytes; root:root 0644; `982cb3768d1d8b00126255ee2785bccf8360c68b197fb3dec95858ab56195f87`; `libpython3.14:amd64` version `3.14.4-1ubuntu0.2`. |

The first relation has one hop and the second has two, all root:root 0777 symlinks with the exact policy text. Package-record SHA-256 values were `6cfb141a37c72862aac5627e9f1a8e2b065f39522c6e5a2be9fa12732b4b3bca` and `0f91f347e4761a609e47635bbfd2695a071e9271c6e293dc9f89552a1bcd13c8`; file-list hashes were `b4bb2bf9a529dab1cb2699f5769e81fd493a019b38f76ef58d5d6009e932a8fa` and `069c39626e9b2dccf3bf1d5893d8102feba89b31e4829b3593b85cce0c4992cb`, respectively. Local dpkg agreement is not independent upstream signature verification.

## Preserved execution controls and limits

`runtime_identity.py:199–270` retains complete installed-file, stdlib, tool and driver attestation, adds the policy/link evidence, and still rejects an unexpected interpreter/environment. The unchanged pre-dispatch path recomputes and exactly compares runtime identity. The attester only reads these targets; it adds no hook import, subprocess, mount, `/etc` namespace allowance or system mutation. The 155-byte hook installs Apport's exception handler; its imported module was not audited. Earlier normal-Python metadata helpers may have auto-loaded it, as disclosed in the v3 record. This delta review used `/usr/bin/python3.14 -I -S -B` for independent stdlib-only inspection, not the authored validator.

`SETUP.sh:3–5` now quotes and dispatches adjacent `setup.py` using the same `-I -S -B` flags. The setup script's own package/root checks are unchanged. `guards.py`, `launch.py` and `PROVISION-CGROUP.sh` change only the dedicated cgroup basename from v3 to v4. No new allowance reaches existing cgroups. Process identity, bounded cleanup, exclusive lease, active-run guards, pre-allocation cap and whole-device VRAM checks retain the previously reviewed implementation.

`benchmark.py`, `setup.py`, adapter, worker, reference observer/tests, fixtures and expected predictions are byte-identical to v3. Thus no mathematical, timing, warmup, profile eligibility, parity, budget or adoption gate changed. Worker limits remain 2 CPU/4 GiB/no swap/64 PIDs/300 seconds; the 2-GiB allocator and sampled 3-GiB whole-device GPU limits and overall backstops are unchanged. Sampling does not create a hard hardware VRAM limit. Live controller availability and actual enforcement must be qualified afresh.

One non-gating provenance caveat: the v4 manifest retains inherited v3 `changed_v2_files`, `semantic_runtime_change` and `mechanical_revision_changes` summaries. They describe the earlier process-identity revision, not the whole v4 delta. Its explicit `v4_scope`, frozen STATUS and exact patch identify the actual v4 changes. This review does not rewrite frozen metadata.

Before execution, the orchestrator must issue a new release for a fresh exact execution copy; setup must remain capped and fail closed, actual runtime bytes must be pinned, and namespace/control/cleanup qualification must precede observer or GPU measurements. No failed v3 environment or receipt is relabelled successful. The orchestrator's proposed concurrent 12-core proof plus 2-core GPU screen can only supply a **development screen under measured proof load**; it cannot establish uncontended performance or adoption. Numerical criteria remain unchanged. Concurrent privileged mutation of host files is outside the prevention claim; no adversarial race or platform execution was tested by this static review.
