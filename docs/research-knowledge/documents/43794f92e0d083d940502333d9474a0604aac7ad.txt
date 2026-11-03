# Public recovery distribution plan 01

**Status:** Proposed publication recipe; no release, upload, mirror, paid resource or network mutation performed. Checked official sources on 2026-10-23 UTC. Complements [recovery design](DESIGN.md), [capsule API](API-PROPOSAL.md) and [primary-source refresh](../SOURCES.md); changes no frozen schema or earlier evidence.

**Recommendation:** distribute exact public artifacts through a versioned GitHub Release plus a separately administered HTTPS content-addressed mirror and an owner-held offline copy. Split any artifact approaching 2 GiB into 1 GiB raw chunks for the release. Keep capsule staging and trusted profile selection unchanged. Actual provider independence, continued retention and current accepted-chain state require separate evidence.

## Verified distribution facts

| Route | Current official fact | Consequence |
| --- | --- | --- |
| Public GitHub Release assets | At most 1,000 assets per release; each file must be **under 2 GiB**. The docs publish no total release-size or bandwidth quota. [Release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas) | A multi-GiB PK needs chunks. This is a practical public delivery route, not a promise of unlimited service or indefinite retention. |
| Release download API | Public resources can be downloaded without authentication; binary retrieval can return 200 or redirect with 302. Responses expose size, SHA256 digest and stable browser download location. [Release asset API](https://docs.github.com/en/rest/releases/assets#get-a-release-asset) | Verify full bytes against independently selected hashes. A release adapter must handle redirects safely; never persist temporary signed redirect URLs as identity. |
| Immutable releases | Published assets/tag cannot be changed; publication creates an attestation. A whole immutable release can still be deleted. Draft, attach everything, then publish is the documented order. [Immutability](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) | Useful mutation resistance if enabled; it does not establish retention, setup honesty or canonical profile selection. Do not infer the current repository has enabled it. |
| GitHub hosting policy | GitHub reserves throttling/suspension and repository removal for excessive resource use. [Acceptable use](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies#9-excessive-bandwidth-use) | The absence of a published release bandwidth quota is not an availability guarantee. |
| GitHub Pages | Available for public repositories on GitHub Free; published sites are limited to 1 GB, with a soft 100 GB/month bandwidth limit. [Pages limits](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits) | Suitable for a small manifest/documentation index, not the multi-GiB PK or a full history archive. A second GitHub route remains the same provider. |
| GitHub Actions artifacts | Default retention is 90 days; deletion of a workflow run deletes its artifacts. Public-repository retention is configurable only within 1–90 days. [Artifact lifecycle](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/remove-workflow-artifacts), [retention settings](https://docs.github.com/en/organizations/managing-organization-settings/configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-organization) | Build handoff only; do not make this the long-term recovery dependency. |

The scoped repository's [public releases endpoint](https://api.github.com/repos/olafweller/kaspa-privacy-initiative/releases) returned `[]` during this read-only check. That establishes no listed public release at that observation; it says nothing about unpublished/private assets or other providers. The release documentation specifies no automatic expiry analogous to Actions artifacts, but offers no perpetual-retention commitment.

## Provider-neutral layout and chunk contract

The canonical staging layout remains:

```text
/capsules/<capsule-manifest-sha256>.json
/objects/sha256/<complete-object-sha256>
```

Use static, verified HTTPS endpoints with ordinary full-object GET. No account, owner key or private scan query should be required. Locations are transport hints supplied separately from installed trusted selection. A DNS name, TLS certificate or mirror's own manifest does not select the financial instance or make history current.

The capsule's exact five typed object references remain unchanged: descriptor, history, parameters manifest, public parameters and software inventory. The externally selected compact role/PK/VK/descriptor/software identities remain authoritative. Recognition can omit downloading the PK; a compact exit requires the exact compact PK, never the wide PK.

For oversized release assets, propose a **separate publication index**, not extra fields in the capsule API. Each public object record contains:

| Field | Required meaning |
| --- | --- |
| Complete object identity | Existing kind, exact raw-byte length and full SHA256 from selected capsule/static pins. |
| Chunk sequence | Zero-based contiguous index, byte offset, exact length, chunk SHA256 and safe asset basename. |
| Chunk rule | Fixed 1,073,741,824-byte chunks except the final remainder; offsets cover the complete object exactly once with no gaps/overlaps. |
| Reconstruction | Concatenate raw chunks in index order; independently recheck final length and complete-object SHA256 before installing at its CAS path. No archive extraction or compression required. |
| Transport inventory | Stable release asset IDs/URLs and independently configured HTTPS roots; no credentials, query tokens or private paths. |

This is a proposed adapter contract, **not implemented support** in current capsule staging. The HTTPS wrapper fetches complete CAS objects. A future explicit chunk assembler or mirror-side reconstruction must finish and authenticate the complete object before handing it to that wrapper/stager. Chunk hashes enable retry and identify corruption; only the already selected complete-object identity authorizes the reconstructed bytes. Measure the actual compact PK before deciding whether it needs chunks; a larger wide PK is not an owner-recovery dependency. Neither a new setup nor merely the same source can regenerate the existing randomized Groth16 artifact.

## Reviewable publication recipe

1. **Prepare public bytes locally.** Freeze exact selected profile/software/VK/compact-PK identities, capsule and publication index; record full lengths/hashes. Include only deliberately public history. Exclude backups, seeds, witness files, owner/index maps and discarded overlapping Auth/NF preparations. Keep the owner's private backup separately; it is never a release asset.
2. **Prepare the release set.** Use a neutral versioned tag pinned to the reviewed source commit. Small JSON/VK/history objects can be single assets. Chunk large PK/history objects using the rule above and keep the asset count below 1,000. Record exact names and independently verify every reconstructed object before any future upload. Source ZIP/TAR alone is not proof that parameter/history assets are included.
3. **Publish one complete generation together.** When publication is authorized, use a draft release, attach all assets/indexes, verify API size/digest against local identities, then publish; enable/use immutable releases only as an explicit repository choice. Record the resulting tag commit, release ID, asset IDs and immutable flag. This document does not perform that action.
4. **Replicate outside that administration/provider.** Have a genuinely separate operator hold complete authenticated objects at the CAS paths on existing HTTPS capacity; obtain a stated retention/expiry policy and restoration contact. An ordinary static HTTPS server is sufficient for the protocol; no particular free storage capacity or durability is assumed. Keep an offline complete copy as a third failure domain. Different directories, hostnames or regions under one account do not establish independent control.
5. **Exercise and maintain retrieval.** Restore from each provider alone with the original cache/operator source unmounted; check every byte, then run semantic replay/currentness checks separately. Record dated full-download observations and failures. Recheck periodically under an explicit owner-chosen retention plan; restore lost replicas from a surviving verified copy and recheck them. A successful check is evidence for that time, not future availability.

History changes produce a new capsule/history digest, not an overwritten old object. Retain generations required to reconstruct accepted history; an unauthenticated “latest” pointer is discovery only. A seed plus an intact PK still cannot reconstruct lost ciphertext/context history.

## Decisive retrieval controls and claim boundary

Coordinate with the recovery lane's HTTPS-to-CAS wrapper: external trusted base URL plus `/objects/sha256/<digest>`, verified TLS, exact streamed length/SHA and fallback only for the same selected object. Its selected redirect policy permits at most five HTTPS-to-HTTPS redirects, including cross-origin public CDN locations; reject URI credentials/fragments and any downgrade. The initial base rejects query strings; a redirected signed query must never enter logs. This requires tests and does not implement a GitHub asset resolver: release URLs do not naturally expose the CAS path, so direct downloads still need an explicit publication adapter or CAS gateway. Never execute downloaded code, infer role from filenames or disable TLS.

Use public synthetic fixtures for these controls; chunk-specific cases apply only if that future adapter is implemented:

- Original cache unmounted: retrieve over the actual transport, stage a fresh CAS, and verify the complete bytes survive loss of the serving source.
- Bad/missing first mirror: fall back to a second origin serving the **same** expected object; all sources bad means incomplete.
- Truncated, appended, wrong-role, stale-index or reordered chunk data: reject before private backup/witness access.
- Recognition with no PK available: report only recognized material; spend-material mode must not claim readiness.
- Cold reconstruction from every chunk: one missing/corrupt chunk fails; reordered chunks cannot be accepted through a matching chunk list without the full-object hash.
- Semantic history/currentness: intact download of a stale/reorged capsule never authorizes a spend or proves present balance.

A local loopback HTTP test establishes transport logic only. Real verified HTTPS retrieval establishes endpoint reachability and byte identity at a time. Two independently controlled providers plus dated repeated complete retrievals strengthen availability evidence, but do not prove perpetual retention, consensus currentness, privacy, setup honesty or a valid independent exit. Network requests can expose IP/timing and the selected profile; broad public downloads avoid owner-specific history queries but are not network anonymity.

