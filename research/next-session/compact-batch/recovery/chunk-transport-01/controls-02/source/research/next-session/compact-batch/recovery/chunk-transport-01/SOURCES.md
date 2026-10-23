# Chunk transport: narrow primary-source review

Checked 2026-10-23 UTC. Scope: optional ordered raw-chunk retrieval before the existing public-object CAS/capsule stage. **No PK download, upload, installation, provider selection or network mutation.** The earlier [distribution plan](../DISTRIBUTION-PLAN-01.md) remains byte-identical; this note does not claim an implemented adapter or passing controls.

**Conclusion:** reuse established fixed-output authentication and ordered chunk reconstruction. An untrusted chunk index can guide retrieval; the independently installed **complete raw-object byte length and SHA256** remain authoritative. Authenticate the complete owned object before CAS installation, parameter decoding or private-input access. No new cryptographic construction is needed.

## Primary analogues and exact boundaries

| Primary source | Reused/adapted | Rejected assumption |
| --- | --- | --- |
| Nix [fixed-output definition](https://nix.dev/manual/nix/2.33/glossary#gloss-fixed-output-derivation), [output hash attributes](https://nix.dev/manual/nix/2.33/language/advanced-attributes.html#adv-attr-outputHash), [flat file addressing](https://nix.dev/manual/nix/2.33/store/file-system-object/content-address.html) | Expected content identity is chosen before a network fetch. Keep the selected raw SHA256 independent of URLs and the fetched index. Flat file-content identity is distinct from an archive/store representation. | Do not substitute a NAR/store-path digest for the selected raw PK hash, infer a trusted hash from downloaded bytes, or import Nix execution/daemon privileges. These are versioned manual semantics, not an assertion about an installed/latest Nix release. |
| IPFS [UnixFS file structure](https://github.com/ipfs/specs/blob/3000be69497e47c399cdb719440d0809f085388b/src/unixfs.md#311-dag-pb-file), [CID distinction](https://docs.ipfs.tech/concepts/content-addressing/#cids-are-not-file-hashes) | Preserve ordered positions, paired lengths and complete reconstruction. UnixFS requires each file link to have a corresponding size and rejects mismatched lists. | A UnixFS root/CID identifies a particular encoded graph, not the flat SHA256 of the reconstructed raw file. Chunking/layout/metadata can change that root. Do not replace the existing whole-object identity with a new DAG root or claim UnixFS wire compatibility. |
| IPFS [persistence/pinning](https://docs.ipfs.tech/concepts/persistence/) | Treat authenticated identity and retained availability as separate properties. | Content addressing does not ensure any provider retains the chunks; caches can be garbage-collected and providers can disappear. IPFS or a pinning service is not selected here. |
| GitHub [release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas) | Rechecked: each asset must be under2GiB; at most1,000 assets/release. A1GiB raw chunk fits the per-asset limit. | Fixed1GiB is this transport's local policy, not an IPFS block-size recommendation, a retention guarantee or permission to create a release. |

Pinned UnixFS source: official `ipfs/specs` main observed at **`3000be69497e47c399cdb719440d0809f085388b`**, file `src/unixfs.md`, Git blob **`cbe53d550f3f3cc814600bb5a7c24dc09bb4fb28`**. The rendered specification is marked draft; only the stated design analogues are adapted. No upstream security claim transfers.

## Minimal derived contract

Let **T** be the externally selected positive complete-object length and **G=1,073,741,824** bytes. Expected chunk count is `ceil(T/G)`; position i has offset `i*G` and exact length `min(G,T−i*G)`. Use exact integers.

1. Before chunk retrieval, require any index-declared whole length/hash to equal independently selected T/SHA. Strictly parse the index; forbid duplicate JSON fields, unsafe names/paths, unsupported encodings and arbitrary URL/command/import authority. Location hints use the separately trusted transport-root policy.
2. Require all positions once, in order, with those derived offsets/lengths: no gaps, overlaps, zero-length extra tail or missing final chunk. **Repeated chunk hashes at different positions are legitimate** when bytes repeat; duplicate positions are not. Do not confuse deduplication with deletion of a file segment.
3. Stream each raw chunk into newly owned temporary storage, checking its declared length/hash and the running whole-object length/hash. A chunk hash supplied by the same untrusted index is a useful corruption/retry check, not independent authenticity. Fallback must target the same selected object, with final whole authentication unchanged.
4. Reject truncated/appended/reordered/mixed bytes or a self-consistent replacement index unless the completed raw object matches **both** selected T and SHA256. Install only after complete authentication, preserving the existing metadata-alias/symlink guard and atomic/exclusive CAS handoff. No archive extraction, downloaded executable, sparse-hole shortcut or partial-object parameter decode.
5. Hand the reconstructed object to existing capsule/role/VK/dimension checks. Success means selected public bytes were recovered; it never sets accepted-chain currentness, recognized balance, spend authorization or setup honesty.

A useful negative is “every chunk matches a malicious index, but the final raw hash differs”: it must fail before handoff. Also retain missing-final, duplicate-position, changed-offset, wrong-role/domain, appended-data and original-cache-unmounted controls. Tests can use tiny synthetic chunks only under an explicitly separate test parameter; a tiny-chunk pass does not measure1GiB memory/I/O or prove large-object support.

This adapter remains transport. TLS/redirect safety, privacy of request metadata, provider administration/retention, fresh accepted history, exact parameter identity during use and private backup recovery remain separate obligations. No independent-provider or long-term-availability result follows from two local directories, two local servers or one successful download.

