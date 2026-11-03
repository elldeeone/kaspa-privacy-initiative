# Public provider and retention observations

Checked 2026-10-23 UTC. This is read-only research and an observed inventory, not
an operator agreement or a long-term availability qualification.

GitHub permits up to1,000 assets per release, each under2GiB; its published
release documentation specifies no aggregate release-size/bandwidth limit. The
selected1GiB raw chunks fit that per-asset rule. Public binary asset GET supports
anonymous access and either direct200 or302 to the binary location. The adapter
therefore authenticates selected raw bytes after every allowed HTTPS redirect;
asset API metadata and URLs do not select the instance.
Sources: [release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas),
[asset download API](https://docs.github.com/en/rest/releases/assets#get-a-release-asset).

Immutable releases protect attached assets and the tag after publication, with
an attestation. They do not prevent deletion of the release itself. The documented
workflow attaches all assets to a draft before publication. Whether this actual
release uses immutability must come from its observed metadata, not this recipe.
Source: [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).

GitHub may throttle or suspend excessive use; a storage/bandwidth limit statement
is not an independent retention contract. Actions artifacts default to90-day
retention and disappear when their workflow run is deleted. Published Pages
sites are limited to1GB, so they cannot hold the1,307,894,256-byte compact PK.
Neither route creates a different provider/control domain.
Sources: [acceptable use](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies#9-excessive-bandwidth-use),
[Actions lifecycle](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/remove-workflow-artifacts),
[Pages limits](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits).

## Actual observations and open dependency

The anonymous public [repository API](https://api.github.com/repos/elldeeone/kaspa-privacy-initiative)
reported a public repository owned by `elldeeone`; the
[public releases API](https://api.github.com/repos/elldeeone/kaspa-privacy-initiative/releases)
reported zero published releases at the saved pre-publication observation.
Those response bytes/hashes are retained in `provider-observation-01`; a draft
or later publication can legitimately change the result.

The new downloader actually retrieved the selected2724-byte compact parameter
manifest from a commit-pinned GitHub raw URL with system TLS verification and
its independently selected `f27a8069…` hash. This establishes real external HTTPS
reachability and exact manifest bytes at that time. It does not establish a
public PK download, release-CDN redirect, retention or a second operator.

The subsequent [public release](https://github.com/elldeeone/kaspa-privacy-initiative/releases/tag/native-kas-recovery-2026-10-23)
was published at22:51:30Z, release ID422373283, with19 audited assets. The fresh
post-publication metadata is retained in `PUBLISHED-RELEASE-02.json`; record01
keeps the earlier draft-URL snapshot and is explicitly superseded. The release
was observed mutable, not immutable.

The source-only client then downloaded and restored the whole selected compact
PK, software archive and exact member index over verified HTTPS in125.689s.
All11 response entities passed their independently selected length/SHA; actual
redirects were GitHub HTTPS302 to its HTTPS release CDN. Four original source/
cache/repository/controller paths were absent; no backup/prover was mounted and
downloaded software was not executed. `full-HTTPS-01` retains the evidence.
These actual downloads improve the initial reachability observation while
leaving the same-provider, retention, soundness and currentness boundaries intact.

Root's authorized account inventory found GitHub access for this repository and
no separately controlled mirror already available. Unrelated infrastructure was
excluded. An owner question for an existing independent operator/access remains
pending. No account/service, billed resource, external message or upload was
created by this lane.

| Candidate | Observed scope | Administrative failure domain | Retention result |
| --- | --- | --- | --- |
| Repository raw source | Actual verified HTTPS manifest GET | Same GitHub repository/account as proposed release | No independent commitment |
| Published GitHub Release | Actual complete compactPK/software HTTPS restore | Same GitHub repository/account | Provider deletion/control risk remains |
| Prepared offline/CAS tree | Whole compact PK restored network-off with original paths absent | Same host/storage in this experiment | Portable copy; no offsite/host-loss evidence |
| Separate HTTPS operator | No endpoint/control evidence yet | Unknown | Open |

Before calling a second copy independent, record the actual operator identity,
separate administrative credentials/control, host/storage provider, object root,
retention/expiry/deletion policy and a dated complete restore using that copy
alone. A DNS alias, CDN redirect, second bucket under one account or local server
does not establish that separation. This requirement is an engineering inference
from the failure model, not a guarantee offered by the cited providers.
