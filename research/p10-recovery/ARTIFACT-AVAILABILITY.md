# P10 public artifact availability

At upstream main `cde2b88de3a16af401a2046bd90a124aa105418a`, the exact wallet proving parameters are a public-data dependency with **no distribution location found in the checked upstream channels**. This is an availability finding, not evidence that the parameters never existed or are secret.

The recorded artifact is `public-proving-parameters.bin`, **156,439,536 bytes**, SHA256 `812b3bda0ec5f9b0c17fc1d530e49fc21defc9dcc5ea9c70a133ca62fec31e99`, for wallet VK `d3c179aae5c2c6c013b1de1da5ad4412e4b2c8bae7288c0b9d85e0c986b5a3ec`. Sources: [generation.json:113–123](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/private-note-chain/evidence/public/generation.json#L113-L123), [restore-report.json:3–9](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/private-note-chain/evidence/public/restore-report.json#L3-L9).

## What was checked

| Channel | Result |
| --- | --- |
| Git tracked files | No tracked `public-proving-parameters.bin`. The README explicitly says these parameters remain in ignored local storage. |
| Tracked public tar archives | Listed all six archives under `poc/private*` and `poc/remote-cuda`; none contains a setup/parameter file. The two relevant workload archives use exact allowlists, not a directory copy. |
| GitHub releases | Releases API returned `[]`; no release asset route was present. |
| Actions artifacts | API returned three artifacts, all non-expired. Downloaded all three using authenticated `gh`; every ZIP contains only image smoke JSONs and an image digest text file. Each expires on 2027-01-16. Anonymous ZIP download returned HTTP 401. |
| GHCR | Anonymous registry bearer-token access returned HTTP 200 for four digest-pinned manifests. Downloaded, SHA256-checked and listed every added workload layer for the private-note image and both lifecycle image versions. No wallet proving parameters are included. |

Exact source: [README:48–65](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/private-note-chain/README.md#L48-L65); [private package policy/allowlist:40–53,64–71](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/remote-cuda/private_package.py#L40-L71); [lifecycle policy:41–53](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/remote-cuda/lifecycle_package.py#L41-L53), [allowlist/restore:88–109](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/remote-cuda/lifecycle_package.py#L88-L109); [Actions upload:40–46](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/.github/workflows/cuda-lifecycle-image.yml#L40-L46).

The policies explicitly set `walletSetupParametersIncluded: false` / `setupParametersIncluded: false`. Excluding wallet secrets is appropriate; the separate public proving parameters still need a public recovery path.

Checked GHCR repository: `ghcr.io/olafweller/kaspa-privacy-initiative/cuda-qualification`:

- Base: `sha256:fb6af438a2f4735b878d07ea5ddfd709c4bd7ecf4b4327df4314286076eb51a6`.
- Private-note: `sha256:4bd54b3278b827e721f6633b8643020284820a2c4899a0269c5909a74cde5d09`.
- Lifecycle, recorded publication: `sha256:aefe98f7e463ba3bbc4cc6b692cc739c04d083718983deb79b2543debb150db7`.
- Lifecycle, newest Actions artifact: `sha256:7f32b3692d174b55c5feb1b7355b087076df4c1107e228c9cd08d621ef4530f0` (workflow source `80605a38c06c837afc2c0a9a432032a13b2b069d`).

The base image's complete filesystem was not downloaded. Its [Dockerfile:12–29](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/remote-cuda/Dockerfile#L12-L29) and [base package builder:52–81](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/remote-cuda/package.py#L52-L81) contain the earlier fixed classifier workload, not the later wallet setup. The explicit later workload layers and package allowlists were inspected directly.

## Reproduction

From a clean checkout of the pinned commit:

```sh
git ls-files '*public-proving*'
tar -tzf poc/private-native-proof/evidence/public-package.tar.gz
tar -tzf poc/private-note-proof/evidence/public-package.tar.gz
gh api repos/olafweller/kaspa-privacy-initiative/releases
gh api repos/olafweller/kaspa-privacy-initiative/actions/artifacts
gh api repos/olafweller/kaspa-privacy-initiative/actions/artifacts/12151061997/zip > /tmp/p10-public-metadata.zip
unzip -l /tmp/p10-public-metadata.zip
```

Registry manifest and layer inspection needs only Python's standard library and anonymous registry authorization. Select any workload digest above:

```python
import hashlib, io, json, tarfile, urllib.request
repo = 'olafweller/kaspa-privacy-initiative/cuda-qualification'
digest = '7f32b3692d174b55c5feb1b7355b087076df4c1107e228c9cd08d621ef4530f0'
base = 'fb6af438a2f4735b878d07ea5ddfd709c4bd7ecf4b4327df4314286076eb51a6'
with urllib.request.urlopen('https://ghcr.io/token?service=ghcr.io&scope=repository:'+repo+':pull') as r:
    token = json.load(r)['token']
def get(path):
    req = urllib.request.Request('https://ghcr.io/v2/'+repo+'/'+path, headers={
        'Authorization': 'Bearer '+token,
        'Accept': 'application/vnd.docker.distribution.manifest.v2+json'})
    with urllib.request.urlopen(req) as r:
        return r.read()
def manifest(d):
    raw = get('manifests/sha256:'+d)
    assert hashlib.sha256(raw).hexdigest() == d
    return json.loads(raw)
base_layers = {x['digest'] for x in manifest(base)['layers']}
for layer in manifest(digest)['layers']:
    if layer['digest'] in base_layers:
        continue
    raw = get('blobs/'+layer['digest'])
    assert 'sha256:'+hashlib.sha256(raw).hexdigest() == layer['digest']
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        print(layer['digest'], archive.getnames())
```

Machine-readable observations: [GitHub](github-availability.json), [GHCR](registry-availability.json), [tracked archives](public-archive-inventory.json). These record the actual UTC check timestamps. No pre-existing ignored operator files were read; no setup, proof, broadcast or external write was performed in this sub-investigation.

Smallest actionable gap: publish the **existing** parameter bytes at a durable public URL, with expected SHA256, size and wallet-VK binding in a recovery manifest. A fresh setup yields a different key/instance and cannot replace the missing parameters for this published instance. A subsequent clean recovery should use only a user-owned backup and the public recovery bundle; this availability check alone does not establish that complete recovery works.
