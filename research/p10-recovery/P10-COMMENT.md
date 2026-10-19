Unposted draft for [P10/#10](https://github.com/olafweller/kaspa-privacy-initiative/issues/10):

At `cde2b88`, we could rebuild the published pre-exit state byte-for-byte and verify the archived Bob exit in an isolated process. Creating a new exit is blocked by a public artifact: the 156,439,536-byte proving-parameter file required by [`bob-exit`](https://github.com/olafweller/kaspa-privacy-initiative/blob/cde2b88de3a16af401a2046bd90a124aa105418a/poc/private-native/host/src/main.rs#L430-L439), SHA256 `812b3bda0ec5f9b0c17fc1d530e49fc21defc9dcc5ea9c70a133ca62fec31e99`.

We found no distribution location in Git/public archives, releases, Actions artifacts or the inspected GHCR workload layers. The docs say the parameters remain local.

Could those existing public parameters be published at a durable URL, with their size, SHA256 and wallet-VK binding? No wallet backup or setup secrets are needed. A fresh setup cannot replace them because it changes the pinned identity.

A separate fresh synthetic instance did restore from Bob's own backup plus staged public data and produced a newly verified exit proof in isolation. That tests the mechanism; it does not recover the published instance or establish a native payout.
