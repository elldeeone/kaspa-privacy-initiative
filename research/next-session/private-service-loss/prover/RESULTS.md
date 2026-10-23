# Fresh owner-local prover results

The separate Auth528 prover now authenticates public parameters **before reading
an owner's witness pipe**. It has no hosted service, runtime manifest override,
alternate-key option or private witness serializer. The original AA package,
keys and frozen evidence remain unchanged.

Completed and independently reviewed:

- 22 source unit tests, 8 actual unselected-client unread-pipe controls and
  10 metadata-only private-path controls.
- One fresh selected setup, with measured 3,231,025 constraints, 3,195,131
  witnesses and 3 instances. Three distinct actual local statements produced
  checked genuine proofs under the same new VK. The operator process stopped.
- Root-selected canonical parameter manifest `008689b8…caad54`, binding the
  fresh D/VK, complete 1,290,878,896-byte public artifact, core/build identity and
  measured dimensions. Selected cold executable: `870e61f6…4477aa`.
- Twelve actual selected-loader controls: one full-size load authenticated the
  complete owned buffer, decoded with exhaustion and checked VK/query equality;
  a missing-file failure consumed none of 302 offered public canary bytes.

The payment proof took 8.058s, continuing exit 7.922s and terminal exit 8.033s
including private request parsing and checked verification. The safe
[mode-only summary](../trial/proofs-public-01/PROOFS-PUBLIC.json) contains no
private witness hash, host path or owner association.

Setup took 13.259s; official serialization, stream hashing, fsync and same-file
readback took 3.369s. The selected loader read in 0.782s, hashed in 0.545s and
decoded/checked in 1.751s. These are single functional samples with already
mirrored parameters and potentially warm OS caches, not p95 qualifications.

All owned jobs exited cleanly, inactive/dead/PID0 with zero swap. Whole setup
session peak was 5,593,722,880 bytes; loader-control peak was 2,590,212,096 bytes.
The session's 25:20.56 wall includes long resident idle while other components
were prepared; phase peaks are not independent.

The public cache is outside Git, mode 0600, and contains only the new public
parameter artifact plus manifest. Its local hardlink is not evidence of an
independent durable mirror. Single-party setup honesty, retained data/software
availability, and the trusted host/release immutability assumption remain.
ADR-0054 uses ordinary selected read-only executables; it does not protect
against a malicious host or inode writer. No special execution path or host
policy change was used here.

Native four-body validation, independent network recovery and confirmed payouts
are separate lifecycle evidence. This lane funded and broadcast nothing. Passing
these checks is not a cryptographic audit, financial privacy qualification or
fee qualification; the previous privacy and fee failures remain.

[Raw results](RESULTS.json) and [review closure](REVIEW-ACK.json) pin the artifacts.
