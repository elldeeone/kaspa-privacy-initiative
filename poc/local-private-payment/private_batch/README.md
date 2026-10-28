# Restricted-intent and disclosure-policy research interfaces

[RFC-0030](../../../docs/rfc/0030-private-batch-construction.md) and
[ADR-0074](../../../docs/adr/0074-private-batch-construction.md) define the new
research profile. These files preserve the existing NativeAuth authority seam;
they do not change funded notes or frozen source snapshots.

`intent.py` provides the exact 1460-byte owner-intent encoding and SHA256 limbs.
It checks encoding/ranges, not signatures, points, ciphertexts or financial
validity. The complete new relation must prove those predicates, exact tuple
correspondence and actual native effects. Signing keys remain wallet-local.

`release_policy.py` is a runnable single-server SQLite durability model using
**clear, public synthetic member tokens** and opaque synthetic proof bytes.
It pins the exact cohort/effects before any release permission, refuses overlap
with changed cohorts/effects, and preserves uncertain publication across crashes.
It uses a trusted external latest checkpoint to reject stale/missing history.
It does not implement private admission, MASCOT, a financial proof verifier,
native policy, rollback-resistant hardware or global history currentness.

An actual protocol must perform member equality/overlap privately inside
qualified MPC, persist its selected private representation at every honest
release participant, and validate the complete real proof/effects before
egress. The model has no function that authorizes, cancels or freezes Exit.

Run the small public model/codec checks:

```sh
python3 -m unittest discover -s poc/local-private-payment/private_batch -p 'test_*.py' -v
```

The tests deliberately retain two failures of stronger privacy claims:
known ABC→ADE intersections identify A, and rolling back both journal and
trusted external checkpoint is undetectable locally. Their expected assertions
are not privacy PASS results. A fixed history-bound cohort can permanently
lose private progress after a colluder Exit; independent exits must still work.

The initial codec binds an exact head/outpoint. It does not authorize offline
head refresh, a changed output order/effect core or cross-service private retry.
No current wallet recovery record is read by these tests.
