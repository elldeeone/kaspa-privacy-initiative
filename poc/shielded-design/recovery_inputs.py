"""Offline retained-data inputs. No archive server, chain authority or proof."""
import copy
import hashlib
from pathlib import Path

from recovery import reconstruct_public
from recovery_format import RecoveryError, hex32, read_json, reject


def load_retained_archive(paths, checkpoint):
    """A redundant copy must match the externally retained checkpoint exactly."""
    for path in paths:
        try:
            archive = read_json(path)
            reconstruct_public(archive, checkpoint)
            return {'archive': archive, 'checkpoint': copy.deepcopy(checkpoint)}
        except (RecoveryError, OSError):
            continue
    raise RecoveryError('incomplete_data', 'no_authenticated_retained_archive')


def require_prover_artifact(path, expected_sha256):
    """Availability/identity preflight only; never certifies a prover or proof."""
    hex32(expected_sha256)
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raise RecoveryError('proof_unavailable', 'prover_artifact_unavailable') from None
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        reject('prover_artifact_identity_mismatch')
    return raw
