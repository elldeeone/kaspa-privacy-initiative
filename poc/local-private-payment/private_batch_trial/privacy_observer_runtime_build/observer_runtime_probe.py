"""Unselected static-observer closure probe.

This module proves that the real FD40 structural parser is available from the
finite frozen-module table.  It does not consume FD40, produce predictions,
write FD62, or authorize measurement coverage.
"""

import privacy_fd40_structural as fd40


def _arbitrary_model_import_is_absent():
    try:
        import privacy_capture_model  # noqa: F401
    except ModuleNotFoundError:
        return True
    return False


def run():
    if (not _arbitrary_model_import_is_absent()
            or fd40.CAPSULE_MAGIC != b'KPBOSA2\0'
            or fd40.CAPSULE_VERSION != 2
            or fd40.RUN_BINDING_BYTES != 3403
            or fd40.STRUCTURAL_BYTES != 1988
            or fd40.LEAF_COUNT_OFFSET != 7862):
        raise RuntimeError('kpb-observer-runtime-probe-schema-drift')
    return 0
