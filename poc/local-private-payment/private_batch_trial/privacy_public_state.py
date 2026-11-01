"""Exact public CM/NF transition checks for the selected batch projection.

This module checks only the public indexed-nullifier and commitment-tree
relations already specified by RFC-0030 ``wire.rs``.  It has no owner labels,
notes, openings, keys, accepted-chain head, proof verifier, or native covenant
authority.  A successful check therefore constrains the public candidate view;
it does not authorize selected privacy coverage or native acceptance.
"""

import hashlib


PROJECTION_BYTES = 10_685
PREFIX_BYTES = 193
BODY_BYTES = 10_492
CM_DEPTH = 16
NF_DEPTH = 17
OWNERS = 3
OUTPUTS = 6
ZERO = bytes(32)


class PublicStateError(ValueError):
    """Uniform public-only refusal; no private diagnostic is represented."""


def _need(condition, code):
    if not condition:
        raise PublicStateError(code)


def _sha(*parts):
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


CM_EMPTY = _sha(b'KPX1CME\0')
NF_EMPTY = _sha(b'KPX1NFE\0')


def _u32(raw):
    _need(type(raw) is bytes and len(raw) == 4, 'public-state-u32-width')
    return int.from_bytes(raw, 'little')


def _fold(leaf, index, path, tag, depth):
    _need(type(leaf) is bytes and len(leaf) == 32,
          'public-state-leaf-width')
    _need(type(path) is bytes and len(path) == depth * 32,
          'public-state-path-width')
    _need(type(index) is int and not isinstance(index, bool)
          and 0 <= index < 1 << depth, 'public-state-index-range')
    root = leaf
    for level in range(depth):
        sibling = path[32 * level:32 * (level + 1)]
        if (index >> level) & 1:
            root = _sha(tag, sibling, root)
        else:
            root = _sha(tag, root, sibling)
    return root


def _nf_leaf(value, successor, successor_index):
    _need(type(value) is bytes and len(value) == 32
          and type(successor) is bytes and len(successor) == 32,
          'public-state-nf-leaf-width')
    _need(type(successor_index) is int and not isinstance(successor_index, bool)
          and 0 <= successor_index < 1 << NF_DEPTH,
          'public-state-nf-successor-index')
    return _sha(b'KPX1NFL\0', value, successor,
                successor_index.to_bytes(4, 'little'))


def _less(left, right):
    """Canonical full-width little-endian integer order."""
    return int.from_bytes(left, 'little') < int.from_bytes(right, 'little')


def _insert_nf(root, count, nf, witness):
    _need(type(root) is bytes and len(root) == 32
          and type(nf) is bytes and len(nf) == 32
          and type(witness) is bytes and len(witness) == 1160,
          'public-state-nf-shape')
    _need(type(count) is int and not isinstance(count, bool)
          and 1 <= count < 1 << NF_DEPTH,
          'public-state-nf-count-range')
    predecessor_index = _u32(witness[:4])
    predecessor = witness[4:36]
    successor = witness[36:68]
    successor_index = _u32(witness[68:72])
    _need(predecessor_index < count and successor_index < count
          and nf != ZERO
          and (predecessor_index == 0) == (predecessor == ZERO)
          and (successor_index == 0) == (successor == ZERO),
          'public-state-nf-indices')
    _need(_less(predecessor, nf)
          and (successor == ZERO or _less(nf, successor)),
          'public-state-nf-interval')
    predecessor_path = witness[72:616]
    append_path = witness[616:1160]
    _need(_fold(_nf_leaf(predecessor, successor, successor_index),
                predecessor_index, predecessor_path, b'KPX1NFN\0', NF_DEPTH)
          == root, 'public-state-nf-predecessor-root')
    middle = _fold(_nf_leaf(predecessor, nf, count), predecessor_index,
                   predecessor_path, b'KPX1NFN\0', NF_DEPTH)
    _need(_fold(NF_EMPTY, count, append_path, b'KPX1NFN\0', NF_DEPTH)
          == middle, 'public-state-nf-empty-append')
    return _fold(_nf_leaf(nf, successor, successor_index), count,
                 append_path, b'KPX1NFN\0', NF_DEPTH)


def verify_public_state_transition(raw):
    """Verify the exact three-NF/six-CM public transition.

    The returned receipt is deliberately nonauthorizing.  A separate bridge
    must bind this computation to the typed, selected FD40 projection before
    any privacy-model row can be closed.
    """
    _need(type(raw) is bytes and len(raw) == PROJECTION_BYTES,
          'public-state-projection-width')
    prefix, body = raw[:PREFIX_BYTES], raw[PREFIX_BYTES:]
    _need(len(body) == BODY_BYTES and prefix[:8] == b'KPBAFX01'
          and body[:8] == b'KPBAEF01'
          and int.from_bytes(prefix[189:193], 'little') == BODY_BYTES,
          'public-state-projection-frame')

    old_cm_root = body[204:236]
    old_nf_root = body[236:268]
    old_cm_count = _u32(body[268:272])
    old_nf_count = _u32(body[272:276])
    new_cm_root = body[284:316]
    new_nf_root = body[316:348]
    new_cm_count = _u32(body[348:352])
    new_nf_count = _u32(body[352:356])
    _need(1 <= old_cm_count <= (1 << CM_DEPTH) - OUTPUTS
          and 1 <= old_nf_count <= (1 << NF_DEPTH) - OWNERS
          and new_cm_count == old_cm_count + OUTPUTS
          and new_nf_count == old_nf_count + OWNERS,
          'public-state-count-transition')

    nfs = [body[404 + 96 * index:436 + 96 * index]
           for index in range(OWNERS)]
    _need(all(nf != ZERO for nf in nfs)
          and all(_less(nfs[index - 1], nfs[index])
                  for index in range(1, OWNERS)),
          'public-state-sorted-distinct-nfs')
    cm_rows = [body[692 + 520 * index:692 + 520 * (index + 1)]
               for index in range(OUTPUTS)]
    commitments = [row[:32] for row in cm_rows]
    _need(all(cm not in (ZERO, CM_EMPTY) for cm in commitments)
          and len(set(commitments)) == OUTPUTS,
          'public-state-distinct-output-cms')

    root = old_nf_root
    interval_commitments = []
    for index, nf in enumerate(nfs):
        witness = body[3812 + 1160 * index:3812 + 1160 * (index + 1)]
        interval_commitments.append(hashlib.sha256(witness[:72]).hexdigest())
        root = _insert_nf(root, old_nf_count + index, nf, witness)
    _need(root == new_nf_root, 'public-state-new-nf-root')

    root = old_cm_root
    for index, commitment in enumerate(commitments):
        position = old_cm_count + index
        path = body[7292 + 512 * index:7292 + 512 * (index + 1)]
        _need(_fold(CM_EMPTY, position, path, b'KPX1CMN\0', CM_DEPTH)
              == root, 'public-state-cm-empty-append')
        root = _fold(commitment, position, path, b'KPX1CMN\0', CM_DEPTH)
    _need(root == new_cm_root, 'public-state-new-cm-root')

    return {
        'schema': 'kpb-public-state-transition-verification/v1',
        'projection_sha256': hashlib.sha256(raw).hexdigest(),
        'old_cm_count': old_cm_count,
        'new_cm_count': new_cm_count,
        'old_nf_count': old_nf_count,
        'new_nf_count': new_nf_count,
        'verified_nf_insertions': OWNERS,
        'verified_cm_appends': OUTPUTS,
        'nf_interval_commitment_sha256': interval_commitments,
        'owner_label_fields': 0,
        'accepted_chain_currentness_proven': False,
        'proof_validity_proven': False,
        'native_acceptance_proven': False,
        'privacy_proven': False,
        'authorizes_selected_coverage': False,
    }
