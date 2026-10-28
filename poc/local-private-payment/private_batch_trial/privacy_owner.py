"""Owner-only truth hook. The controller receives a salted commitment only."""
import hashlib
import os
import secrets

import privacy_codec as codec

TRUTH_TAG = b'KPBTRU01'


def write_truth(bound, component, round_number, context_raw, nf, rows,
                *, private_path='/owner/PRIVACY-TRUTH.json', public_path='/out/PRIVACY-COMMITMENT.json'):
    """Invoke after real owner intent construction, inside that owner namespace.

    No original seed, intent body, fee, Delta or receipt is part of the public
    sidecar. The private fresh salt prevents dictionary attacks on the small
    finite correspondence space. This is an evidence commitment, not a proof.
    """
    import private_worker as boundary
    marker = codec.parse(boundary.read('/NAMESPACE.json'))
    codec.need(marker == {'schema': 'kpb-one-owner-namespace/v1', 'network': 'disabled',
        'operation': 'pay', 'owner_slots': 1}, 'privacy-own-financial-namespace-required')
    config = codec.parse(boundary.read('/CONFIG.json', private=True))
    codec.need(config['owner_component'] == component and config['round'] == round_number
               and config['privacy_binding'] == codec.binding(bound), 'privacy-own-frozen-job-binding')
    codec.need(type(context_raw) is bytes and len(context_raw) == 276, 'privacy-actual-approved-head-context')
    codec.need(str(private_path) == '/owner/PRIVACY-TRUTH.json'
               and str(public_path) == '/out/PRIVACY-COMMITMENT.json', 'privacy-fixed-truth-hook-paths')
    truth = codec.truth_record(bound, component, round_number, hashlib.sha256(context_raw).hexdigest(), nf, rows)
    salt = secrets.token_bytes(32)
    commit = hashlib.sha256(TRUTH_TAG + salt + codec.encoded(truth)).hexdigest()
    boundary.write(private_path, {'schema': 'kpb-salted-owner-truth/v1', 'salt_hex32': salt.hex(), 'truth': truth})
    directory = os.open('/owner', os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    public = {'schema': 'kpb-owner-truth-commitment/v1', 'binding': bound, 'owner_component': component,
        'round': round_number, 'salted_commitment_sha256': commit, 'truth_or_identifiers_exported': False}
    boundary.write(public_path, public, 0o400)
    directory = os.open('/out', os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return public


def open_truth(raw, public, bound, component, round_number):
    """Use only after the isolated scorer durably reserves its one query."""
    value = codec.parse(raw)
    codec.fields(value, ('schema', 'salt_hex32', 'truth'))
    codec.need(value['schema'] == 'kpb-salted-owner-truth/v1', 'privacy-salted-truth-schema')
    salt = bytes.fromhex(codec.word(value['salt_hex32']))
    codec.need(salt != bytes(32), 'privacy-nonzero-truth-salt')
    truth = value['truth']; codec.check_truth(truth, bound)
    codec.fields(public, ('schema', 'binding', 'owner_component', 'round', 'salted_commitment_sha256', 'truth_or_identifiers_exported'))
    codec.need(public['schema'] == 'kpb-owner-truth-commitment/v1' and public['binding'] == bound
        and public['owner_component'] == component == truth['owner_component']
        and public['round'] == round_number == truth['round'] and public['truth_or_identifiers_exported'] is False
        and hashlib.sha256(TRUTH_TAG + salt + codec.encoded(truth)).hexdigest() == public['salted_commitment_sha256'],
        'privacy-original-owner-truth-commitment-join')
    return truth
