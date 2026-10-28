"""PUBLIC known-seed signature normalizer smoke; no Original is mounted."""
import hashlib
from pathlib import Path
import sys
sys.path.insert(0, '/source/poc/local-private-payment/private_batch_trial')
import lifecycle_worker as lifecycle
import wallet_profile as wallet
import private_worker as boundary

try:
    config = boundary.parse(boundary.read('/public/CONFIG.json'))
    for item in config['source_members'] + config['runtime_members']:
        boundary.read(item['path'], item['sha256'])
    wallet.authenticate_js('/runtime/JS-INSTALLED-LEAF-MAP.json', config['leaf_map_sha256'], '/runtime/js')
    if list(Path('/owner').iterdir()) or Path('/original').exists():
        raise ValueError('public-smoke-no-Original-or-owner-input')
    source = boundary.parse(boundary.read('/public/SIGNATURE-INPUT.json', config['input_sha256']))
    normalized = lifecycle.normalize(source)
    matrix, witness = Path(normalized['matrix']), Path(normalized['witness'])
    if not matrix.is_relative_to('/tmp') or matrix.parent != witness.parent:
        raise ValueError('public-smoke-private-scratch-paths')
    raw = boundary.read(witness)
    if hashlib.sha256(raw).hexdigest() != config['expected_public_witness_sha256']:
        raise ValueError('public-smoke-reference-witness')
    value = boundary.parse(raw)
    if value['nVars'] != 10049 or normalized['matrix_sha256'] != lifecycle.MATRIX_SHA or normalized['mapping_sha256'] != lifecycle.MAP_SHA:
        raise ValueError('public-smoke-qualified-signature-layout')
    if list(Path('/owner').iterdir()):
        raise ValueError('public-smoke-host-signature-intermediate')
    boundary.write('/out/PUBLIC.json', {'schema': 'kpi-PUBLIC-real-signature-tmpfs-smoke/v1',
        'status': 'PASS', 'actual_stock_signature_generator_and_normalizer': True,
        'signature_variables': 10049, 'same_public_reference_witness': True,
        'returned_paths_private_tmpfs': True, 'host_owner_directory_empty': True,
        'actual_Original_or_private_owner_input': False, 'new_AuthExit_proof_claim': False}, 0o400)
except BaseException:
    boundary.write('/out/PUBLIC.json', {'schema': 'kpi-PUBLIC-real-signature-tmpfs-smoke/v1',
        'status': 'REFUSED', 'actual_Original_or_private_owner_input': False}, 0o400)
    raise SystemExit('PUBLIC-normalizer-smoke-refused')
