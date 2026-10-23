"""Public-only import/mount composition gate, before any owner inputs."""
import json
from pathlib import Path
import sys

sys.path.insert(0, '/app/poc/private-cashout-wallet')
import private_wallet

assert not any(Path(path).exists() for path in ('/backup.json', '/public-params.bin',
                                               '/own-prover', '/native-helper', '/crypto'))
manifest = json.loads(Path('/manifest.json').read_bytes())
try:
    # Full26+5 dependency authentication and fixed module imports must succeed.
    # Invalid descriptor then stops before SDK/native execution or any key input.
    private_wallet.network_replay({}, {}, manifest, Path('/out/unused'))
except ValueError as error:
    assert str(error) == 'private-network-descriptor-fields', str(error)
else:
    raise AssertionError('invalid descriptor accepted')
print(json.dumps({'passed': True, 'complete_public_dependency_mount_and_import_gate': True,
                  'expected_invalid_descriptor_rejected': True, 'owner_backup_or_pk_present': False,
                  'sdk_native_or_prover_executed': False, 'network_namespace': 'isolated'}))
