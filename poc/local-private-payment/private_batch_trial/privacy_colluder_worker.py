#!/usr/bin/env python3
"""One Original1 and own local record; actual CF/route facts, no truth oracle."""
from pathlib import Path
import os

import private_worker as boundary
import privacy_codec as codec
import privacy_observer as observer
import wallet_profile as wallet
import owner_record


def write_new(path, value, mode):
    path = Path(path); boundary.write(path, value, mode)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def run():
    marker = codec.parse(boundary.read('/NAMESPACE.json'))
    codec.need(marker == {'schema': 'kpb-one-colluder-view-namespace/v1', 'network': 'disabled',
        'owner_component': 1, 'owner_slots': 1, 'truth_slots': 0, 'server_slots': 0}, 'privacy-one-colluder-only-marker')
    interfaces = [line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    codec.need(interfaces == ['lo'] and all(not Path(path).exists() for path in (
        '/truth', '/counts', '/corrupt-server', '/home/luke/.codex', '/home/luke/.ssh', '/etc/ssl/private',
        '/var/tmp/kpi-owner-private-lifecycle-01/private')), 'privacy-one-colluder-no-honest-or-host-private-mounts')
    codec.need(sorted(path.name for path in Path('/original').iterdir()) == ['BACKUP.json']
         and sorted(path.name for path in Path('/own').iterdir()) == [owner_record.LEAF],
         'privacy-exact-one-original-and-own-record-leaves')
    config = codec.parse(boundary.read('/CONFIG.json'))
    codec.fields(config, ('schema', 'binding', 'round', 'owner_component', 'domain_hex32', 'profile_id_hex32',
                         'source_members', 'runtime_members', 'js_leaf_map_sha256', 'projection_sha256', 'route_sha256'))
    codec.binding(config['binding'])
    codec.need(config['schema'] == 'kpb-one-colluder-view-worker/v1' and type(config['owner_component']) is int
         and config['owner_component'] == 1 and type(config['round']) is int and config['round'] in (1, 2),
         'privacy-exact-colluder-worker-context')
    for row in config['source_members'] + config['runtime_members']:
        boundary.read(row['path'], row['sha256'])
    raw_projection = boundary.read('/public/PROJECTION.bin', config['projection_sha256'])
    codec.need(len(config['route_sha256']) == 3, 'privacy-three-actual-route-files')
    routes = [codec.parse(boundary.read('/routes/owner-' + str(component) + '.json', pin))
              for component, pin in enumerate(config['route_sha256'])]
    profile = wallet.Profile(bytes.fromhex(config['domain_hex32']), bytes.fromhex(config['profile_id_hex32']))
    modules = wallet.authenticate_js('/runtime/JS-INSTALLED-LEAF-MAP.json', config['js_leaf_map_sha256'], '/runtime/js')
    crypto = wallet.Crypto('/runtime/crypto')
    # The existing outer namespace is the one-owner isolation boundary; no
    # nested bwrap or host Authority path is used.
    with boundary.NamespaceAuthority('/runtime/node', modules) as authority:
        receiver = wallet.Receiver(boundary.load_backup('/original/BACKUP.json', profile), profile, crypto, authority)
        own = owner_record.decode(boundary.read('/own/' + owner_record.LEAF, private=True), 1)
        facts = observer.colluder_facts(receiver, own, config['round'], raw_projection, routes)
    context = observer.batch_from_projection(config['round'], raw_projection)['context_sha256']
    write_new('/private-output/COLLUDER-CONSTRAINTS.json', {'schema': 'kpb-private-colluder-constraints/v1',
        'binding': config['binding'], 'round': config['round'], 'context_sha256': context, 'constraints': facts}, 0o600)
    write_new('/out/PUBLIC.json', {'schema': 'kpb-colluder-view-produced/v1', 'binding': config['binding'],
        'owner_component': 1, 'round': config['round'], 'actual_incoming_CF_decrypted': True,
        'actual_all_three_routes_used': True, 'private_record_or_identifiers_exported': False}, 0o400)


if __name__ == '__main__':
    os.umask(0o077)
    try: run()
    except BaseException: raise SystemExit('one-colluder derivation incomplete')
