#!/usr/bin/env python3
"""Bind actual public stock parameters/rows/derived-prefix recipe, without copies.

No witness, wallet, private owner file, raw MPC diagnostic or fixed prefix value
is accepted. Large immutable artifacts remain at their original selected paths;
the role launcher binds the recorded axis files read-only at A/B/C.rows.gz.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
from pack_existing import metadata_bytes, digest_bytes, FR, FQ


def selected_file(path, expected, size=None):
    digest_bytes(expected)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise ValueError('selected public artifact must be a regular nonsymlink file')
    digest = hashlib.sha256()
    count = 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('selected public artifact inode substitution')
        while block := stream.read(1024 * 1024):
            digest.update(block)
            count += len(block)
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != \
       (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or \
       digest.hexdigest() != expected or (size is not None and count != size):
        raise ValueError('selected public artifact identity or size changed')
    return count


def read_json(path, expected):
    digest_bytes(expected)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('public manifest is not regular')
        body = stream.read()
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != \
       (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or \
       hashlib.sha256(body).hexdigest() != expected:
        raise ValueError('public manifest identity changed')
    return json.loads(body)


def member(parent, name):
    if Path(name).name != name or name in ('', '.', '..'):
        raise ValueError('public manifest member path')
    return parent / name


def count(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError('noncanonical public count')
    return value


def main():
    parser = argparse.ArgumentParser()
    for name in ['rows-manifest', 'parameters-manifest', 'trace-preparation', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ['rows-manifest', 'parameters-manifest', 'trace-preparation']:
        parser.add_argument('--expected-' + name + '-sha256', required=True)
    args = parser.parse_args()
    rows = read_json(args.rows_manifest, args.expected_rows_manifest_sha256)
    params = read_json(args.parameters_manifest, args.expected_parameters_manifest_sha256)
    trace = read_json(args.trace_preparation, args.expected_trace_preparation_sha256)
    if rows['schema'] != 'kpi-r1cs-axis-gzip/v1' or \
       params['schema'] != 'kpi-stock-financial-aggregate-setup/v1' or \
       trace['schema'] != 'kpb-financial-trace-independent-preparation/v1':
        raise ValueError('unsupported actual public artifact schema')
    instances, witnesses, constraints = (count(rows[k]) for k in
        ['num_instances', 'num_witnesses', 'num_constraints'])
    variables = instances + witnesses
    if instances != 3 or variables >= 2**64 or variables != rows['model_variables'] or \
       (variables, constraints, instances) != (params['model_variables'], params['num_constraints'], params['num_instance_slots']) or \
       (variables, instances) != (trace['model_variables'], trace['model_instances']) or \
       rows['field_decimal'] != str(FR) or rows['private_assignment_included'] is not False or \
       rows['public_prefix_policy']['fixed_digest_values'] is not False or \
       trace['private_owner_material_read'] is not False or params['aggregate_proof_generated'] is not False:
        raise ValueError('actual unassigned statement geometry or prefix policy')
    fingerprint = rows['canonical_r1cs_fingerprint']
    if fingerprint != params['canonical_r1cs_fingerprint']:
        raise ValueError('stock setup differs from exact finalized matrices')
    for key in ['original_signature_mapping_sha256', 'original_signature_matrix_sha256']:
        if rows[key] != params[key] or rows[key] != trace[key]:
            raise ValueError('component source identity mismatch')
    source = params['setup_source_sha256']
    if source != trace['source_sha256']:
        raise ValueError('setup and actual construction source differ')
    pk, vk = params['pk'], params['vk']
    pk_path = member(args.parameters_manifest.parent, pk['file'])
    vk_path = member(args.parameters_manifest.parent, vk['file'])
    selected_file(pk_path, pk['compressed_sha256'], count(pk['compressed_bytes']))
    selected_file(vk_path, vk['sha256'], count(vk['bytes']))
    recipe, layout = trace['prefix_recipe'], trace['layout']
    recipe_path = member(args.trace_preparation.parent, recipe['file'])
    layout_path = member(args.trace_preparation.parent, layout['file'])
    selected_file(recipe_path, recipe['sha256'], count(recipe['bytes']))
    selected_file(layout_path, layout['container_sha256'], count(layout['container_bytes']))
    if recipe['outputs'] != instances - 1:
        raise ValueError('derived prefix output arity')
    axes = []
    for index, axis in enumerate(rows['axes']):
        if axis['axis'] != index or index >= 3:
            raise ValueError('axis order')
        path = member(args.rows_manifest.parent, axis['file'])
        selected_file(path, axis['compressed_sha256'], count(axis['compressed_bytes']))
        axes.append({'axis': index, 'path': str(path.resolve()),
            'compressed_sha256': axis['compressed_sha256'], 'compressed_bytes': axis['compressed_bytes'],
            'raw_sha256': axis['uncompressed_sha256'], 'raw_bytes': axis['uncompressed_bytes']})
    if len(axes) != 3:
        raise ValueError('axis arity')
    domain = 1 << (constraints + instances - 1).bit_length()
    if domain > 2**28:
        raise ValueError('unsupported BN254 radix2 domain')
    # Pinned ark-bn2540.6 FrConfig uses generator5. Its get_root_of_unity
    # (including the3^2 large subgroup path) yields this same radix2 root.
    omega = pow(5, (FR - 1) // domain, FR)
    parameters = [omega, pow(omega, -1, FR), pow(domain, -1, FR), 5]
    expected_vk = 232 + 32 * instances
    expected_pk = expected_vk + 104 + 128 * variables + 32 * witnesses + 32 * (domain - 1)
    if vk['bytes'] != expected_vk or pk['uncompressed_bytes'] != expected_pk:
        raise ValueError('stock compressed key geometry')
    record = {'prefix_mode': 2, 'source_sha256': source, 'origin_model_sha256': '0' * 64,
        'pk_sha256': pk['uncompressed_sha256'], 'vk_sha256': vk['sha256'],
        'matrix_fingerprint': fingerprint, 'axes': axes, 'instances': instances,
        'witnesses': witnesses, 'rows': constraints, 'domain': domain,
        'pk_bytes': expected_pk, 'vk_bytes': expected_vk, 'domain_parameters': parameters,
        'public_prefix': [], 'derived_outputs': instances - 1,
        'prefix_recipe_sha256': recipe['sha256'], 'prefix_layout_sha256': layout['sha256']}
    encoded = metadata_bytes(record)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'model.meta').write_bytes(encoded)
    # Tiny public files only; never duplicate large PK or matrix artifacts.
    (args.output / 'vk.bin').write_bytes(vk_path.read_bytes())
    (args.output / 'PREFIX-RECIPE.bin').write_bytes(recipe_path.read_bytes())
    transport = {'schema': 'kpi-financial-packed-public-root/v1',
        'classification': 'UNFUNDED_PUBLIC_PARAMETERS_NO_PROOF_OR_FINANCIAL_ACCEPTANCE',
        'metadata_sha256': hashlib.sha256(encoded).hexdigest(), 'metadata_bytes': len(encoded),
        'source_sha256': source, 'setup_source_sha256': source,
        'matrix_export_source_sha256': rows['source_sha256'],
        'actual_construction_source_sha256': trace['source_sha256'],
        'matrix_fingerprint': fingerprint, 'instances': instances, 'variables': variables,
        'witnesses': witnesses, 'rows': constraints, 'domain': domain, 'axes': axes,
        'stock_pk_gzip': {**pk, 'path': str(pk_path.resolve())},
        'stock_vk': {**vk, 'path': str(vk_path.resolve())},
        'prefix_recipe': {**recipe, 'path': str(recipe_path.resolve())},
        'layout': {**layout, 'path': str(layout_path.resolve())},
        'public_context_sha256': trace['public_context_sha256'],
        'fixed_or_placeholder_public_prefix_values': False,
        'large_public_artifacts_copied': False, 'model_ready_for_private_intake': False,
        'full_point_and_final_program_admission_still_required': True,
        'source_manifest_pins': {'rows': args.expected_rows_manifest_sha256,
            'parameters': args.expected_parameters_manifest_sha256,
            'trace_preparation': args.expected_trace_preparation_sha256},
        'producer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (args.output / 'TRANSPORT.json').write_text(json.dumps(transport, indent=2) + '\n')
    print(json.dumps({'metadata_sha256': transport['metadata_sha256'], 'source_sha256': source,
        'model_variables': variables, 'constraints': constraints, 'fixed_prefix_values': False}))


if __name__ == '__main__':
    main()
