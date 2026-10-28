#!/usr/bin/env python3
"""Stream an explicitly selected PUBLIC legacy model into compact transport.

The existing stock PK/VK are hashed and referenced, never regenerated/copied.
No assignment, wallet, owner material, MPC diagnostics or TLS key is accepted.
This producer implements KnownPublicPrefix mode1 only.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct

FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583
AXIS_MAGIC = b"KPI_R1CS_AXIS_V1"
META_MAGIC = b"KPI_PACKED_V1\0\0\0"
assert len(AXIS_MAGIC) == len(META_MAGIC) == 16


def digest_file(path):
    digest = hashlib.sha256()
    count = 0
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            count += len(chunk)
    return digest.hexdigest(), count


def canonical_number(value, bound=None):
    if not value or (len(value) > 1 and value[0] == '0') or not value.isascii() or not value.isdecimal():
        raise ValueError('noncanonical public integer')
    result = int(value)
    if bound is not None and result >= bound:
        raise ValueError('public integer outside canonical range')
    return result


def digest_bytes(value):
    if len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('noncanonical public digest')
    return bytes.fromhex(value)


def u64(value):
    if not 0 <= value < 2**64:
        raise ValueError('public count outside u64')
    return struct.pack('<Q', value)


def fr(value):
    if not 0 <= value < FR:
        raise ValueError('noncanonical Fr')
    return value.to_bytes(32, 'little')


class Tokens:
    def __init__(self, stream):
        self.tokens = (word for line in stream for word in line.split())

    def word(self):
        try:
            return next(self.tokens)
        except StopIteration as error:
            raise ValueError('truncated public model') from error

    def tag(self, expected):
        if self.word() != expected:
            raise ValueError('public model type/order mismatch: ' + expected)

    def count(self):
        return canonical_number(self.word(), 2**64)

    def scalar(self):
        return canonical_number(self.word(), FR)

    def hash(self):
        value = self.word()
        digest_bytes(value)
        return value

    def point(self, degree):
        self.tag('g1' if degree == 1 else 'g2')
        identity = self.count()
        if identity > 1:
            raise ValueError('invalid public point identity marker')
        coordinates = [canonical_number(self.word(), FQ) for _ in range(2 * degree)]
        if identity and any(coordinates):
            raise ValueError('noncanonical public identity coordinates')
        # Curve/subgroup admission and exact PK equivalence are mandatory in
        # the independent C++ admitted-reader control, not claimed by pack().
        return identity


def metadata_bytes(record):
    """Canonical public storage root. Mode2 carries identities, never values."""
    mode = record['prefix_mode']
    if mode not in (1, 2):
        raise ValueError('unsupported prefix policy')
    values = record['public_prefix']
    instances = record['instances']
    if mode == 1:
        if len(values) != instances or not values or values[0] != 1:
            raise ValueError('incomplete independently public prefix')
    elif values or record['origin_model_sha256'] != '0' * 64:
        raise ValueError('secret-derived policy cannot carry public value placeholders')
    output = bytearray(META_MAGIC + u64(mode) + FR.to_bytes(32, 'little') + FQ.to_bytes(32, 'little'))
    for name in ['source_sha256', 'origin_model_sha256', 'pk_sha256', 'vk_sha256', 'matrix_fingerprint']:
        output.extend(digest_bytes(record[name]))
    for name in ['compressed_sha256', 'raw_sha256']:
        for axis in record['axes']:
            output.extend(digest_bytes(axis[name]))
    for name in ['instances', 'witnesses', 'rows', 'domain', 'pk_bytes', 'vk_bytes']:
        output.extend(u64(record[name]))
    for name in ['compressed_bytes', 'raw_bytes']:
        for axis in record['axes']:
            output.extend(u64(axis[name]))
    for value in record['domain_parameters']:
        output.extend(fr(value))
    output.extend(u64(len(values)))
    for value in values:
        output.extend(fr(value))
    if mode == 2:
        if record['derived_outputs'] != instances - 1:
            raise ValueError('private-prefix output arity')
        output.extend(u64(record['derived_outputs']))
        for name in ['prefix_recipe_sha256', 'prefix_layout_sha256']:
            if record[name] == '0' * 64:
                raise ValueError('private-prefix recipe/layout identity required')
            output.extend(digest_bytes(record[name]))
    expected = 672 + 32 * instances if mode == 1 else 744
    if len(output) != expected:
        raise ValueError('metadata geometry')
    return bytes(output)


def pack(args):
    for name in ['expected_model_sha256', 'expected_pk_sha256', 'expected_vk_sha256']:
        digest_bytes(getattr(args, name))
    model_sha, model_bytes = digest_file(args.model)
    pk_sha, pk_bytes = digest_file(args.pk)
    vk_sha, vk_bytes = digest_file(args.vk)
    if (model_sha, pk_sha, vk_sha) != (args.expected_model_sha256, args.expected_pk_sha256, args.expected_vk_sha256):
        raise ValueError('selected public source artifact pin mismatch')
    args.output.mkdir(parents=True, exist_ok=False)
    with args.model.open('rt', encoding='ascii') as stream:
        reader = Tokens(stream)
        reader.tag('KPI_MASCOT_PUBLIC_MODEL_V1')
        reader.tag('field')
        if canonical_number(reader.word()) != FR:
            raise ValueError('public field mismatch')
        reader.tag('curve'); reader.tag('BN254')
        reader.tag('reduction'); reader.tag('LibSnark')
        reader.tag('source'); source_sha = reader.hash()
        reader.tag('pk_sha256')
        if reader.hash() != pk_sha:
            raise ValueError('legacy public PK identity mismatch')
        reader.tag('vk_sha256')
        if reader.hash() != vk_sha:
            raise ValueError('legacy public VK identity mismatch')
        reader.tag('num_instance'); instances = reader.count()
        reader.tag('num_private'); witnesses = reader.count()
        reader.tag('num_constraints'); rows = reader.count()
        reader.tag('domain'); domain = reader.count()
        variables = instances + witnesses
        if not instances or variables >= 2**64 or not domain or domain > 2**28 or \
           domain & (domain - 1) or rows + instances > domain:
            raise ValueError('public model geometry/domain')
        parameters = []
        for tag in ['omega', 'omega_inverse', 'inv_n', 'coset_shift']:
            reader.tag(tag); parameters.append(reader.scalar())
        omega, inverse, inv_n, coset = parameters
        if pow(omega, domain, FR) != 1 or (domain > 1 and pow(omega, domain // 2, FR) == 1) or \
           omega * inverse % FR != 1 or domain * inv_n % FR != 1 or not coset or pow(coset, domain, FR) == 1:
            raise ValueError('public domain roots/normalization')
        reader.tag('public_inputs')
        if reader.count() != instances:
            raise ValueError('public prefix arity')
        prefix = [reader.scalar() for _ in range(instances)]
        if prefix[0] != 1:
            raise ValueError('public prefix ONE')
        fingerprint = hashlib.sha256(b'KPINAS/R1CS/v1\0' + u64(instances) + u64(witnesses) + u64(rows))
        axes = []
        max_row_terms = 0
        for axis, name in enumerate('ABC'):
            reader.tag(name)
            if reader.count() != rows:
                raise ValueError('public matrix row count')
            path = args.output / (name + '.rows.gz')
            raw_hash, raw_bytes, terms_total = hashlib.sha256(), 0, 0
            with path.open('xb') as compressed, gzip.GzipFile(
                    filename='', mode='wb', compresslevel=1, mtime=0, fileobj=compressed) as output:
                def write(data):
                    nonlocal raw_bytes
                    output.write(data)
                    raw_hash.update(data)
                    raw_bytes += len(data)
                write(AXIS_MAGIC + u64(axis) + FR.to_bytes(32, 'little') +
                      u64(instances) + u64(witnesses) + u64(rows))
                for _ in range(rows):
                    reader.tag('row')
                    terms = reader.count()
                    max_row_terms = max(max_row_terms, terms)
                    terms_total += terms
                    count_bytes = u64(terms)
                    write(count_bytes); fingerprint.update(count_bytes)
                    for _ in range(terms):
                        column, coefficient = reader.count(), reader.scalar()
                        if column >= variables:
                            raise ValueError('public R1CS column range')
                        encoded = fr(coefficient) + u64(column)
                        write(encoded); fingerprint.update(encoded)
            compressed_sha, compressed_bytes = digest_file(path)
            expected_raw = 80 + 8 * rows + 40 * terms_total
            if raw_bytes != expected_raw:
                raise ValueError('raw axis byte accounting')
            axes.append({'axis': axis, 'file': path.name, 'rows': rows, 'terms': terms_total,
                         'compressed_sha256': compressed_sha, 'compressed_bytes': compressed_bytes,
                         'raw_sha256': raw_hash.hexdigest(), 'raw_bytes': raw_bytes})
        for tag, degree in [('alpha_g1', 1), ('beta_g1', 1), ('beta_g2', 2),
                            ('delta_g1', 1), ('delta_g2', 2)]:
            reader.tag(tag)
            if reader.point(degree):
                raise ValueError('legacy proving base identity')
        query_counts = {}
        for tag, degree, count in [('a_query', 1, variables), ('b_g1_query', 1, variables),
                                  ('b_g2_query', 2, variables), ('l_query', 1, witnesses),
                                  ('h_query', 1, domain - 1)]:
            reader.tag(tag)
            if reader.count() != count:
                raise ValueError('legacy query arity')
            for _ in range(count):
                reader.point(degree)
            query_counts[tag] = count
        reader.tag('vk_hex')
        vk_hex = reader.word()
        if vk_hex != args.vk.read_bytes().hex():
            raise ValueError('legacy canonical VK bytes mismatch')
        reader.tag('END')
        if next(reader.tokens, None) is not None:
            raise ValueError('legacy model trailing data')
    if digest_file(args.model)[0] != model_sha or digest_file(args.pk)[0] != pk_sha or digest_file(args.vk)[0] != vk_sha:
        raise ValueError('selected public source changed during packing')
    expected_pk = (232 + 32 * instances) + 64 + 40 + 128 * variables + 32 * witnesses + 32 * (domain - 1)
    if pk_bytes != expected_pk or vk_bytes != 232 + 32 * instances:
        raise ValueError('stock compressed PK/VK byte geometry')
    record = {'schema': 'kpi-packed-public-model-prototype/v1',
              'prefix_mode': 1, 'prefix_policy': 'KnownPublicPrefix',
              'source_sha256': source_sha, 'origin_model_sha256': model_sha,
              'origin_model_bytes': model_bytes, 'pk_sha256': pk_sha, 'vk_sha256': vk_sha,
              'matrix_fingerprint': fingerprint.hexdigest(), 'pk_bytes': pk_bytes, 'vk_bytes': vk_bytes,
              'instances': instances, 'witnesses': witnesses, 'rows': rows, 'domain': domain,
              'domain_parameters': parameters, 'public_prefix': prefix, 'axes': axes,
              'query_counts': query_counts, 'maximum_row_terms': max_row_terms,
              'stock_pk_or_vk_reencoded_or_copied': False,
              'private_input_or_MPC_or_setup_executed': False,
              'curve_admission_and_full_query_equivalence': 'REQUIRED_SEPARATE_READER_CONTROL',
              'financial_or_privacy_qualification': False}
    encoded = metadata_bytes(record)
    (args.output / 'model.meta').write_bytes(encoded)
    record['packed_model_sha256'] = hashlib.sha256(encoded).hexdigest()
    record['metadata_bytes'] = len(encoded)
    record['new_transport_bytes'] = len(encoded) + sum(axis['compressed_bytes'] for axis in axes)
    record['total_referenced_public_bytes'] = record['new_transport_bytes'] + pk_bytes + vk_bytes
    (args.output / 'MANIFEST.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({name: record[name] for name in ['packed_model_sha256', 'matrix_fingerprint',
          'metadata_bytes', 'new_transport_bytes', 'total_referenced_public_bytes', 'maximum_row_terms']}))


def main():
    parser = argparse.ArgumentParser()
    for name in ['model', 'pk', 'vk', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ['expected-model-sha256', 'expected-pk-sha256', 'expected-vk-sha256']:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    pack(args)


if __name__ == '__main__':
    main()
