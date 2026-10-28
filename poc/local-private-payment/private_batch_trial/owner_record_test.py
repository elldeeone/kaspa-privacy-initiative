"""PUBLIC schema-only framing controls; no financial witness/Original is read."""
import copy
import json
import unittest
import owner_record as record
import privacy_codec as codec


def minimum(shape):
    if type(shape) is dict:
        return {name: minimum(child) for name, child in shape.items()}
    kind = shape[0]
    if kind == 'array': return [minimum(shape[2]) for _ in range(shape[1])]
    if kind == 'hex': return '0' * (2 * shape[1])
    if kind == 'decimal': return '0'
    if kind in ('owner', 'uint'): return 0
    return shape[1]


def framed(payload, owner=1):
    return (record.MAGIC + owner.to_bytes(8, 'little') + len(payload).to_bytes(8, 'little')
            + payload + bytes(record.FRAME_BYTES - record.HEADER_BYTES - len(payload)))


class FullRecordFraming(unittest.TestCase):
    def setUp(self):
        self.value = minimum(record.RECORD)
        self.value['owner_component'] = 1
        self.raw = record.encode(self.value, 1)

    def test_full_fields_roundtrip_all_roles_and_public_bound(self):
        self.assertEqual(record.MAX_JSON_BYTES, 9823)
        maximum = record._maximum(record.RECORD)
        self.assertEqual(len(codec.encoded(maximum)), 9823)
        self.assertLess(len(codec.encoded(self.value)), 9823)
        self.assertGreater(record.FRAME_BYTES, 3 * (record.HEADER_BYTES + record.MAX_JSON_BYTES))
        for owner in range(3):
            for source in (self.value, maximum):
                original = copy.deepcopy(source); original['owner_component'] = owner
                raw = record.encode(original, owner)
                self.assertEqual(len(raw), 32768)
                self.assertEqual(record.decode(raw, owner), original)
                payload = (json.dumps(original, sort_keys=True, separators=(',', ':')) + '\n').encode()
                self.assertEqual(raw[32:32 + len(payload)], payload)
                self.assertEqual(int.from_bytes(raw[24:32], 'little'), len(payload))

    def test_strict_frame_boundaries_and_owner(self):
        cases = [self.raw[:-1], self.raw + b'\0', b'x' + self.raw[1:],
                 b'KPB_OWNER_FR32V2' + self.raw[16:]]
        for size in (0, record.MAX_JSON_BYTES + 1, (1 << 64) - 1):
            cases.append(self.raw[:24] + size.to_bytes(8, 'little') + self.raw[32:])
        for owner in (0, 2, (1 << 64) - 1):
            cases.append(self.raw[:16] + owner.to_bytes(8, 'little') + self.raw[24:])
        for raw in cases:
            with self.subTest(case=cases.index(raw)):
                with self.assertRaises(ValueError): record.decode(raw, 1)
        for owner in (-1, 3, True, '1'):
            with self.assertRaises(ValueError): record.decode(self.raw, owner)
            with self.assertRaises(ValueError): record.encode(self.value, owner)

    def test_padding_legacy_duplicate_and_noncanonical_payload(self):
        size = int.from_bytes(self.raw[24:32], 'little')
        malformed = bytearray(self.raw); malformed[32 + size] = 1
        payload = codec.encoded(self.value)
        legacy = payload + bytes(record.FRAME_BYTES - len(payload))
        duplicate = b'{"owner_component":1,' + payload[1:]
        for raw in (bytes(malformed), legacy, framed(b' ' + payload), framed(duplicate),
                    framed(payload.replace(b'"owner_component":1', b'"owner_component": 1')),
                    framed(payload[:-1])):
            with self.assertRaises(ValueError): record.decode(raw, 1)

    def test_original_schema_ranges_and_exact_fields(self):
        cases = []
        for key, value in [('schema', 'other'), ('owner_component', 2), ('fee_sompi', True),
                           ('fee_sompi', -1), ('fee_sompi', 1 << 64), ('nonce_hex32', 'AA' * 32)]:
            changed = copy.deepcopy(self.value); changed[key] = value; cases.append(changed)
        changed = copy.deepcopy(self.value); changed['unexpected'] = 'PUBLIC'; cases.append(changed)
        changed = copy.deepcopy(self.value); del changed['intent_hex1460']; cases.append(changed)
        for path, value in [
            (('input', 'position'), 1 << 32), (('input', 'position'), -1),
            (('input', 'path_hex32'), ['00' * 32] * 15),
            (('signature', 'S'), str(record.Q)), (('signature', 'S'), '00'),
            (('signature', 'R8'), [str(record.P), '0']),
            (('signature_inputs', 'ownerKeyBytes'), ['256'] * 64),
            (('signature_inputs', 'sigS'), '+1'), (('signature_inputs', 'sigS'), 1),
        ]:
            changed = copy.deepcopy(self.value); changed[path[0]][path[1]] = value; cases.append(changed)
        for changed in cases:
            with self.assertRaises(ValueError): record.encode(changed, 1)
            with self.assertRaises(ValueError): record.decode(framed(codec.encoded(changed)), 1)

    def test_decimal_width_variation_never_changes_observed_size(self):
        lengths = set()
        for scalar in (0, 1, 9, 10, 99, 100, 10**38, record.Q - 1):
            original = copy.deepcopy(self.value)
            original['signature']['S'] = original['signature_inputs']['sigS'] = str(scalar)
            lengths.add(len(codec.encoded(original)))
            raw = record.encode(original, 1)
            self.assertEqual(len(raw), record.FRAME_BYTES)
            self.assertEqual(record.decode(raw, 1), original)
        self.assertGreater(len(lengths), 1)


if __name__ == '__main__': unittest.main()
