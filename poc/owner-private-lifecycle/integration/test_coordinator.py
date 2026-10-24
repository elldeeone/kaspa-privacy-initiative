"""Actual namespace smoke checks, still only public synthetic proof fixtures."""
from pathlib import Path
import tempfile
import unittest

from construction.codec import parse_json
from driver import isolated, ready_public
from public import DOMAIN, body_core, hx, load_wire, sha
from test_history import batch_projection, fixture


class CoordinatorTests(unittest.TestCase):
    def test_actual_isolated_assembler_matches_public_host_builder(self):
        history, roster = fixture()
        example = batch_projection(history, 0, roster)
        p = load_wire().parse_projection(bytes.fromhex(example['projection_hex']))
        inputs = [(row.nf, row.cv) for row in p.body.spends]
        packet = {'schema': 'kpx8-public-assembly-ipc/v1', 'operation': 'build', 'history': history,
            'inputs': [{'nf_hex32': nf.hex(), 'cv_hex64': cv.hex()} for nf, cv in inputs],
            'rows_hex': [row.tuple_bytes.hex() for row in p.body.outputs], 'delta_hex32': p.body.delta.hex(),
            'session_sha256': p.body.session.hex(), 'roster': roster, 'fee_sompi': p.body.fee}
        expected = body_core(history, inputs, [row.tuple_bytes for row in p.body.outputs], p.body.delta,
                             p.body.session.hex(), roster, p.body.fee)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            isolated(packet, output)
            self.assertEqual((output / 'BODY.bin').read_bytes(), expected)
            report = parse_json((output / 'OBSERVER.json').read_bytes())
            self.assertTrue(report['public_stdin_only'])
            self.assertFalse(report['private_owner_directories_visible'])
            self.assertFalse(report['docker_socket_visible'])

    def test_READY_rejects_recovered_CM_position_even_when_other_fields_match(self):
        record = {'schema': 'kpx8-owner-input-ready/v1', 'participant_id_hex32': sha(b'owner').hex(),
            'session_sha256': sha(b'session').hex(), 'nf_hex32': sha(b'NF').hex(),
            'cv_hex64': '11' * 64, 'own_output_count': 2, 'mpc_input_written': True,
            'financial_authorization': False}
        self.assertEqual(len(ready_public(record, record['participant_id_hex32'], record['session_sha256'])), 2)
        for field, value in (('input_cm_hex32', '22' * 32), ('position', 4)):
            with self.assertRaises(ValueError):
                ready_public(dict(record, **{field: value}), record['participant_id_hex32'], record['session_sha256'])


if __name__ == '__main__':
    unittest.main()
