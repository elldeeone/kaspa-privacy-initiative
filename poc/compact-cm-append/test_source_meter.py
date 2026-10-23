"""Calibrate the source upper meter against retained independent native receipts."""
from pathlib import Path
import json
import unittest

import kernel
import source_meter

ROOT=Path(__file__).resolve().parents[2]


class SourceMeterControls(unittest.TestCase):
    def test_all_eight_actual_kernel_units_below_source_upper(self):
        path=ROOT/'research/next-session/private-change/fees/native-02/client-output/result/RESULTS.json'
        results=json.loads(path.read_bytes())
        checked=0
        for row in results['cases']:
            if row['fault']!='positive':continue
            program=kernel.program(row['n'],row['mode'],bytes.fromhex(row['old_root']))
            meter=source_meter.Meter()
            meter.units=3*len(program)+65+3500
            meter.run(source_meter.ast(program))
            self.assertGreaterEqual(meter.units,row['native_units'])
            self.assertEqual(len(meter.stack),1);self.assertFalse(meter.alt)
            checked+=1
        self.assertEqual(checked,8)

    def test_current_whole_private_source_includes_verifier_and_fits_1600(self):
        tail=(ROOT/'poc/private-exit-recovery/kpx3-policy-template.bin').read_bytes()
        upper=source_meter.current_private_upper_bound(b'\x4c\x70'+bytes(112)+tail)
        self.assertGreater(upper,14_961_272)
        self.assertLessEqual(upper,16_009_999)

    def test_unknown_opcode_or_bad_branch_shape_cannot_be_free(self):
        with self.assertRaisesRegex(ValueError,'unsupported-source-opcode'):
            source_meter.Meter().run(source_meter.ast(b'\xff'))
        with self.assertRaisesRegex(ValueError,'abstract-conditional-stack-shape'):
            source_meter.Meter([source_meter.Item(1)]).run(source_meter.ast(b'\x63\x51\x67\x68'))


if __name__=='__main__':unittest.main()
