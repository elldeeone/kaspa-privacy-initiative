"""Mutation controls for public source selection; no crypto/compiler import."""
import copy
import importlib.util
import json
from pathlib import Path
import runpy
import unittest

HERE = Path(__file__).parent
GUARD = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')


def read(path):
    return GUARD['read'](str(path))


spec = importlib.util.spec_from_file_location('aggregate_source_audit', HERE / 'audit_sources.py')
audit = importlib.util.module_from_spec(spec)
exec(compile(read(HERE / 'audit_sources.py'), str(HERE / 'audit_sources.py'), 'exec'), audit.__dict__)


class SourceSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = read(HERE / 'circuits/aggregate.circom')
        cls.library = read(HERE / 'circuits/authority-template.circom')
        cls.original = read(HERE.parent / 'signature-authority-predicate-01/circuits/authority.circom')
        cls.recipe = read(HERE / 'FIXTURE-RECIPE-01.json')

    def interface(self, wrapper=None, library=None, original=None):
        return audit.audit_interface(wrapper if wrapper is not None else self.wrapper,
                                     library if library is not None else self.library,
                                     original if original is not None else self.original)

    def test_valid_interface_and_symbols(self):
        row = self.interface()
        self.assertEqual((row['outputs'], row['publicInputFields'], row['privateInputDeclarations']), (0, 2091, 19))
        symbols = row['flattenedPublicSymbols']
        self.assertEqual(len(symbols), len(set(symbols)))
        self.assertEqual(symbols[0], 'main.anchor')
        self.assertEqual(symbols[-2:], ['main.tuple[3][519]', 'main.feeTotal'])
        self.assertFalse(any('owner_' in x or '.out[' in x for x in symbols))

    def test_public_surface_mutations(self):
        mutations = [
            (b'assetTag, NF, tuple, feeTotal]', b'assetTag, NF, tuple, feeTotal, owner_nf]'),
            (b'assetTag, NF, tuple, feeTotal]', b'assetTag, NF, tuple, feeTotal, owner_outputTuple]'),
            (b'profileId, roleId, assetTag, NF', b'profileId, assetTag, NF'),
            (b'assetTag, NF, tuple, feeTotal]', b'assetTag, NF, NF, tuple, feeTotal]'),
            (b'signal input tuple[4][520];', b'signal input tuple[4][519];'),
            (b'template TwoOwnerAggregate() {', b'template TwoOwnerAggregate() { signal output leakedM[2];'),
            (b'= TwoOwnerAggregate();', b'= OtherAggregate();'),
            (b'signal input owner_nf[2];', b'signal input owner_nf[2]; signal input ownerSigningKey[2];'),
        ]
        for old, new in mutations:
            with self.subTest(mutation=new.decode()):
                self.assertIn(old, self.wrapper)
                changed = self.wrapper.replace(old, new)
                self.assertNotEqual(changed, self.wrapper)
                with self.assertRaises(ValueError):
                    self.interface(wrapper=changed)
        with self.assertRaises(ValueError):
            self.interface(wrapper=self.wrapper + b'\ncomponent main = Other();\n')

    def test_exact_extraction(self):
        with self.assertRaises(ValueError):
            self.interface(library=self.library + b'\ncomponent main = Other();\n')
        with self.assertRaises(ValueError):
            self.interface(library=self.library + b'\n')
        with self.assertRaises(ValueError):
            self.interface(original=self.original + b'\n')

    def test_recipe_positive_and_mutations(self):
        self.assertEqual(audit.audit_recipe(self.recipe)['actualR1csRequired'], 29)
        recipe = json.loads(self.recipe)
        mutations = []
        for change in ['generation_only', 'replay_reject', 'missing_case', 'duplicate_id', 'wrong_arity', 'extra_output']:
            value = copy.deepcopy(recipe)
            if change == 'generation_only': value['cases'][12]['actualCheckerRequired'] = False
            elif change == 'replay_reject': value['cases'][6]['expectedAccepted'] = False
            elif change == 'missing_case': value['cases'].pop()
            elif change == 'duplicate_id': value['cases'][-1]['id'] = 'N21'
            elif change == 'wrong_arity': value['expectedPublicFieldCount'] = 2090
            elif change == 'extra_output': value['expectedOutputs'] = 35
            mutations.append((change, value))
        for label, value in mutations:
            with self.subTest(mutation=label), self.assertRaises(ValueError):
                audit.audit_recipe(json.dumps(value).encode())


if __name__ == '__main__':
    unittest.main()
