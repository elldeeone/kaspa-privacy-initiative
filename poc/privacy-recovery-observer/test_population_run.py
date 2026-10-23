"""Public metadata-only regression; the actual scorer and ledger are mocked."""
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock,patch

SPEC=importlib.util.spec_from_file_location('reusable_population_controller',Path(__file__).with_name('population_run.py'))
controller=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controller)


class MetadataMerge(unittest.TestCase):
    def test_complete_score_is_retained_in_worker_metadata(self):
        class DummyLedger:
            pass
        public_score=dict(schema='PUBLIC_MOCK_METADATA_ONLY',complete=True,
                          privacy_qualification=False,arm='public-regression')
        mocked_score=Mock(return_value=public_score)
        modules={'population_model':types.SimpleNamespace(Ledger=DummyLedger),
                 'population_score':types.SimpleNamespace(score=mocked_score)}
        with tempfile.TemporaryDirectory(prefix='kpi-public-metadata-regression-') as temporary:
            directory=Path(temporary)
            (directory/'STATUS.json').write_text(json.dumps(dict(complete=True,cluster=7)))
            (directory/'truth.json').write_text(json.dumps(dict(payment_index={'1':2})))
            (directory/'predictions.jsonl').write_text('')
            with patch.dict(sys.modules,modules):
                result=controller.score_worker(directory)
            self.assertTrue(result['complete'])
            self.assertEqual(result['schema'],public_score['schema'])
            self.assertEqual(result['cluster'],7)
            self.assertEqual(result['score_file_sha256'],controller.sha(directory/'score.json'))
            self.assertFalse((directory/'SCORE-FAILURE.json').exists())
            mocked_score.assert_called_once()
            ledger,jobs=mocked_score.call_args.args
            self.assertEqual(ledger.payment_index,{1:2})
            self.assertEqual(jobs,[])


if __name__=='__main__': unittest.main()
