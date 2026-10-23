"""Crash recovery must never send again or bypass the next owner check."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_chain as driver


class ResumeTests(unittest.TestCase):
    def trace(self, root, saved):
        trace = driver.Trace.__new__(driver.Trace)
        trace.trial = root
        trace.public = root / 'chain-public'
        trace.release = root / 'chain-release.json'
        trace.profile = {'trial_id': 'test', 'domain_hex32': '11' * 32}
        trace.complete = {'payouts_sompi': {'bob': 95_000_000, 'charlie': 95_000_000},
                          'total_fees_sompi': 30_000_000, 'fee_qualification': False}
        driver.save(root / 'LOCAL-COMPLETE.json', trace.complete)
        driver.save(trace.release, {'local_complete_sha256': driver.digest(root / 'LOCAL-COMPLETE.json')})
        trace.check_sources = lambda release: None
        for stage in driver.KINDS[:saved]:
            driver.save(trace.public / 'observations' / (stage + '.json'), {'start_hash': 'aa' * 32})
        return trace

    def test_saved_private_still_requires_owner_gate_before_new_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            trace = self.trace(Path(tmp), 4)
            trace.recovery_archive = lambda index, observations: index
            def reject(phase, owner):
                self.assertEqual((phase, owner), (3, 'bob'))
                raise ValueError('recovery rejected')
            trace.check_owner = reject
            with patch.object(driver, 'call', side_effect=AssertionError('network must not run')):
                with self.assertRaisesRegex(ValueError, 'recovery rejected'):
                    trace.run()

    def test_ambiguous_terminal_send_only_observes_and_reuses_exact_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            trace = self.trace(Path(tmp), 5)
            # Bob's accepted spend makes the private head spent. Charlie's
            # durable send marker means its outcome must be reconciled, never resent.
            for stage in ('bob-reveal', 'charlie-reveal'):
                driver.save(trace.trial / 'chain' / (stage + '.submission-intent.json'),
                            {'start_hash': 'bb' * 32})
            body = {'id': 'cc' * 32}
            driver.save(trace.public / 'bodies/charlie-reveal.json', body)
            reads = []
            def observe(index, start, indices=None):
                reads.append((index, start))
                return {'accepted_body': body, 'transaction_id': body['id'], 'start_hash': start}
            trace.observe = observe
            def archive(index, observations):
                self.assertEqual(index, 5, 'must not require an already spent earlier head')
                return index
            trace.recovery_archive = archive
            trace.check_owner = lambda phase, owner: {'passed': True}
            with patch.object(driver, 'call', side_effect=AssertionError('no resend/checkpoint allowed')):
                with contextlib.redirect_stdout(io.StringIO()):
                    result = trace.run()
            self.assertEqual(reads, [(5, 'bb' * 32)])
            self.assertEqual(result['confirmed_native_operations'], 6)

    def test_retained_body_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'body.json'
            driver.save(path, {'id': 'original'})
            with self.assertRaisesRegex(ValueError, 'retained artifact differs'):
                driver.save_or_match(path, {'id': 'substituted'})
            self.assertEqual(json.loads(path.read_text()), {'id': 'original'})


if __name__ == '__main__':
    unittest.main()
