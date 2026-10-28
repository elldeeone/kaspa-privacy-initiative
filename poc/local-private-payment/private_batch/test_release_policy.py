import hashlib
import itertools
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from release_policy import DisclosureHistory, PreparedRelease, Refused, REFUSAL


def token(value: str) -> bytes:
    return hashlib.sha256(('public synthetic token ' + value).encode()).digest()


class DisclosurePolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='kpi-public-disclosure-model-')
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'history.sqlite'
        self.policy = token('policy')
        self.history = DisclosureHistory.initialize_new_epoch(self.path, self.policy)
        self.genesis = self.history.checkpoint
        self.members = tuple(token(name) for name in 'ABC')
        self.effects = b'public synthetic effects for one complete ABC batch'

    def prepare(self):
        return self.history.prepare(self.members, hashlib.sha256(self.effects).digest())

    def assert_refused(self, function):
        with self.assertRaises(Refused) as caught:
            function()
        self.assertEqual(str(caught.exception), REFUSAL)
        for member in self.members:
            self.assertNotIn(member.hex(), str(caught.exception))

    def test_prepare_and_publication_are_durable_before_callback(self):
        ticket = self.prepare()
        observed = []

        def emit(artifact):
            reopened = DisclosureHistory(self.path, self.policy, self.history.checkpoint)
            observed.append((len(reopened._read()), artifact[:8]))

        self.history.publish(ticket, self.effects, b'opaque synthetic proof', emit)
        self.assertEqual(observed, [(2, b'KPBMOD01')])

    def test_changed_cohort_refuses_even_with_fresh_job(self):
        self.prepare()
        for names in ('ADE', 'ABD', 'BCD'):
            self.assert_refused(lambda names=names:self.history.prepare(tuple(token(name) for name in names), token('fresh effects/job')))

    def test_identical_cohort_requires_identical_effects(self):
        first = self.prepare()
        second = self.history.prepare(tuple(reversed(self.members)), hashlib.sha256(self.effects).digest())
        self.assertGreater(second.sequence, first.sequence)
        self.assert_refused(lambda:self.history.prepare(self.members, token('changed fee/head/output')))

    def test_missing_history_never_initializes_implicitly(self):
        head = self.prepare().checkpoint
        self.path.unlink()
        self.assert_refused(lambda:DisclosureHistory(self.path, self.policy, head))
        self.assert_refused(lambda:self.history.prepare(self.members, token('new effects')))
        self.assertFalse(self.path.exists())

    def test_rollback_is_detected_against_external_latest_checkpoint(self):
        old_copy = self.path.with_name('old-copy.sqlite')
        shutil.copyfile(self.path, old_copy)
        latest = self.prepare().checkpoint
        shutil.copyfile(old_copy, self.path)
        self.assert_refused(lambda:DisclosureHistory(self.path, self.policy, latest))

    def test_both_history_and_anchor_rollback_is_an_explicit_limit(self):
        old_copy = self.path.with_name('old-copy.sqlite')
        shutil.copyfile(self.path, old_copy)
        self.prepare()
        shutil.copyfile(old_copy, self.path)
        # Expected limitation: no local mechanism can know a trusted external
        # checkpoint was also rolled back. This preserves a privacy FAIL case.
        rolled_back = DisclosureHistory(self.path, self.policy, self.genesis)
        self.assertEqual(rolled_back._read(), [])

    def test_wrong_service_or_profile_refuses(self):
        self.prepare()
        self.assert_refused(lambda:DisclosureHistory(self.path, token('another policy'), self.history.checkpoint))

    def test_lost_peer_history_or_corruption_refuses(self):
        head = self.prepare().checkpoint
        self.path.write_bytes(b'not a sqlite database')
        self.assert_refused(lambda:DisclosureHistory(self.path, self.policy, head))

    def test_uncertain_publication_remains_pinned(self):
        ticket = self.prepare()

        def interrupted(_):
            raise RuntimeError('simulated crash after durable publication intent')

        with self.assertRaises(RuntimeError):
            self.history.publish(ticket, self.effects, b'opaque synthetic proof', interrupted)
        reopened = DisclosureHistory(self.path, self.policy, self.history.checkpoint)
        self.assert_refused(lambda:reopened.publish(ticket, self.effects, b'opaque synthetic proof', lambda _:None))
        self.assert_refused(lambda:reopened.prepare(tuple(token(name) for name in 'ADE'), token('new effects')))

    def test_wrong_artifact_or_forged_ticket_never_emits(self):
        ticket = self.prepare()
        emitted = []
        self.assert_refused(lambda:self.history.publish(ticket, b'substituted native effects', b'proof', emitted.append))
        forged = PreparedRelease(ticket.sequence, token('wrong checkpoint'), ticket.effects_digest)
        self.assert_refused(lambda:self.history.publish(forged, self.effects, b'proof', emitted.append))
        self.assert_refused(lambda:self.history.publish(ticket, self.effects, b'', emitted.append))
        self.assertEqual(emitted, [])

    def test_stale_concurrent_writer_refuses(self):
        stale = DisclosureHistory(self.path, self.policy, self.genesis)
        self.prepare()
        self.assert_refused(lambda:stale.prepare(tuple(token(name) for name in 'DEF'), token('other effects')))

    def test_disjoint_batches_and_one_time_ticket(self):
        ticket = self.prepare()
        self.history.prepare(tuple(token(name) for name in 'DEF'), token('other effects'))
        emitted = []
        self.history.publish(ticket, self.effects, b'proof', emitted.append)
        self.assertEqual(len(emitted), 1)
        self.assert_refused(lambda:self.history.publish(ticket, self.effects, b'proof', emitted.append))

    def test_malformed_member_sets_refuse(self):
        for members in (self.members[:2], self.members + (token('D'),), (self.members[0],) * 3,
                        (bytes(32), *self.members[1:]), list(self.members)):
            self.assert_refused(lambda members=members:self.history.prepare(members, token('effects')))

    def test_tampered_hash_chain_refuses(self):
        head = self.prepare().checkpoint
        connection = sqlite3.connect(self.path)
        connection.execute('UPDATE events SET payload = ?', (b'{}',))
        connection.commit()
        connection.close()
        self.assert_refused(lambda:DisclosureHistory(self.path, self.policy, head))

    def test_malformed_event_refuses_even_with_matching_supplied_anchor(self):
        payload = b'null'
        forged_head = hashlib.sha256(b'KPBHEVT1' + self.genesis + payload).digest()
        connection = sqlite3.connect(self.path)
        connection.execute('INSERT INTO events VALUES (?, ?, ?)', (1, payload, forged_head))
        connection.execute('UPDATE metadata SET head = ?', (forged_head,))
        connection.commit()
        connection.close()
        self.assert_refused(lambda:DisclosureHistory(self.path, self.policy, forged_head))

    def test_exit_race_cost_is_private_liveness_without_exit_authority(self):
        self.prepare()
        # C's independent Exit consumes C. The model cannot create a replacement
        # ABC financial batch and deliberately refuses survivors with new peers.
        self.assert_refused(lambda:self.history.prepare(tuple(token(name) for name in 'ADE'), token('after C exit')))
        self.assertFalse(hasattr(self.history, 'authorize_exit'))
        self.assertFalse(hasattr(self.history, 'freeze_exit'))

    def test_original_known_cohort_intersection_counterexample_is_retained(self):
        owners = 'ABCDE'
        nfs = {name:token(name) for name in owners}
        first = {nfs[name] for name in 'ABC'}
        second = {nfs[name] for name in 'ADE'}
        self.assertEqual(first & second, {nfs['A']})
        # Same-cohort publication leaves A/B interchangeable once C is known.
        candidates = []
        for permutation in itertools.permutations(first - {nfs['C']}):
            candidates.append(dict(zip('AB', permutation)))
        self.assertEqual(len(candidates), 2)
        self.assertEqual({mapping['A'] for mapping in candidates}, {nfs['A'], nfs['B']})


if __name__ == '__main__':
    unittest.main()
