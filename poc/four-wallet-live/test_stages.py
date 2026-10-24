"""Public synthetic schema/alias controls; no runtime, Native, proof or network."""
from copy import deepcopy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import public
import stages
from test_journal import EVIDENCE, P2SH, TRIAL, case, identifier


class PublicStageControls(unittest.TestCase):
    def test_request_uses_pinned_accepted_sizing_and_refuses_local_or_wrong_trial(self):
        profile = {'financial_profile_id': stages.PROFILE_ID, 'child_domain_hex32': stages.DOMAIN}
        sizing = {'schema': 'kpx6-four-wallet-public-sizing/v1',
            'classification': 'INVALID_PUBLIC_RECORD_SIZING_NOT_QUOTE_OR_SETTLEMENT_AUTHORITY',
            'financial_profile_sha256': stages.PROFILE_SHA, 'trial_id': TRIAL,
            'public_source_kind': 'accepted', 'net_principal_sompi': 1_000_000_000,
            'reference_rate': 100, 'recipient_exit_credit_sompi': 17_000_001,
            'genuine_body_requote_and_exact_fee_reconciliation_required': True,
            'private_witness_PK_proof_native_Full_chain_acceptance_or_fee_qualification': False,
            'sizing_grants_spend_authority': False,
            'descriptor_sha256': EVIDENCE, 'fetch_sha256': EVIDENCE,
            'accepted_point': {'transactionId': identifier(77), 'index': 0}, 'actual_DAA': 42}
        recipient = {'schema': 'kpx6-owner-initial-public/v1', 'trial_id': TRIAL, 'role': 'B',
            'financial_profile_id': stages.PROFILE_ID, 'domain_hex32': stages.DOMAIN,
            'network_id': 'testnet-10', 'genesis_hash_hex': stages.GENESIS}
        selected, _ = stages.request(public.encoded(sizing), public.encoded(recipient), profile, TRIAL)
        self.assertEqual(selected['recipient_exit_credit_sompi'], 17_000_001)
        for key, value in (('public_source_kind', 'local'), ('trial_id', '9f160067-3a09-4ad5-b1b4-a6a9896a0000'),
                           ('net_principal_sompi', '1000000000'), ('reference_rate', True),
                           ('recipient_exit_credit_sompi', True), ('sizing_grants_spend_authority', True)):
            changed = deepcopy(sizing); changed[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                stages.request(public.encoded(changed), public.encoded(recipient), profile, TRIAL)

    def test_component_record_requires_exact_auth_payload_proof_slot_and_domain(self):
        point = {'transactionId': identifier(88), 'index': 0}
        auth = bytearray(528)
        auth[:8] = b'KPX4AU01'; auth[8:40] = bytes.fromhex(stages.DOMAIN)
        auth[40:76] = bytes.fromhex(point['transactionId']) + bytes(4)
        auth[76:188] = b'\x22' * 112
        payload, proof = bytes(auth) + bytes(3920-528), b'\x33' * 128
        body = case(1, [point], [2000], [(1980, P2SH)], payload)
        redeem = b'\x4c\x70' + bytes(auth[76:188]) + b'\x55' * 32
        frame = b'\x41' + bytes(65) + b'\x4c\x80' + proof + b'\x4d' + len(redeem).to_bytes(2, 'little') + redeem
        body['transaction']['inputs'][0].update(computeBudget=1600, signatureScript=frame.hex())
        body['entries'][0]['blockDaaScore'] = 0
        component = {'schema': 'kpx4-selected-public-payment-component/v1',
            'classification': 'UNVERIFIED_COMPONENT_EXTERNAL_SETTLEMENT_POLICY_REQUIRED',
            'role': 'compact2', 'fee_context': 'PROPOSED_VIRTUAL_NEW_POLICY_REQUIRED',
            'auth_hex528': bytes(auth).hex(), 'payload_hex': payload.hex(),
            'proof_hex128': proof.hex(), 'public_case': body}
        record = stages.component(public.encoded(component), {'child_domain_hex32': stages.DOMAIN})
        self.assertEqual(bytes.fromhex(record), payload + proof)
        self.assertEqual(len(bytes.fromhex(record)), 4048)
        changed = deepcopy(component); changed['proof_hex128'] = (b'\x44' * 128).hex()
        with self.assertRaises(ValueError):
            stages.component(public.encoded(changed), {'child_domain_hex32': stages.DOMAIN})
        with self.assertRaises(ValueError):
            stages.component(public.encoded(component), {'child_domain_hex32': '00' * 32})

    def test_late_eighth_backup_alias_refuses_all_public_copy_reads(self):
        with tempfile.TemporaryDirectory(prefix='four-wallet-stage-public-controls-') as temporary:
            root = Path(temporary); roots = [root / 'LOCAL', root / 'LIVE']
            for trial_root in roots:
                for role in 'ABCD':
                    folder = trial_root / 'owners' / role; folder.mkdir(parents=True)
                    (folder / 'backup.json').write_bytes(b'PUBLIC_SYNTHETIC_NOT_A_KEY_' + role.encode())
            safe = root / 'public.json'; safe.write_bytes(b'PUBLIC_SELECTED')
            alias = root / 'late-public.json'; alias.hardlink_to(roots[1] / 'owners/D/backup.json')
            args = SimpleNamespace(operation='copy-public', exclude_trial_directory=roots,
                file=[safe, alias], file_sha256=[public.digest(b'PUBLIC_SELECTED'), '00' * 32],
                output=root / 'out')
            with patch.object(stages.Exclusions, 'read') as read:
                with self.assertRaises(ValueError):
                    stages.run(args)
                read.assert_not_called()
            self.assertFalse(args.output.exists())

    def test_postquery_eighth_backup_alias_refuses_before_first_page_read(self):
        # These are metadata/sentinel fixtures, not compressed accepted pages.
        with tempfile.TemporaryDirectory(prefix='four-wallet-bundle-public-controls-') as temporary:
            root = Path(temporary); roots = [root / 'LOCAL', root / 'LIVE']
            for trial_root in roots:
                for role in 'ABCD':
                    folder = trial_root / 'owners' / role; folder.mkdir(parents=True)
                    (folder / 'backup.json').write_bytes(b'PUBLIC_SYNTHETIC_NOT_A_KEY_' + role.encode())
            source = root / 'public-bundle'; source.mkdir()
            safe = source / 'base' / '0000.json.gz'; safe.parent.mkdir()
            safe.write_bytes(b'PUBLIC_SYNTHETIC_NOT_GZIP_OR_FULL_RPC')
            alias = source / 'post' / '0001.json.gz'; alias.parent.mkdir()
            alias.hardlink_to(roots[1] / 'owners/D/backup.json')

            def page(name, length, pin):
                return {'path': name, 'request': {'startHash': EVIDENCE,
                    'dataVerbosityLevel': 'Full', 'minConfirmationCount': 20},
                    'decoded_sha256': EVIDENCE, 'decoded_bytes': 0,
                    'gzip_sha256': pin, 'gzip_bytes': length,
                    'encoding': 'PUBLIC_SYNTHETIC_METADATA_ONLY_NOT_ACCEPTED_EVIDENCE'}

            fetch = root / 'fetch.json'
            metadata = {'schema': 'kpx5-gn2-network-fetch/v1', 'status': 'FETCHED_PENDING_REPLAY',
                'pages': [page('base/0000.json.gz', safe.stat().st_size,
                               public.digest(b'PUBLIC_SYNTHETIC_NOT_GZIP_OR_FULL_RPC'))],
                'current_view': {'post_query_delta': {'pages': [page('post/0001.json.gz', 1, '00' * 32)]}}}
            raw = public.encoded(metadata); fetch.write_bytes(raw)
            args = SimpleNamespace(operation='bundle', exclude_trial_directory=roots,
                fetch=fetch, fetch_sha256=public.digest(raw), bundle_directory=source,
                output=root / 'out')
            actual_read, reads = stages.Exclusions.read, []

            def tracked(exclusions, path, pin):
                reads.append(Path(path))
                return actual_read(exclusions, path, pin)

            with patch.object(stages.Exclusions, 'read', new=tracked):
                with self.assertRaises(ValueError):
                    stages.run(args)
            self.assertEqual(reads, [fetch])
            self.assertFalse(args.output.exists())


if __name__ == '__main__':
    unittest.main()
