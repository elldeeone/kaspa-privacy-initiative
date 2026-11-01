"""Source-only V3 adapter controls; public synthetic data, no lifecycle."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import unittest

import wallet_profile_v3 as adapter


BRIDGE = Path(os.environ.get(
    "KPX_RECIPIENT_CRYPTO",
    "/home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/"
    "kpi-future-recipient-crypto"))


class WalletProfileV3AdapterControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seed = hashlib.sha256(b"PUBLIC V3 ADAPTER SEED DO NOT FUND").digest()
        cls.binding = adapter.v3.LedgerBinding(
            hashlib.sha256(b"PUBLIC V3 ADAPTER DOMAIN").digest(),
            hashlib.sha256(b"PUBLIC V3 ADAPTER PROFILE").digest(),
            hashlib.sha256(b"PUBLIC V3 ADAPTER OWNER").digest(),
            hashlib.sha256(b"PUBLIC V3 ADAPTER ATTEMPT").digest())

    def test_source_status_is_exact_and_selection_always_refuses(self):
        self.assertFalse(adapter.V3_LIFECYCLE_CONFIGURED)
        self.assertEqual(adapter.source_status(), {
            "authenticated_public_history_adapter": False,
            "atomic_durable_transition_store": False,
            "external_latest_ledger_head_authority": False,
            "private_route_os_authority": False,
            "profile_global_index_allocation_authority": False,
            "production_honest_provenance": False,
            "reference_source_sha256": adapter.V3_REFERENCE_SHA256,
            "schema": "kpb-v3-recipient-lifecycle-source-status/v1",
            "shared_lifecycle_selected": False,
            "same_process_python_capability_is_authority": False,
            "status": "CONFIGURED0_REFERENCE_ONLY",
        })
        with self.assertRaisesRegex(
                adapter.v3.Invalid, "^v3-lifecycle-configured0$"):
            adapter.require_selected()

        here = Path(__file__).resolve().parent
        for selected_source in (
                "wallet_profile.py", "output_producer.py",
                "private_lifecycle.py", "lifecycle_worker.py"):
            self.assertNotIn(
                "wallet_profile_v3", (here / selected_source).read_text())

    def test_adapter_runs_only_the_pinned_reference_capability_path(self):
        lifecycle = adapter.ReferenceLifecycleAdapter(
            self.seed, self.binding, BRIDGE)
        offer, raw = lifecycle.allocate_for_private_route(7)
        self.assertEqual(len(raw), 208)
        accepted = lifecycle.accept_from_private_route(
            offer, raw, attempt_id=self.binding.attempt_id)
        delivery = lifecycle.produce_reference_output(
            accepted, 120_000_000,
            hashlib.sha256(b"PUBLIC V3 ADAPTER RHO").digest(), 0,
            attempt_id=self.binding.attempt_id)
        self.assertEqual(len(delivery.ciphertext), 264)
        recovered = adapter.v3.recover(
            self.seed, self.binding, lifecycle.crypto,
            lifecycle.export_recovery_ledger(), [delivery])
        self.assertEqual(recovered.phase1_consumed_sompi, 120_000_000)
        self.assertFalse(adapter.source_status()["production_honest_provenance"])

    def test_raw_invoice_cannot_replace_private_offer(self):
        lifecycle = adapter.ReferenceLifecycleAdapter(
            self.seed, self.binding, BRIDGE)
        offer, raw = lifecycle.allocate_for_private_route(8)
        parsed = adapter.v3.Invoice.parse(raw)
        with self.assertRaisesRegex(
                adapter.v3.Invalid, "^honest-invoice-capability$"):
            lifecycle.accept_from_private_route(
                parsed, raw, attempt_id=self.binding.attempt_id)

        changed = raw[:-1] + bytes([raw[-1] ^ 1])
        with self.assertRaisesRegex(
                adapter.v3.Invalid, "^private-invoice-mismatch$"):
            lifecycle.accept_from_private_route(
                offer, changed, attempt_id=self.binding.attempt_id)
        with self.assertRaisesRegex(
                adapter.v3.Invalid, "^invoice-not-live$"):
            lifecycle.accept_from_private_route(
                offer, raw, attempt_id=self.binding.attempt_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
