"""CONFIGURED0 adapter for the ADR-0092 V3 recipient reference.

This file deliberately does not replace ``wallet_profile.py`` or mint
production provenance.  It binds the exact phase-1 source so the future
lifecycle can exercise its allocation/export/accept/use seam while the real
private-route authority and durable ledger remain absent.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
V3_REFERENCE = HERE.parents[1] / "future-recipient" / "v3" / "recipient.py"
V3_REFERENCE_SHA256 = (
    "ffa32eeed08788e818178e7429f346edf49041e68aa18a61bdc7b662e9c56183")
STATUS_SCHEMA = "kpb-v3-recipient-lifecycle-source-status/v1"
STATUS = "CONFIGURED0_REFERENCE_ONLY"
V3_LIFECYCLE_CONFIGURED = False


def _digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


if (V3_REFERENCE.is_symlink() or not V3_REFERENCE.is_file()
        or _digest(V3_REFERENCE) != V3_REFERENCE_SHA256):
    raise RuntimeError("v3-reference-source-pin")

_SPEC = importlib.util.spec_from_file_location(
    "_kpb_future_recipient_v3_configured0", V3_REFERENCE)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover - import guard
    raise RuntimeError("v3-reference-source-unavailable")
v3 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = v3
_SPEC.loader.exec_module(v3)


def source_status() -> dict:
    return {
        "authenticated_public_history_adapter": False,
        "atomic_durable_transition_store": False,
        "external_latest_ledger_head_authority": False,
        "private_route_os_authority": False,
        "profile_global_index_allocation_authority": False,
        "production_honest_provenance": False,
        "reference_source_sha256": V3_REFERENCE_SHA256,
        "schema": STATUS_SCHEMA,
        "shared_lifecycle_selected": False,
        "same_process_python_capability_is_authority": False,
        "status": STATUS,
    }


def require_selected() -> None:
    """Fail closed until a distinct OS-authorized lifecycle is implemented."""
    raise v3.Invalid("v3-lifecycle-configured0")


class ReferenceLifecycleAdapter:
    """In-process phase-1 facade; never a producer or acceptance authority."""

    def __init__(self, seed: bytes, binding: "v3.LedgerBinding",
                 crypto_executable: Path):
        self.crypto = v3.Crypto(crypto_executable)
        self.wallet = v3.IssuanceWallet(seed, binding, self.crypto)

    def allocate_for_private_route(self, index: int):
        allocation = self.wallet.allocate(index)
        offer = self.wallet.export_private_invoice(allocation)
        return offer, offer.take_invoice_bytes()

    def accept_from_private_route(self, offer, raw: bytes, *,
                                  attempt_id: bytes):
        return self.wallet.accept_private_invoice(
            offer, raw, attempt_id=attempt_id)

    def produce_reference_output(self, accepted, value_sompi: int, rho: bytes,
                                 position: int, *, attempt_id: bytes):
        return v3.deliver(
            self.crypto, accepted, value_sompi, rho, position,
            attempt_id=attempt_id)

    def export_recovery_ledger(self) -> bytes:
        return self.wallet.export_private_ledger()


__all__ = (
    "ReferenceLifecycleAdapter", "STATUS", "STATUS_SCHEMA",
    "V3_LIFECYCLE_CONFIGURED", "V3_REFERENCE_SHA256", "require_selected",
    "source_status", "v3",
)
