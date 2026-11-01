"""V3 one-use recipient reference; synthetic Testnet research only.

The mature Rust bridge supplies X25519 sealed boxes and secp256k1 public keys.
This module adds no cryptographic primitive. Its Python capability is an
in-process reference seam, not an OS/process authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import struct
import subprocess

SELECTED_CRYPTO_SHA256 = (
    "6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff")


class Invalid(ValueError):
    """A deterministic validation category; never includes secret material."""


class Crypto:
    """Exact retained RustCrypto bridge, executed from a content-checked fd."""
    def __init__(self, executable: Path):
        path = Path(executable).absolute()
        if path.is_symlink() or not path.is_file():
            raise Invalid("selected-crypto-pin")
        self.executable = path
        descriptor = self._open_selected()
        os.close(descriptor)

    def _open_selected(self) -> int:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.executable, flags)
        except OSError:
            raise Invalid("selected-crypto-pin") from None
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise Invalid("selected-crypto-pin")
            digest = hashlib.sha256()
            blocks = []
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                blocks.append(block)
                digest.update(block)
            if digest.hexdigest() != SELECTED_CRYPTO_SHA256:
                raise Invalid("selected-crypto-pin")
            try:
                sealed = os.memfd_create(
                    "kpb-v3-crypto",
                    os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                for block in blocks:
                    offset = 0
                    while offset < len(block):
                        offset += os.write(sealed, block[offset:])
                os.fchmod(sealed, 0o500)
                fcntl.fcntl(
                    sealed, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
                os.lseek(sealed, 0, os.SEEK_SET)
            except (AttributeError, OSError):
                if "sealed" in locals():
                    os.close(sealed)
                raise Invalid("selected-crypto-pin") from None
            os.close(descriptor)
            return sealed
        except Exception:
            os.close(descriptor)
            raise

    def call(self, op: str, *, secret=None, public=None, payload=None) -> bytes:
        request = {"op": op}
        for key, value in (("secret_hex", secret), ("public_hex", public),
                           ("payload_hex", payload)):
            if value is not None:
                request[key] = value.hex()
        descriptor = self._open_selected()
        try:
            try:
                proc = subprocess.run(
                    [f"/proc/self/fd/{descriptor}"], pass_fds=(descriptor,),
                    input=json.dumps(request), text=True, capture_output=True,
                    check=False)
            except OSError:
                raise Invalid("crypto-adapter") from None
        finally:
            os.close(descriptor)
        try:
            result = json.loads(proc.stdout)
        except (ValueError, TypeError):
            raise Invalid("crypto-adapter") from None
        if type(result) is not dict:
            raise Invalid("crypto-adapter")
        if proc.returncode or "error" in result:
            raise Invalid("crypto-" + str(result.get("error", "adapter")))
        if set(result) != {"hex"} or type(result["hex"]) is not str:
            raise Invalid("crypto-adapter")
        try:
            return bytes.fromhex(result["hex"])
        except (ValueError, KeyError, TypeError):
            raise Invalid("crypto-adapter") from None

    def xonly(self, secret: bytes) -> bytes:
        return fixed(self.call("derive-xonly", secret=fixed(secret)))

    def delivery_public(self, secret: bytes) -> bytes:
        return fixed(self.call("derive-delivery", secret=fixed(secret)))

    def seal(self, public: bytes, plaintext: bytes) -> bytes:
        return self.call("seal", public=fixed(public), payload=plaintext)

    def unseal(self, secret: bytes, ciphertext: bytes) -> bytes:
        return self.call("unseal", secret=fixed(secret), payload=ciphertext)

KDF_TAG = b"KPBKDF01"
OWNER_TAG = b"KPX1OWN\0"
KEY_TAG = b"KPX1KEY\0"
NOTE_TAG = b"KPX1NOT\0"
INVOICE_MAGIC = b"KPX3IN01"
RECEIPT_MAGIC = b"KPX3RC01"
RECIPIENT_PROFILE = "KPX3-ONE-USE-HIDDEN-INVOICE-KEYS"
LEDGER_SCHEMA = "kpx3-private-invoice-ledger/v1"
LEDGER_EVENT_TAG = b"KPX3_LEDGER_EVENT_V1\n"
LEDGER_EXPORT_TAG = b"KPX3_LEDGER_EXPORT_V1\n"
MIN_NOTE_SOMPI = 60_000_000
MAX_SOMPI = 2_870_000_000_000_000_000
ZERO = bytes(32)


def h(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def fixed(value: bytes, size: int = 32) -> bytes:
    if type(value) is not bytes or len(value) != size:
        raise Invalid("bytes-length")
    return value


def uint(value: int, bits: int) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise Invalid("integer-range")
    return value


def u32(value: int) -> bytes:
    return struct.pack("<I", uint(value, 32))


def u64(value: int) -> bytes:
    return struct.pack("<Q", uint(value, 64))


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def _strict_hex(value, size: int) -> bytes:
    if type(value) is not str or len(value) != 2 * size:
        raise Invalid("ledger-encoding")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise Invalid("ledger-encoding") from None
    if len(raw) != size or raw.hex() != value:
        raise Invalid("ledger-encoding")
    return raw


def _strict_json(raw: bytes):
    if type(raw) is not bytes or not raw.endswith(b"\n"):
        raise Invalid("ledger-encoding")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise Invalid("ledger-encoding")
            result[key] = value
        return result

    try:
        value = json.loads(raw[:-1].decode("ascii"), object_pairs_hook=unique)
    except (UnicodeDecodeError, ValueError, TypeError, Invalid):
        raise Invalid("ledger-encoding") from None
    if raw != _canonical(value) + b"\n":
        raise Invalid("ledger-canonical")
    return value


@dataclass(frozen=True)
class LedgerBinding:
    domain: bytes
    profile_id: bytes
    owner_id: bytes
    attempt_id: bytes

    def __post_init__(self):
        for value in (self.domain, self.profile_id, self.owner_id, self.attempt_id):
            fixed(value)
            if value == ZERO:
                raise Invalid("ledger-binding")


def derive(seed: bytes, binding: LedgerBinding, role: bytes, index: int,
           retry: int | None = None) -> bytes:
    message = (KDF_TAG + fixed(binding.profile_id) + fixed(binding.domain)
               + fixed(role, 8) + u64(index))
    if retry is not None:
        message += u32(retry)
    return hmac.digest(fixed(seed), message, "sha256")


@dataclass(frozen=True)
class Invoice:
    domain: bytes
    index: int
    owner: bytes
    incoming: bytes
    key_commitment: bytes
    native_pk: bytes
    delivery_pk: bytes

    def encode(self) -> bytes:
        return (INVOICE_MAGIC + fixed(self.domain) + u64(self.index)
                + fixed(self.owner) + fixed(self.incoming)
                + fixed(self.key_commitment) + fixed(self.native_pk)
                + fixed(self.delivery_pk))

    @classmethod
    def parse(cls, raw: bytes) -> "Invoice":
        fixed(raw, 208)
        if raw[:8] != INVOICE_MAGIC:
            raise Invalid("invoice-magic")
        return cls(raw[8:40], int.from_bytes(raw[40:48], "little"),
                   raw[48:80], raw[80:112], raw[112:144], raw[144:176],
                   raw[176:208])


@dataclass(frozen=True)
class Receipt:
    domain: bytes
    index: int
    owner: bytes
    incoming: bytes
    value_sompi: int
    rho: bytes
    key_commitment: bytes
    native_pk: bytes

    @classmethod
    def for_invoice(cls, invoice: Invoice, value_sompi: int,
                    rho: bytes) -> "Receipt":
        invoice.encode()
        return cls(invoice.domain, invoice.index, invoice.owner, invoice.incoming,
                   value_sompi, fixed(rho), invoice.key_commitment,
                   invoice.native_pk)

    def invoice(self, delivery_pk: bytes) -> Invoice:
        return Invoice(self.domain, self.index, self.owner, self.incoming,
                       self.key_commitment, self.native_pk, fixed(delivery_pk))

    def note_bytes(self) -> bytes:
        if not MIN_NOTE_SOMPI <= uint(self.value_sompi, 64) <= MAX_SOMPI:
            raise Invalid("note-value")
        return (fixed(self.owner) + fixed(self.incoming) + u64(self.value_sompi)
                + fixed(self.rho) + fixed(self.key_commitment)
                + fixed(self.native_pk))

    def encode(self) -> bytes:
        return RECEIPT_MAGIC + fixed(self.domain) + u64(self.index) + self.note_bytes()

    def commitment(self) -> bytes:
        return h(NOTE_TAG, fixed(self.domain), self.note_bytes())

    @classmethod
    def parse(cls, raw: bytes) -> "Receipt":
        fixed(raw, 216)
        if raw[:8] != RECEIPT_MAGIC:
            raise Invalid("receipt-magic")
        receipt = cls(raw[8:40], int.from_bytes(raw[40:48], "little"),
                      raw[48:80], raw[80:112],
                      int.from_bytes(raw[112:120], "little"), raw[120:152],
                      raw[152:184], raw[184:216])
        receipt.encode()
        return receipt


@dataclass(frozen=True, repr=False)
class _Keys:
    owner_secret: bytes
    nf_secret: bytes
    native_secret: bytes
    delivery_secret: bytes
    invoice: Invoice


@dataclass
class _Entry:
    keys: _Keys
    state: str
    capability: object


_CAPABILITY_MINT = object()


class _InvoiceCapability:
    """Opaque in-process stand-in for one authenticated lifecycle stage."""
    __slots__ = ("_wallet", "_index", "_nonce")

    def __init__(self, mint, wallet: "IssuanceWallet", index: int):
        if mint is not _CAPABILITY_MINT:
            raise Invalid("honest-invoice-capability")
        self._wallet = wallet
        self._index = index
        self._nonce = object()

    def __copy__(self):
        raise Invalid("honest-invoice-capability")

    def __deepcopy__(self, memo):
        raise Invalid("honest-invoice-capability")

    def __reduce__(self):
        raise Invalid("honest-invoice-capability")


class InvoiceAllocationCapability(_InvoiceCapability):
    """A permanently allocated but not yet exported V3 invoice index."""
    __slots__ = ()


class ExportedInvoiceCapability(_InvoiceCapability):
    """A one-shot private-route offer carrying exact Invoice208 bytes."""
    __slots__ = ("_taken",)

    def __init__(self, mint, wallet: "IssuanceWallet", index: int):
        super().__init__(mint, wallet, index)
        self._taken = False

    def take_invoice_bytes(self) -> bytes:
        entry = self._wallet._entry_for(self, ExportedInvoiceCapability)
        if entry.state != "EXPORTED":
            raise Invalid("invoice-not-live")
        if self._taken:
            raise Invalid("private-invoice-already-taken")
        self._taken = True
        return entry.keys.invoice.encode()


class AcceptedInvoiceCapability(_InvoiceCapability):
    """A sender-accepted offer that alone can authorize phase-1 delivery."""
    __slots__ = ()

    def invoice(self) -> Invoice:
        return self._wallet._entry_for(
            self, AcceptedInvoiceCapability).keys.invoice


class IssuanceWallet:
    def __init__(self, seed: bytes, binding: LedgerBinding, crypto: Crypto):
        self._seed = fixed(seed)
        if not isinstance(binding, LedgerBinding):
            raise Invalid("ledger-binding")
        if type(crypto) is not Crypto:
            raise Invalid("crypto-adapter-binding")
        self.binding = binding
        self.crypto = crypto
        self._entries: dict[int, _Entry] = {}
        self._events: list[dict] = []
        self._head = ZERO

    def _derive_keys(self, index: int) -> _Keys:
        uint(index, 64)
        owner_secret = derive(self._seed, self.binding, b"OWNSEC\0\0", index)
        nf_secret = derive(self._seed, self.binding, b"KSECRET\0", index)
        incoming = derive(self._seed, self.binding, b"INCOMING", index)
        delivery_secret = derive(self._seed, self.binding, b"DELIVERY", index)
        delivery_pk = self.crypto.delivery_public(delivery_secret)
        for retry in range(1 << 32):
            native_secret = derive(
                self._seed, self.binding, b"NATIVE\0\0", index, retry)
            try:
                native_pk = self.crypto.xonly(native_secret)
                break
            except Invalid as error:
                if str(error) != "crypto-scalar":
                    raise
        else:  # pragma: no cover - 2^32 rejected scalars is infeasible
            raise Invalid("native-scalar-exhausted")
        invoice = Invoice(
            self.binding.domain, index,
            h(OWNER_TAG, self.binding.domain, owner_secret, incoming), incoming,
            h(KEY_TAG, self.binding.domain, nf_secret), native_pk, delivery_pk)
        invoice.encode()
        return _Keys(owner_secret, nf_secret, native_secret, delivery_secret,
                     invoice)

    def allocate(self, index: int) -> InvoiceAllocationCapability:
        uint(index, 64)
        if index in self._entries:
            raise Invalid("invoice-index-reuse")
        keys = self._derive_keys(index)
        if any(entry.keys.invoice.delivery_pk == keys.invoice.delivery_pk
               for entry in self._entries.values()):
            raise Invalid("delivery-key-reuse")
        capability = InvoiceAllocationCapability(_CAPABILITY_MINT, self, index)
        self._entries[index] = _Entry(keys, "ALLOCATED", capability)
        self._append_event(index, "ALLOCATED", keys.invoice)
        return capability

    def export_private_invoice(
            self, capability: InvoiceAllocationCapability,
    ) -> ExportedInvoiceCapability:
        entry = self._entry_for(capability, InvoiceAllocationCapability)
        if entry.state != "ALLOCATED":
            raise Invalid("invoice-not-live")
        exported = ExportedInvoiceCapability(
            _CAPABILITY_MINT, self, capability._index)
        entry.state = "EXPORTED"
        entry.capability = exported
        self._append_event(capability._index, "EXPORTED", entry.keys.invoice)
        return exported

    def accept_private_invoice(
            self, capability: ExportedInvoiceCapability, raw: bytes, *,
            attempt_id: bytes,
    ) -> AcceptedInvoiceCapability:
        entry = self._entry_for(capability, ExportedInvoiceCapability)
        if entry.state != "EXPORTED":
            raise Invalid("invoice-not-live")
        try:
            accepted_attempt = fixed(attempt_id)
        except Invalid:
            self._poison_live(capability)
            raise Invalid("cross-attempt-invoice") from None
        if accepted_attempt != self.binding.attempt_id:
            self._poison_live(capability)
            raise Invalid("cross-attempt-invoice")
        if not capability._taken:
            self._poison_live(capability)
            raise Invalid("private-invoice-not-transferred")
        expected = entry.keys.invoice.encode()
        if type(raw) is not bytes or not hmac.compare_digest(raw, expected):
            self._poison_live(capability)
            raise Invalid("private-invoice-mismatch")
        accepted = AcceptedInvoiceCapability(
            _CAPABILITY_MINT, self, capability._index)
        entry.state = "ACCEPTED"
        entry.capability = accepted
        self._append_event(capability._index, "ACCEPTED", entry.keys.invoice)
        return accepted

    def _append_event(self, index: int, state: str, invoice: Invoice) -> None:
        event = {
            "index": uint(index, 64),
            "invoice_hex208": invoice.encode().hex(),
            "previous_sha256": self._head.hex(),
            "sequence": len(self._events),
            "state": state,
        }
        digest = h(LEDGER_EVENT_TAG, _canonical(event))
        event["event_sha256"] = digest.hex()
        self._events.append(event)
        self._head = digest

    def _entry_for(self, capability: _InvoiceCapability,
                   expected_type: type[_InvoiceCapability]) -> _Entry:
        if type(capability) is not expected_type:
            raise Invalid("honest-invoice-capability")
        entry = self._entries.get(capability._index)
        if entry is None or entry.capability is not capability:
            raise Invalid("invoice-not-live")
        return entry

    def _consume(self, capability: AcceptedInvoiceCapability,
                 attempt_id: bytes) -> Invoice:
        try:
            accepted_attempt = fixed(attempt_id)
        except Invalid:
            self._poison_live(capability)
            raise Invalid("cross-attempt-invoice") from None
        if accepted_attempt != self.binding.attempt_id:
            self._poison_live(capability)
            raise Invalid("cross-attempt-invoice")
        entry = self._entry_for(capability, AcceptedInvoiceCapability)
        if entry.state != "ACCEPTED":
            raise Invalid("invoice-not-live")
        entry.state = "CONSUMED"
        self._append_event(capability._index, "CONSUMED", entry.keys.invoice)
        return entry.keys.invoice

    def _poison_live(self, capability: _InvoiceCapability) -> None:
        expected = {
            "ALLOCATED": InvoiceAllocationCapability,
            "EXPORTED": ExportedInvoiceCapability,
            "ACCEPTED": AcceptedInvoiceCapability,
        }
        entry = self._entries.get(getattr(capability, "_index", None))
        if (entry is None or entry.state not in expected
                or type(capability) is not expected[entry.state]
                or entry.capability is not capability):
            raise Invalid("invoice-not-live")
        entry.state = "POISONED"
        self._append_event(capability._index, "POISONED", entry.keys.invoice)

    def abandon(self, capability: _InvoiceCapability) -> None:
        self._poison_live(capability)

    def _poison_after_consume(
            self, capability: AcceptedInvoiceCapability) -> None:
        entry = self._entry_for(capability, AcceptedInvoiceCapability)
        if entry.state != "CONSUMED":
            raise Invalid("invoice-not-live")
        entry.state = "POISONED"
        self._append_event(capability._index, "POISONED", entry.keys.invoice)

    def export_private_ledger(self) -> bytes:
        body = {
            "attempt_id_hex32": self.binding.attempt_id.hex(),
            "domain_hex32": self.binding.domain.hex(),
            "event_count": len(self._events),
            "events": self._events,
            "head_sha256": self._head.hex(),
            "owner_id_hex32": self.binding.owner_id.hex(),
            "profile_id_hex32": self.binding.profile_id.hex(),
            "recipient_profile": RECIPIENT_PROFILE,
            "schema": LEDGER_SCHEMA,
        }
        ledger_key = derive(self._seed, self.binding, b"LEDGER\0\0", 0)
        mac = hmac.digest(ledger_key, LEDGER_EXPORT_TAG + _canonical(body),
                          "sha256")
        return _canonical({**body, "hmac_sha256": mac.hex()}) + b"\n"


@dataclass(frozen=True, repr=False)
class _RecoveredEntry:
    keys: _Keys
    state: str


class RestoredPrivateLedger:
    """Recovery-only authenticated state; it cannot mint or consume invoices."""
    def __init__(self, binding: LedgerBinding, crypto: Crypto,
                 entries: dict[int, _RecoveredEntry], head: bytes):
        self.binding = binding
        self.crypto = crypto
        self._entries = dict(entries)
        self._head = fixed(head)

    def entry_statuses(self) -> tuple[tuple[int, str], ...]:
        return tuple((index, self._entries[index].state)
                     for index in sorted(self._entries))

    def _keys_for(self, index: int) -> _Keys:
        try:
            return self._entries[index].keys
        except KeyError:
            raise Invalid("ledger-index") from None


def restore_private_ledger(seed: bytes, binding: LedgerBinding, crypto: Crypto,
                           raw: bytes) -> RestoredPrivateLedger:
    seed = fixed(seed)
    if not isinstance(binding, LedgerBinding):
        raise Invalid("ledger-binding")
    if type(crypto) is not Crypto:
        raise Invalid("crypto-adapter-binding")
    value = _strict_json(raw)
    expected_keys = {
        "attempt_id_hex32", "domain_hex32", "event_count", "events",
        "head_sha256", "hmac_sha256", "owner_id_hex32", "profile_id_hex32",
        "recipient_profile", "schema",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise Invalid("ledger-schema")
    supplied_mac = _strict_hex(value["hmac_sha256"], 32)
    body = {key: item for key, item in value.items() if key != "hmac_sha256"}
    ledger_key = derive(seed, binding, b"LEDGER\0\0", 0)
    expected_mac = hmac.digest(
        ledger_key, LEDGER_EXPORT_TAG + _canonical(body), "sha256")
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise Invalid("ledger-authentication")

    if (value["schema"] != LEDGER_SCHEMA
            or value["recipient_profile"] != RECIPIENT_PROFILE):
        raise Invalid("ledger-schema")
    actual_binding = LedgerBinding(
        _strict_hex(value["domain_hex32"], 32),
        _strict_hex(value["profile_id_hex32"], 32),
        _strict_hex(value["owner_id_hex32"], 32),
        _strict_hex(value["attempt_id_hex32"], 32))
    if actual_binding != binding:
        raise Invalid("ledger-binding")
    if (type(value["event_count"]) is not int
            or type(value["events"]) is not list
            or value["event_count"] != len(value["events"])):
        raise Invalid("ledger-events")

    expected_invoice_wallet = IssuanceWallet(seed, binding, crypto)
    event_keys = {
        "event_sha256", "index", "invoice_hex208", "previous_sha256",
        "sequence", "state",
    }
    entries: dict[int, _RecoveredEntry] = {}
    delivery_public_keys: set[bytes] = set()
    head = ZERO
    for sequence, event in enumerate(value["events"]):
        if type(event) is not dict or set(event) != event_keys:
            raise Invalid("ledger-events")
        if (type(event["sequence"]) is not int
                or event["sequence"] != sequence
                or type(event["index"]) is not int):
            raise Invalid("ledger-sequence")
        index = uint(event["index"], 64)
        previous = _strict_hex(event["previous_sha256"], 32)
        supplied_event_digest = _strict_hex(event["event_sha256"], 32)
        invoice_raw = _strict_hex(event["invoice_hex208"], 208)
        state = event["state"]
        states = (
            "ALLOCATED", "EXPORTED", "ACCEPTED", "CONSUMED", "POISONED")
        if type(state) is not str or state not in states:
            raise Invalid("ledger-transition")
        if previous != head:
            raise Invalid("ledger-chain")
        event_body = {key: item for key, item in event.items()
                      if key != "event_sha256"}
        digest = h(LEDGER_EVENT_TAG, _canonical(event_body))
        if not hmac.compare_digest(supplied_event_digest, digest):
            raise Invalid("ledger-chain")
        invoice = Invoice.parse(invoice_raw)
        if invoice.index != index:
            raise Invalid("ledger-invoice")
        if state == "ALLOCATED":
            if index in entries:
                raise Invalid("ledger-duplicate-index")
            keys = expected_invoice_wallet._derive_keys(index)
            if invoice != keys.invoice:
                raise Invalid("ledger-invoice")
            if invoice.delivery_pk in delivery_public_keys:
                raise Invalid("delivery-key-reuse")
            delivery_public_keys.add(invoice.delivery_pk)
            entries[index] = _RecoveredEntry(keys, state)
        else:
            entry = entries.get(index)
            allowed_previous = {
                "EXPORTED": ("ALLOCATED",),
                "ACCEPTED": ("EXPORTED",),
                "CONSUMED": ("ACCEPTED",),
                "POISONED": (
                    "ALLOCATED", "EXPORTED", "ACCEPTED", "CONSUMED"),
            }[state]
            if entry is None or entry.state not in allowed_previous:
                raise Invalid("ledger-transition")
            if invoice != entry.keys.invoice:
                raise Invalid("ledger-invoice")
            entries[index] = _RecoveredEntry(entry.keys, state)
        head = digest
    if _strict_hex(value["head_sha256"], 32) != head:
        raise Invalid("ledger-head")
    return RestoredPrivateLedger(binding, crypto, entries, head)


@dataclass(frozen=True)
class Delivery:
    position: int
    cm: bytes
    ciphertext: bytes


def deliver(crypto: Crypto, authority: AcceptedInvoiceCapability,
            value_sompi: int,
            rho: bytes, position: int, *, attempt_id: bytes) -> Delivery:
    if type(authority) is not AcceptedInvoiceCapability:
        raise Invalid("honest-invoice-capability")
    if crypto is not authority._wallet.crypto:
        raise Invalid("crypto-adapter-binding")
    uint(position, 32)
    invoice = authority.invoice()
    receipt = Receipt.for_invoice(invoice, value_sompi, rho)
    receipt.encode()
    invoice = authority._wallet._consume(authority, attempt_id)
    try:
        ciphertext = crypto.seal(invoice.delivery_pk, receipt.encode())
        if len(ciphertext) != 264:
            raise Invalid("sealed-size")
    except Exception:
        authority._wallet._poison_after_consume(authority)
        raise
    return Delivery(position, receipt.commitment(), ciphertext)


@dataclass(frozen=True)
class OwnedClaim:
    position: int
    receipt: Receipt
    ledger_state: str

    @property
    def phase1_route_completed(self) -> bool:
        """True only for this reference lifecycle; never production authority."""
        return self.ledger_state == "CONSUMED"


@dataclass
class Recovery:
    owned: list[OwnedClaim] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)

    @property
    def recovered_liability_sompi(self) -> int:
        return sum(claim.receipt.value_sompi for claim in self.owned)

    @property
    def phase1_consumed_sompi(self) -> int:
        return sum(claim.receipt.value_sompi for claim in self.owned
                   if claim.phase1_route_completed)


def recover(seed: bytes, binding: LedgerBinding, crypto: Crypto,
            private_ledger: bytes | None,
            deliveries: list[Delivery]) -> Recovery:
    """Recover from seed + authenticated private ledger + complete public rows.

    The rows remain a reference input, not proof of accepted KAS state.
    """
    if type(private_ledger) is not bytes or not private_ledger:
        raise Invalid("private-ledger-required")
    ledger = restore_private_ledger(seed, binding, crypto, private_ledger)
    if type(deliveries) is not list:
        raise Invalid("public-history")
    result = Recovery()
    used_indices: set[int] = set()
    required_consumed = {
        index for index, entry in ledger._entries.items()
        if entry.state == "CONSUMED"
    }
    for expected_position, delivery in enumerate(deliveries):
        if (type(delivery) is not Delivery
                or type(delivery.position) is not int
                or not 0 <= delivery.position < 1 << 32
                or delivery.position != expected_position
                or type(delivery.ciphertext) is not bytes
                or len(delivery.ciphertext) != 264):
            raise Invalid("public-history")
        fixed(delivery.cm)
        successful_trials: list[
            tuple[int, Receipt | None, _RecoveredEntry, str | None]] = []
        for index in sorted(ledger._entries):
            entry = ledger._entries[index]
            try:
                plaintext = crypto.unseal(
                    entry.keys.delivery_secret, delivery.ciphertext)
            except Invalid as error:
                if str(error) == "crypto-unseal":
                    continue
                raise
            try:
                receipt = Receipt.parse(plaintext)
                if receipt.domain != binding.domain:
                    raise Invalid("receipt-domain")
                if (receipt.index != index
                        or receipt.invoice(entry.keys.invoice.delivery_pk)
                        != entry.keys.invoice):
                    raise Invalid("receipt-descriptor")
                if receipt.commitment() != delivery.cm:
                    raise Invalid("receipt-cm")
            except Invalid as error:
                successful_trials.append((index, None, entry, str(error)))
                continue
            successful_trials.append((index, receipt, entry, None))
        if len(successful_trials) > 1:
            raise Invalid("ambiguous-decrypt")
        if not successful_trials:
            result.rejected.append({
                "position": delivery.position, "reason": "not-owned"})
            continue
        index, receipt, entry, error = successful_trials[0]
        if error is not None:
            raise Invalid(error)
        assert receipt is not None
        if index in used_indices:
            raise Invalid("invoice-reuse-in-history")
        used_indices.add(index)
        result.owned.append(OwnedClaim(
            delivery.position, receipt, entry.state))
    if not required_consumed.issubset(used_indices):
        raise Invalid("missing-consumed-delivery")
    return result


__all__ = (
    "AcceptedInvoiceCapability", "Crypto", "Delivery",
    "ExportedInvoiceCapability", "Invalid", "Invoice",
    "InvoiceAllocationCapability", "IssuanceWallet", "LedgerBinding",
    "MAX_SOMPI", "MIN_NOTE_SOMPI",
    "OwnedClaim", "Receipt", "RECIPIENT_PROFILE", "Recovery",
    "RestoredPrivateLedger", "SELECTED_CRYPTO_SHA256", "ZERO", "deliver",
    "derive", "recover", "restore_private_ledger",
)
