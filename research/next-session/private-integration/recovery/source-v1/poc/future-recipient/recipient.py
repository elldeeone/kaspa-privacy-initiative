"""Candidate C recipient reference; synthetic accepted-state oracle, no node.

The Python standard library supplies SHA256/HMAC, strict encodings and Merkle
reconstruction. Actual sealed boxes and secp256k1 public keys are delegated to
the narrow Rust bridge. Decryption is neither sender authentication nor proof
of an accepted, backed note. Nothing in this module broadcasts or replays a
ledger. Keys are PUBLIC synthetic fixtures in the tests, never funded wallets.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
import hashlib
import hmac
import json
from pathlib import Path
import struct
import subprocess

OWNER_TAG = b"KPX1OWN\0"
KEY_TAG = b"KPX1KEY\0"
NOTE_TAG = b"KPX1NOT\0"
NF_TAG = b"KPX1NF\0\0"
DERIVE_TAG = b"KPX1DRV\0"
INVOICE_MAGIC = b"KPX1IN01"
RECEIPT_MAGIC = b"KPX1RC01"
CM_NODE = b"KPX1CMN\0"
NF_NODE = b"KPX1NFN\0"
NF_LEAF = b"KPX1NFL\0"
CM_EMPTY = hashlib.sha256(b"KPX1CME\0").digest()
NF_EMPTY = hashlib.sha256(b"KPX1NFE\0").digest()
ZERO = bytes(32)
MAX_SOMPI = 2_870_000_000_000_000_000
MIN_NOTE_SOMPI = 60_000_000
CM_DEPTH = 16
NF_DEPTH = 17
MAX_NOTES = 65_535


class Invalid(ValueError):
    """A deterministic validation category; never includes keys or plaintext."""


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


def derive(seed: bytes, domain: bytes, role: bytes, index: int, retry=None) -> bytes:
    message = DERIVE_TAG + fixed(role, 8) + fixed(domain) + u64(index)
    if retry is not None:
        message += u32(retry)
    return hmac.digest(fixed(seed), message, "sha256")


class Crypto:
    """Supported RustCrypto/libsecp adapter; secrets travel on stdin only."""

    def __init__(self, executable: Path):
        self.executable = Path(executable).resolve(strict=True)

    def call(self, op: str, *, secret=None, public=None, payload=None) -> bytes:
        request = {"op": op}
        for key, value in (("secret_hex", secret), ("public_hex", public),
                           ("payload_hex", payload)):
            if value is not None:
                request[key] = value.hex()
        proc = subprocess.run([str(self.executable)], input=json.dumps(request),
                              text=True, capture_output=True, check=False)
        try:
            result = json.loads(proc.stdout)
        except (ValueError, TypeError):
            raise Invalid("crypto-adapter") from None
        if proc.returncode or "error" in result:
            raise Invalid("crypto-" + str(result.get("error", "adapter")))
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


@dataclass(frozen=True)
class Invoice:
    domain: bytes
    index: int
    owner: bytes
    incoming: bytes
    key_commitment: bytes
    native_pk: bytes

    def encode(self) -> bytes:
        return (INVOICE_MAGIC + fixed(self.domain) + u64(self.index)
                + fixed(self.owner) + fixed(self.incoming)
                + fixed(self.key_commitment) + fixed(self.native_pk))

    @classmethod
    def parse(cls, raw: bytes) -> "Invoice":
        fixed(raw, 176)
        if raw[:8] != INVOICE_MAGIC:
            raise Invalid("invoice-magic")
        return cls(raw[8:40], int.from_bytes(raw[40:48], "little"), raw[48:80],
                   raw[80:112], raw[112:144], raw[144:176])


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
    def for_invoice(cls, invoice: Invoice, value_sompi: int, rho: bytes):
        invoice.encode()  # Validate every boundary before constructing a note.
        return cls(invoice.domain, invoice.index, invoice.owner, invoice.incoming,
                   value_sompi, fixed(rho), invoice.key_commitment, invoice.native_pk)

    def invoice(self) -> Invoice:
        return Invoice(self.domain, self.index, self.owner, self.incoming,
                       self.key_commitment, self.native_pk)

    def note_bytes(self) -> bytes:
        if not MIN_NOTE_SOMPI <= uint(self.value_sompi, 64) <= MAX_SOMPI:
            raise Invalid("note-value")
        return (fixed(self.owner) + fixed(self.incoming) + u64(self.value_sompi)
                + fixed(self.rho) + fixed(self.key_commitment) + fixed(self.native_pk))

    def encode(self) -> bytes:
        return RECEIPT_MAGIC + fixed(self.domain) + u64(self.index) + self.note_bytes()

    def commitment(self) -> bytes:
        return h(NOTE_TAG, fixed(self.domain), self.note_bytes())

    @classmethod
    def parse(cls, raw: bytes) -> "Receipt":
        fixed(raw, 216)
        if raw[:8] != RECEIPT_MAGIC:
            raise Invalid("receipt-magic")
        receipt = cls(raw[8:40], int.from_bytes(raw[40:48], "little"), raw[48:80],
                      raw[80:112], int.from_bytes(raw[112:120], "little"),
                      raw[120:152], raw[152:184], raw[184:216])
        receipt.encode()
        return receipt


@dataclass(frozen=True, repr=False)
class Keys:
    owner_secret: bytes
    nf_secret: bytes
    native_secret: bytes
    delivery_secret: bytes
    invoice: Invoice


class Receiver:
    def __init__(self, seed: bytes, domain: bytes, crypto: Crypto):
        self._seed = fixed(seed)
        self.domain = fixed(domain)
        self.crypto = crypto

    @lru_cache(maxsize=1024)
    def keys(self, index: int) -> Keys:
        uint(index, 64)
        s = derive(self._seed, self.domain, b"OWNSEC\0\0", index)
        k = derive(self._seed, self.domain, b"KSECRET\0", index)
        delivery = derive(self._seed, self.domain, b"DELIVERY", 0)
        incoming = self.crypto.delivery_public(delivery)
        for retry in range(1 << 32):
            native = derive(self._seed, self.domain, b"NATIVE\0\0", index, retry)
            try:
                pk = self.crypto.xonly(native)
                break
            except Invalid as error:
                if str(error) != "crypto-scalar":
                    raise
        else:
            raise Invalid("native-scalar-exhausted")
        invoice = Invoice(self.domain, index, h(OWNER_TAG, self.domain, s, incoming),
                          incoming, h(KEY_TAG, self.domain, k), pk)
        return Keys(s, k, native, delivery, invoice)

    def invoice(self, index: int) -> Invoice:
        return self.keys(index).invoice

    def open(self, ciphertext: bytes) -> Receipt:
        # Decrypt first with a domain-stable delivery key. The invoice index is
        # encrypted, so seed restoration requires no index lookahead guess.
        delivery = derive(self._seed, self.domain, b"DELIVERY", 0)
        receipt = Receipt.parse(self.crypto.unseal(delivery, ciphertext))
        if receipt.domain != self.domain:
            raise Invalid("receipt-domain")
        if receipt.invoice() != self.invoice(receipt.index):
            raise Invalid("receipt-descriptor")
        return receipt

    def nullifier(self, receipt: Receipt, position: int) -> bytes:
        if receipt.invoice() != self.invoice(receipt.index):
            raise Invalid("receipt-descriptor")
        return hmac.digest(self.keys(receipt.index).nf_secret,
                           NF_TAG + self.domain + receipt.commitment() + u32(position),
                           "sha256")


@dataclass(frozen=True)
class Delivery:
    position: int
    cm: bytes
    ciphertext: bytes | None

    def public(self):
        return {"position": uint(self.position, 32), "cm": fixed(self.cm).hex(),
                "ciphertext": None if self.ciphertext is None else self.ciphertext.hex()}


def deliver(crypto: Crypto, invoice: Invoice, value_sompi: int, rho: bytes,
            position: int) -> Delivery:
    """Sender needs public invoice only, never receiver s, k or native secret."""
    receipt = Receipt.for_invoice(invoice, value_sompi, rho)
    ciphertext = crypto.seal(invoice.incoming, receipt.encode())
    if len(ciphertext) != 264:
        raise Invalid("sealed-size")
    return Delivery(uint(position, 32), receipt.commitment(), ciphertext)


class Tree:
    """Sparse Merkle reconstruction; leaves/defaults match the candidate wire."""
    def __init__(self, depth: int, leaves: list[bytes], tag: bytes, empty: bytes):
        if len(leaves) > 1 << depth:
            raise Invalid("tree-capacity")
        self.depth, self.tag = depth, tag
        self.defaults = [empty]
        for _ in range(depth):
            self.defaults.append(h(tag, self.defaults[-1], self.defaults[-1]))
        self.levels = [{i: fixed(value) for i, value in enumerate(leaves)}]
        for level in range(depth):
            previous = self.levels[-1]
            indices = {i // 2 for i in previous}
            self.levels.append({i: h(tag, previous.get(2 * i, self.defaults[level]),
                                     previous.get(2 * i + 1, self.defaults[level]))
                                for i in indices})

    @property
    def root(self):
        return self.levels[-1].get(0, self.defaults[-1])

    def path(self, index: int) -> list[bytes]:
        if not 0 <= uint(index, 32) < 1 << self.depth:
            raise Invalid("tree-index")
        return [self.levels[level].get((index >> level) ^ 1, self.defaults[level])
                for level in range(self.depth)]

    def with_leaf(self, index: int, value: bytes) -> "Tree":
        if not 0 <= uint(index, 32) < 1 << self.depth:
            raise Invalid("tree-index")
        other = object.__new__(Tree)
        other.depth, other.tag = self.depth, self.tag
        other.defaults = self.defaults
        other.levels = [dict(level) for level in self.levels]
        other.levels[0][index] = fixed(value)
        for level in range(self.depth):
            at = index >> (level + 1)
            lower = other.levels[level]
            other.levels[level + 1][at] = h(self.tag,
                lower.get(2 * at, self.defaults[level]),
                lower.get(2 * at + 1, self.defaults[level]))
        return other


def fold_path(leaf: bytes, index: int, path: list[bytes], tag: bytes) -> bytes:
    current = fixed(leaf)
    for level, sibling in enumerate(path):
        a, b = (fixed(sibling), current) if index >> level & 1 else (current, fixed(sibling))
        current = h(tag, a, b)
    return current


@dataclass(frozen=True)
class NFEntry:
    value: bytes
    next_value: bytes
    next_index: int

    def leaf(self):
        return h(NF_LEAF, fixed(self.value), fixed(self.next_value), u32(self.next_index))


def nf_entries(values: list[bytes]) -> list[NFEntry]:
    """Synthetic fixture constructor, not a ledger transition executor."""
    values = [ZERO] + sorted((fixed(v) for v in values), key=lambda v: int.from_bytes(v, "little"))
    if len(set(values)) != len(values):
        raise Invalid("nf-duplicate")
    return [NFEntry(v, values[i + 1] if i + 1 < len(values) else ZERO,
                    i + 1 if i + 1 < len(values) else 0)
            for i, v in enumerate(values)]


@dataclass(frozen=True)
class ExpectedState:
    domain: bytes
    cm_root: bytes
    n: int
    nf_root: bytes
    m: int
    delivery_digest: bytes
    # This is a synthetic accepted-state/data-archive oracle. The script state
    # does not by itself authenticate receipts or prove accepted KAS backing.
    oracle: str = "SYNTHETIC_ACCEPTED_STATE_AND_ARCHIVE_PIN"


@dataclass
class Snapshot:
    deliveries: list[Delivery]
    nullifiers: list[NFEntry]

    def delivery_digest(self):
        return h(b"KPX1ARC\0", json.dumps([d.public() for d in self.deliveries],
                 sort_keys=True, separators=(",", ":")).encode())

    def roots(self):
        return (Tree(CM_DEPTH, [d.cm for d in self.deliveries], CM_NODE, CM_EMPTY),
                Tree(NF_DEPTH, [n.leaf() for n in self.nullifiers], NF_NODE, NF_EMPTY))

    def pin(self, domain: bytes) -> ExpectedState:
        """Fixture-only oracle construction. Never treats arbitrary roots as accepted."""
        cm, nf = self.roots()
        return ExpectedState(fixed(domain), cm.root, len(self.deliveries), nf.root,
                             len(self.nullifiers), self.delivery_digest())

    def verify(self, expected: ExpectedState):
        if expected.oracle != "SYNTHETIC_ACCEPTED_STATE_AND_ARCHIVE_PIN":
            raise Invalid("unsupported-acceptance-oracle")
        if not 0 < uint(expected.n, 32) <= MAX_NOTES:
            raise Invalid("cm-counter")
        if not 1 <= uint(expected.m, 32) <= 2 * expected.n + 1:
            raise Invalid("nf-counter")
        if len(self.deliveries) != expected.n or len(self.nullifiers) != expected.m:
            raise Invalid("snapshot-count")
        if any(d.position != i for i, d in enumerate(self.deliveries)):
            raise Invalid("snapshot-order")
        if any(d.ciphertext is None for d in self.deliveries):
            raise Invalid("receipt-data-unavailable")
        if self.delivery_digest() != fixed(expected.delivery_digest):
            raise Invalid("archive-pin")
        cm, nf = self.roots()
        if cm.root != fixed(expected.cm_root) or nf.root != fixed(expected.nf_root):
            raise Invalid("snapshot-root")
        entries = self.nullifiers
        if entries[0].value != ZERO or len({e.value for e in entries}) != len(entries):
            raise Invalid("nf-sentinel-or-duplicate")
        visited, index = set(), 0
        while True:
            if index in visited or not 0 <= index < len(entries):
                raise Invalid("nf-links")
            visited.add(index)
            entry = entries[index]
            if entry.next_value == ZERO:
                if entry.next_index != 0:
                    raise Invalid("nf-tail")
                break
            if not 0 < entry.next_index < len(entries):
                raise Invalid("nf-links")
            next_entry = entries[entry.next_index]
            if next_entry.value != entry.next_value:
                raise Invalid("nf-links")
            if int.from_bytes(entry.value, "little") >= int.from_bytes(entry.next_value, "little"):
                raise Invalid("nf-order")
            index = entry.next_index
        if len(visited) != len(entries):
            raise Invalid("nf-unreachable")
        return cm, nf


@dataclass
class OwnedClaim:
    position: int
    receipt: Receipt
    nf: bytes
    spent: bool
    duplicate_invoice: bool
    privacy_contaminated: bool = False

    @property
    def normal_credit_sompi(self):
        return self.receipt.value_sompi if not self.spent and not self.duplicate_invoice else 0

    @property
    def owner_action_available(self):
        # Duplicate invoices never revoke previously held owner authority. All
        # correctly derived unspent positions remain available for owner action.
        return not self.spent


@dataclass
class Recovery:
    owned: list[OwnedClaim] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)

    @property
    def normal_credit_sompi(self):
        return sum(c.normal_credit_sompi for c in self.owned)

    @property
    def all_owned_unspent_sompi(self):
        return sum(c.receipt.value_sompi for c in self.owned if not c.spent)


def recover(receiver: Receiver, expected: ExpectedState, snapshot: Snapshot) -> Recovery:
    """Restore using seed + complete pinned public data; no service interface.

    A missing archive causes liveness failure. The caller cannot replace the
    expected accepted state with an arbitrary archive/root and claim backing.
    """
    if receiver.domain != fixed(expected.domain):
        raise Invalid("snapshot-domain")
    snapshot.verify(expected)
    spent = {e.value for e in snapshot.nullifiers}
    result, first, groups = Recovery(), {}, {}
    for delivery in snapshot.deliveries:
        try:
            receipt = receiver.open(delivery.ciphertext)
            if receipt.commitment() != delivery.cm:
                raise Invalid("receipt-cm")
            nf = receiver.nullifier(receipt, delivery.position)
            if nf == ZERO:
                raise Invalid("nf-zero")
        except Invalid as error:
            result.rejected.append({"position": delivery.position, "reason": str(error)})
            continue
        duplicate = receipt.index in first
        first.setdefault(receipt.index, delivery.position)
        claim = OwnedClaim(delivery.position, receipt, nf, nf in spent, duplicate)
        result.owned.append(claim)
        groups.setdefault(receipt.index, []).append(claim)
        if duplicate:
            result.rejected.append({"position": delivery.position, "reason": "unsafe-duplicate-invoice"})
    for group in groups.values():
        if len(group) > 1:
            for claim in group:
                claim.privacy_contaminated = True
    return result


def exit_witness(receiver: Receiver, claim: OwnedClaim, expected: ExpectedState,
                 snapshot: Snapshot) -> dict:
    """Construct current membership/NF witnesses only; no authorization oracle.

    The real native signer and transaction validator must bind exact payout,
    fees, policy and current state. This function creates neither a transaction
    nor a permission, and performs no proof or chain acceptance.
    """
    if receiver.domain != fixed(expected.domain):
        raise Invalid("snapshot-domain")
    if uint(claim.position, 32) >= expected.n:
        raise Invalid("claim-position")
    cm_tree, nf_tree = snapshot.verify(expected)
    receipt = claim.receipt
    if snapshot.deliveries[claim.position].cm != receipt.commitment():
        raise Invalid("claim-position")
    nullifier = receiver.nullifier(receipt, claim.position)
    if nullifier == ZERO:
        raise Invalid("nf-zero")
    if any(e.value == nullifier for e in snapshot.nullifiers):
        raise Invalid("already-spent")
    if expected.m >= 1 << NF_DEPTH or expected.m + 1 > 2 * expected.n + 1:
        raise Invalid("nf-capacity")
    value = int.from_bytes(nullifier, "little")
    predecessor_index, predecessor = max(
        ((i, e) for i, e in enumerate(snapshot.nullifiers)
         if int.from_bytes(e.value, "little") < value),
        key=lambda pair: int.from_bytes(pair[1].value, "little"))
    if predecessor.next_value != ZERO and value >= int.from_bytes(predecessor.next_value, "little"):
        raise Invalid("nf-absence")
    updated_predecessor = NFEntry(predecessor.value, nullifier, expected.m)
    intermediate = nf_tree.with_leaf(predecessor_index, updated_predecessor.leaf())
    appended = NFEntry(nullifier, predecessor.next_value, predecessor.next_index)
    successor = intermediate.with_leaf(expected.m, appended.leaf())
    keys = receiver.keys(receipt.index)
    return {
        "classification": "SYNTHETIC_CURRENT_WITNESS_NO_TRANSACTION_OR_AUTHORIZATION",
        "position": claim.position, "cm": receipt.commitment().hex(),
        "cm_path": [v.hex() for v in cm_tree.path(claim.position)],
        "k": keys.nf_secret.hex(), "nf": nullifier.hex(),
        "predecessor_index": predecessor_index,
        "predecessor": {"value": predecessor.value.hex(), "next_value": predecessor.next_value.hex(),
                        "next_index": predecessor.next_index},
        "predecessor_path": [v.hex() for v in nf_tree.path(predecessor_index)],
        "append_index": expected.m,
        "append_path_after_predecessor_update": [v.hex() for v in intermediate.path(expected.m)],
        "intermediate_nf_root": intermediate.root.hex(),
        "successor_nf_root": successor.root.hex(),
    }
