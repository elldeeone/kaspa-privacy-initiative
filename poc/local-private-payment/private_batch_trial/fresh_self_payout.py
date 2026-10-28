"""ADR-0080: stateless Original-only private keys for fresh self payouts.

Only call inside the owner role. All varying derivation inputs already exist
in the public Exit projection; no journal, new nonce field or invoice key is
used. This changes wallet policy, not the AuthExit relation or public ABI.
"""
from dataclasses import dataclass
import hmac

import exit_wire
import wallet_profile as wallet

PURPOSE = b'EXITPAY1'
TAG = b'KPB_FRESH_SELF_PAYOUT_V1\0'
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclass(frozen=True, repr=False)
class OwnedPayout:
    """Private owner-only key object; never a controller/public receipt."""
    secret: bytes
    public_key: bytes

    @property
    def script_public_key(self):
        return b'\0\0\x20' + self.public_key + b'\xac'


@dataclass(frozen=True, repr=False)
class RecoveredPayout:
    kind: str
    owned_key: OwnedPayout | None


def candidate(root, identity, retry):
    return hmac.digest(root, TAG + identity + retry.to_bytes(4, 'little'), 'sha256')


def derive(receiver, head, nf, action):
    """Derive the first canonical secp scalar from one exact public Exit ID.

    root = existing KDF(Original, profile, purpose EXITPAY1, index0, retry0)
    identity = exact Context276 || NF32 || existing public action/nonce32
    scalar = HMAC-SHA256(root, TAG || identity || retry_u32_le)

    Scalars are 32-byte big-endian secp256k1 secrets, with strict rejection of
    zero and values >=n. The existing native implementation derives X-only keys.
    """
    wallet.need(type(head) is exit_wire.HeadContext
        and head.domain == receiver.profile.domain and head.profile == receiver.profile.profile_id,
        'fresh-self-payout-profile-and-head')
    wallet.need(type(nf) is bytes and len(nf) == 32 and nf != bytes(32)
        and type(action) is bytes and len(action) == 32 and action != bytes(32),
        'fresh-self-payout-public-NF-action')
    identity = head.encode() + nf + action
    root = wallet.derive(receiver._seed, receiver.profile, PURPOSE, 0, 0)
    for retry in range(1 << 32):
        secret = candidate(root, identity, retry)
        wallet.need(type(secret) is bytes and len(secret) == 32, 'fresh-self-payout-KDF-width')
        if 0 < int.from_bytes(secret, 'big') < SECP_N:
            public = receiver.crypto.xonly(secret)
            wallet.need(type(public) is bytes and len(public) == 32, 'fresh-self-payout-native-key')
            return OwnedPayout(secret, public)
    raise wallet.Invalid('fresh-self-payout-scalar-exhausted')


def recover_public(receiver, projection, immutable_tail):
    """Recover a matching fresh native key from Original plus public Exit only.

    No invoice, receipt opening, selected sender, note index or journal is
    needed to test ownership of this native payout. Acceptance stays external.
    """
    effect = exit_wire.validate_public(projection)
    exit_wire.require_current_head(projection, effect.context, immutable_tail)
    owned = derive(receiver, effect.context, effect.nf, effect.action)
    return owned if effect.payout_spk == owned.script_public_key else None


def recover_history(receiver, claim, projection, immutable_tail):
    """Recognize owned historical keys without redefining valid Exit history.

    Full proof/acceptance verification belongs to the history provider. This
    classification checks public shape/NF/value and owns no acceptance flag.
    Other destinations can be protocol-authorized; they are not wallet-owned
    recovery keys and are not rejected merely for differing from this policy.
    """
    effect = exit_wire.validate_public(projection)
    exit_wire.require_current_head(projection, effect.context, immutable_tail)
    wallet.need(effect.nf == claim.nf and effect.payout + effect.fee == claim.receipt.value_sompi,
                'historical-owner-NF-value')
    wallet.need(receiver.nullifier(claim.receipt, claim.position) == claim.nf, 'historical-owned-Original-NF')
    fresh = recover_public(receiver, projection, immutable_tail)
    if fresh is not None:
        return RecoveredPayout('fresh-self', fresh)
    keys = receiver.keys(claim.receipt.index)
    legacy_script = b'\0\0\x20' + keys.invoice.native_pk + b'\xac'
    if effect.payout_spk == legacy_script:
        return RecoveredPayout('legacy-invoice-key', OwnedPayout(keys.native_secret, keys.invoice.native_pk))
    return RecoveredPayout('other-destination', None)


def classify_history(receiver, claim, projection, immutable_tail):
    return recover_history(receiver, claim, projection, immutable_tail).kind
