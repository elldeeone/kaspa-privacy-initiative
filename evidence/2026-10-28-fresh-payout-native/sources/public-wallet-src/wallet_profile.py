"""ADR-0074 owner-local receiving/KDF profile; no native acceptance claim.

Mature sealed-box/secp and EdDSA implementations supply actual cryptography.
This module never accepts an old owner_secret or infers a private batch partition.
An authenticated history and actual Output verifier remain caller obligations.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

HERE=Path(__file__).resolve().parent
_spec=importlib.util.spec_from_file_location('_kpb_mature_recipient',HERE.parents[1]/'future-recipient/v2/recipient.py')
legacy=importlib.util.module_from_spec(_spec)
sys.modules[_spec.name]=legacy
_spec.loader.exec_module(legacy)
Invalid=legacy.Invalid
OWNER_TAG=b'KPBPOW01'
KDF_TAG=b'KPBKDF01'
INVOICE_TAG=b'KPBINV01'
RECEIPT_TAG=b'KPBREC01'
EXIT_TAG=b'KPBPEX01'
NODE_SHA256='d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c'
CRYPTO_SHA256='6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'
P=21888242871839275222246405745257275088548364400416034343698204186575808495617


def need(value,category):
    if not value:
        raise Invalid(category)


def fixed(value,size=32):
    return legacy.fixed(value,size)


def digest_file(path):
    result=hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda:source.read(1024*1024),b''):
            result.update(block)
    return result.hexdigest()


@dataclass(frozen=True)
class Profile:
    domain: bytes
    profile_id: bytes

    def __post_init__(self):
        fixed(self.domain);fixed(self.profile_id)
        need(self.domain!=bytes(32) and self.profile_id!=bytes(32),'profile-identity')
        need(self.domain!=bytes.fromhex('b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'),'legacy-profile-refused')


def derive(seed,profile,role,index,retry=None):
    message=KDF_TAG+profile.profile_id+profile.domain+fixed(role,8)+legacy.u64(index)
    if retry is not None:
        message+=legacy.u32(retry)
    return hmac.digest(fixed(seed),message,'sha256')


def authenticate_js(leaf_map,leaf_map_sha256,runtime_root):
    """Recheck the already archive-admitted public runtime closure, not private data."""
    leaf_map=Path(leaf_map);root=Path(runtime_root)
    need(digest_file(leaf_map)==leaf_map_sha256,'js-leaf-map-pin')
    value=json.loads(leaf_map.read_bytes())
    need(value['installedFileMapSha256']=='25737bfa889a940d41db50612f3a99dffd5c673dedd62288224c4bec80b91b02','admitted-js-map')
    need(type(value['files']) is dict and len(value['files'])==3567,'admitted-js-file-count')
    for relative,expected in value['files'].items():
        relative=Path(relative)
        need(not relative.is_absolute() and '..' not in relative.parts and relative.parts[0]=='node_modules','js-public-path')
        path=root/relative
        need(not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode),'js-regular-public-leaf')
        need(digest_file(path)==expected,'js-installed-leaf')
    return root/'node_modules'


class Crypto(legacy.Crypto):
    """The retained immutable mature sealed-box/secp bridge, with exact identity."""
    def __init__(self,executable):
        super().__init__(executable)
        info=self.executable.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o500,'selected-crypto-metadata')
        need(digest_file(self.executable)==CRYPTO_SHA256,'selected-crypto-pin')


class Authority:
    """One owner-only, network-off subprocess; no signing key in a response."""
    def __init__(self,node,modules):
        node=Path(node);modules=Path(modules)
        need(digest_file(node)==NODE_SHA256,'selected-node-pin')
        script=HERE/'owner_authority.mjs'
        argv=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
            '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
            '--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp',
            '--ro-bind',str(node),'/public/node','--ro-bind',str(modules),'/runtime/node_modules',
            '--ro-bind',str(script),'/owner_authority.mjs','--setenv','PATH','/usr/bin:/bin',
            '--setenv','LANG','C.UTF-8','--setenv','TZ','UTC',
            '/public/node','/owner_authority.mjs','/runtime/node_modules/circomlibjs/main.js']
        cpu=min(os.sched_getaffinity(0))
        self.process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            text=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC'},
            preexec_fn=lambda:os.sched_setaffinity(0,{cpu}))

    def request(self,value):
        need(self.process.poll() is None,'owner-authority-unavailable')
        self.process.stdin.write(json.dumps(value,separators=(',',':'))+'\n');self.process.stdin.flush()
        try:
            response=json.loads(self.process.stdout.readline())
        except (ValueError,TypeError):
            raise Invalid('owner-authority-refused') from None
        need(type(response) is dict and set(response)=={'result'},'owner-authority-refused')
        return response['result']

    def public_key(self,seed):
        row=self.request({'operation':'derive-public','seed_hex32':fixed(seed).hex()})
        return fixed(bytes.fromhex(row['owner_key_hex64']),64)

    def sign(self,seed,statement):
        return self.request({'operation':'sign','seed_hex32':fixed(seed).hex(),'statement_hex':statement.hex()})

    def verify(self,statement,authorization):
        return self.request({'operation':'verify','statement_hex':statement.hex(),
            'authorization':{key:authorization[key] for key in ('owner_key_hex64','R8','S')}})['valid']

    def signature_inputs(self,statement,authorization):
        return self.request({'operation':'signature-inputs','statement_hex':statement.hex(),
            'authorization':{key:authorization[key] for key in ('owner_key_hex64','R8','S')}})

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            self.process.wait()
        self.process.stdout.close();self.process.stderr.close()

    def __enter__(self):
        return self

    def __exit__(self,*args):
        self.close()


@dataclass(frozen=True)
class Invoice(legacy.Invoice):
    def encode(self):
        return INVOICE_TAG+super().encode()[8:]

    @classmethod
    def parse(cls,raw):
        fixed(raw,208);need(raw[:8]==INVOICE_TAG,'new-invoice-version')
        item=legacy.Invoice.parse(legacy.INVOICE_MAGIC+raw[8:])
        return cls(**vars(item))


@dataclass(frozen=True)
class Receipt(legacy.Receipt):
    def encode(self):
        return RECEIPT_TAG+super().encode()[8:]

    def invoice(self,delivery_pk):
        return Invoice(self.domain,self.index,self.owner,self.incoming,self.key_commitment,self.native_pk,fixed(delivery_pk))

    @classmethod
    def parse(cls,raw):
        fixed(raw,216);need(raw[:8]==RECEIPT_TAG,'new-receipt-version')
        item=legacy.Receipt.parse(legacy.RECEIPT_MAGIC+raw[8:])
        return cls(**vars(item))


@dataclass(frozen=True,repr=False)
class Keys:
    signing_seed: bytes
    nf_secret: bytes
    native_secret: bytes
    delivery_secret: bytes
    owner_key: bytes
    invoice: Invoice


class Receiver:
    def __init__(self,seed,profile,crypto,authority):
        self._seed=fixed(seed);self.profile=profile;self.domain=profile.domain
        self.crypto=crypto;self.authority=authority

    @lru_cache(maxsize=1024)
    def keys(self,index):
        legacy.uint(index,64)
        signing=derive(self._seed,self.profile,b'AUTHSIGN',index)
        key=self.authority.public_key(signing)
        need(all(int.from_bytes(key[at:at+32],'little')<P for at in (0,32)),'canonical-owner-key')
        nk=derive(self._seed,self.profile,b'NULKEY01',index)
        incoming=derive(self._seed,self.profile,b'INCOMING',index)
        delivery=derive(self._seed,self.profile,b'DELIVERY',0)
        for retry in range(1<<32):
            native=derive(self._seed,self.profile,b'NATIVE01',index,retry)
            try:
                native_pk=self.crypto.xonly(native)
                break
            except Invalid as error:
                if str(error)!='crypto-scalar':
                    raise
        else:
            raise Invalid('native-scalar-exhausted')
        invoice=Invoice(self.domain,index,legacy.h(OWNER_TAG,self.domain,key,incoming),incoming,
            legacy.h(legacy.KEY_TAG,self.domain,nk),native_pk,self.crypto.delivery_public(delivery))
        return Keys(signing,nk,native,delivery,key,invoice)

    def invoice(self,index):
        return self.keys(index).invoice

    def fresh_payout(self,head,nf,action):
        """Owner-only ADR80 key; reproducible from Original and public Exit."""
        import fresh_self_payout
        return fresh_self_payout.derive(self,head,nf,action)

    def open(self,ciphertext):
        key=derive(self._seed,self.profile,b'DELIVERY',0)
        receipt=Receipt.parse(self.crypto.unseal(key,ciphertext))
        need(receipt.domain==self.domain,'receipt-domain')
        expected=self.invoice(receipt.index)
        need(receipt.invoice(expected.delivery_pk)==expected,'receipt-descriptor')
        return receipt

    def nullifier(self,receipt,position):
        need(type(position) is int and 0<=position<1<<legacy.CM_DEPTH,'membership-position')
        expected=self.invoice(receipt.index)
        need(receipt.domain==self.domain and receipt.invoice(expected.delivery_pk)==expected,'receipt-descriptor')
        return hmac.digest(self.keys(receipt.index).nf_secret,
            legacy.NF_TAG+self.domain+receipt.commitment()+legacy.u32(position),'sha256')


@dataclass(frozen=True,repr=False)
class RecoveredOpening:
    position: int
    receipt: Receipt
    nf: bytes
    path: tuple[bytes,...]
    spent: bool
    # A batch-wide own NF does not identify which complete output is change.
    kind: str='unclassified'


def deliver(crypto,invoice,value_sompi,rho,position):
    need(isinstance(invoice,Invoice),'new-invoice-required')
    receipt=Receipt.for_invoice(invoice,value_sompi,fixed(rho))
    ciphertext=crypto.seal(invoice.delivery_pk,receipt.encode())
    need(len(ciphertext)==264,'sealed-size')
    return legacy.Delivery(legacy.uint(position,32),receipt.commitment(),ciphertext)


def recover_openings(receiver,deliveries,expected_cm_root,spent_nfs,*,require_owned_history=True):
    """Reconstruct/decrypt openings, without asserting Output or chain validity.

    The caller must first verify actual Output proofs and authenticate complete
    accepted history. The returned openings are not proof of backed spendability.
    """
    need(type(deliveries) is list and [d.position for d in deliveries]==list(range(len(deliveries))),
        'complete-ordered-deliveries')
    leaves=[fixed(d.cm) for d in deliveries]
    need(len(leaves)==len(set(leaves)) and all(cm!=bytes(32) for cm in leaves),'unique-delivery-commitments')
    tree=legacy.Tree(legacy.CM_DEPTH,leaves,legacy.CM_NODE,legacy.CM_EMPTY)
    need(tree.root==fixed(expected_cm_root),'authenticated-CM-root')
    spent={fixed(nf) for nf in spent_nfs}
    result=[]
    for delivery in deliveries:
        need(type(delivery.ciphertext) is bytes and len(delivery.ciphertext)==264,'complete-delivery-ciphertext')
        try:
            receipt=receiver.open(delivery.ciphertext)
        except Invalid as error:
            if str(error)=='crypto-unseal':
                continue
            raise
        need(receipt.commitment()==delivery.cm,'recovered-CM')
        nf=receiver.nullifier(receipt,delivery.position)
        need(nf!=bytes(32),'recovered-zero-NF')
        result.append(RecoveredOpening(delivery.position,receipt,nf,tuple(tree.path(delivery.position)),nf in spent))
    need(result or not require_owned_history,'seed-not-in-authenticated-history-cohort')
    return result


def exit_statement(profile,anchor,nf,effects_digest,payout_sompi,fee_sompi):
    need(type(fee_sompi) is int and 1<=fee_sompi<=legacy.MAX_SOMPI,'exit-fee-range')
    need(type(payout_sompi) is int and 10_000_000<=payout_sompi<=legacy.MAX_SOMPI,'exit-payout-range')
    need(legacy.MIN_NOTE_SOMPI<=payout_sompi+fee_sompi<=legacy.MAX_SOMPI,'exit-gross-range')
    need(fixed(nf)!=bytes(32),'exit-zero-NF')
    return EXIT_TAG+profile.domain+fixed(anchor)+nf+fixed(effects_digest)+legacy.u64(payout_sompi)+legacy.u64(fee_sompi)


@dataclass(frozen=True,repr=False)
class ExitAuthorization:
    """Owner-local input for the standalone prover; never a supervisor export."""
    statement: bytes
    authorization: dict
    private_request: dict


def authorize_exit(receiver,claim,raw_projection,expected_head,immutable_tail,*,approved_fee_sompi):
    """Approve the actual reconstructed current effects inside one owner worker."""
    import exit_wire
    body=exit_wire.require_current_head(raw_projection,expected_head,immutable_tail)
    need(body.context.domain==receiver.profile.domain and body.context.profile==receiver.profile.profile_id,
        'exit-wallet-profile')
    need(not claim.spent,'exit-owned-claim-spent')
    need(type(approved_fee_sompi) is int and 1<=approved_fee_sompi<=legacy.MAX_SOMPI
        and body.fee==approved_fee_sompi,'exit-exact-owner-approved-fee')
    keys=receiver.keys(claim.receipt.index)
    need(claim.receipt.invoice(keys.invoice.delivery_pk)==keys.invoice,'exit-owned-receipt')
    need(receiver.nullifier(claim.receipt,claim.position)==claim.nf==body.nf,'exit-exact-original-NF')
    need(claim.receipt.value_sompi==body.payout+body.fee,'exit-exact-owned-value')
    need(body.payout_spk!=b'\0\0\x20'+keys.invoice.native_pk+b'\xac','exit-invoice-linked-destination-refused')
    need(body.payout_spk==receiver.fresh_payout(body.context,body.nf,body.action).script_public_key,
        'exit-owner-selected-fresh-self-destination')
    need(len(claim.path)==legacy.CM_DEPTH,'exit-membership-depth')
    root=exit_wire.old.fold(claim.receipt.commitment(),claim.position,b''.join(claim.path),legacy.CM_NODE,legacy.CM_DEPTH)
    need(root==body.context.cm_root,'exit-exact-current-CM-anchor')
    statement=exit_wire.statement(raw_projection)
    authorization=receiver.authority.sign(keys.signing_seed,statement)
    # A real owner worker passes this directly to its private Rust prover stdin.
    # It is not a public command/result, and no signing secret is included.
    request={'role':'new-auth-exit','profile':{'domain_hex32':receiver.profile.domain.hex(),
        'profile_id_hex32':receiver.profile.profile_id.hex()},'statement_hex':statement.hex(),
        'note_hex168':claim.receipt.note_bytes().hex(),'owner_key_hex64':keys.owner_key.hex(),
        'nullifier_key_hex32':keys.nf_secret.hex(),'position':claim.position,
        'path_hex32':[path.hex() for path in claim.path]}
    return ExitAuthorization(statement,authorization,request)
