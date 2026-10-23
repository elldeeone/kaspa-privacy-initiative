"""ADR55 selection and read-only reuse of the closed Auth528 helpers.

Local rehearsal only. Cold owners use the separate owner wallet and receive no
operator profile, context, recipe or prepared witness from this module.
"""
import hashlib
import json
from pathlib import Path
import stat
import sys
from types import ModuleType

ROOT=Path(__file__).resolve().parents[2]
PHASE=ROOT/'research/next-session/private-change'
ADR_SHA='101738564c05c3ca7fdee35cb475e83c4085d9bfa1573549552c7ca2dbd42b41'
CONTRACT_SHA='efa3d2c68a1fb3ec9b3b409c6196aa44304bb4e62eefc426dfa421e702f0c837'
REUSE_SHA='28aa04e172db61a8c75ca10547ab6a95b212d7226101e19f925ae7bd338bd62c'
IDENTITY_SHA='3669f0aab7d6cd4db661d848d26ed2c741523b7e1fbe7955cf9a0192f73bf37d'
GENESIS='f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
LEGACY=ROOT/'poc/private-cashout-trial'
HELPERS={
    'trial.py':'7ae33a9f2adb252f0b1c19ac7583d5e64af2bf76551ec67b16cd267c7cfb8576',
    'prepare.py':'2ffdb475a902c3c9f217b2538267f3334dcbe628108e930a95c803ef955ae52b',
    'action.py':'6ee9b1066dfcccb6657518e9fb34a3f1a570b01045af715b3b02631dfc8e599f',
    'sdk.mjs':'7e09cb2316dd08072fa4d29e221020215f137e68f761937d7cc0751ee1678e63',
}
_OWNED_HELPERS=None


def require(condition, category):
    if not condition:raise ValueError(category)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'duplicate-json-field');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs)


def selected():
    for path,sha in (
        (ROOT/'docs/adr/0055-recoverable-private-change-and-repeated-spending.md',ADR_SHA),
        (PHASE/'CONTRACT.md',CONTRACT_SHA),
        (PHASE/'TRIAL-REUSE-SELECTION.json',REUSE_SHA),
        (PHASE/'PUBLIC-IDENTITY.json',IDENTITY_SHA)):
        require(not path.is_symlink() and digest(path.read_bytes())==sha,'selected-ADR55-public-authority')
    reuse=parse((PHASE/'TRIAL-REUSE-SELECTION.json').read_bytes())
    identity=parse((PHASE/'PUBLIC-IDENTITY.json').read_bytes())
    require(reuse['schema']=='kpx3-private-change-trial-reuse-selection/v1'
        and reuse['adr0055_sha256']==ADR_SHA and reuse['common_contract_sha256']==CONTRACT_SHA
        and reuse['public_identity_sha256']==IDENTITY_SHA
        and reuse['unselected_17file_template_sha256']==
            'b207222c4f7dda52a88e8682fed5af8eec521ac1ac678ab1077128ffee74d3ec'
        and reuse['program_label']=='AUTH528_PRIVATE_CASHOUT/v1'
        and reuse['new_wallet_policy_only_circuit_and_native_relation_unchanged'] is True,
        'explicit-new-authority-old-source-reuse')
    require(identity['trial_id']==reuse['trial_id'] and identity['domain_hex32']==reuse['domain_hex32']
        and identity['network_id']==reuse['network_id']=='testnet-10'
        and identity['genesis_hash_hex']==reuse['genesis_hash_hex']==GENESIS
        and identity['program_label']==reuse['program_label'],'fresh-selected-public-identity')
    for name,sha in HELPERS.items():
        path=LEGACY/name
        require(not path.is_symlink() and digest(path.read_bytes())==sha,'closed-helper-bytes-changed')
    return identity


def helpers():
    global _OWNED_HELPERS
    selected()
    if _OWNED_HELPERS is not None:return _OWNED_HELPERS
    modules=[]
    for name in ('trial','action','prepare'):
        path=LEGACY/(name+'.py');raw=path.read_bytes()
        require(digest(raw)==HELPERS[name+'.py'] and name not in sys.modules,
                'closed-helper-owned-source-namespace')
        module=ModuleType(name);module.__file__=str(path);sys.modules[name]=module
        try:exec(compile(raw,str(path),'exec'),module.__dict__)
        except BaseException:
            sys.modules.pop(name,None)
            raise
        modules.append(module)
    _OWNED_HELPERS=tuple(modules)
    return _OWNED_HELPERS


class LocalContext:
    """Own fresh local identity only; never a cold-owner process input.

    The selected caller supplies the new wallet's authenticated V2 module and
    already-selected crypto adapter, and owns that adapter's lifetime. Keeping
    one module/Invalid class avoids mixing the old/new Python receiver copies.
    Neither object is an external request field.
    """
    def __init__(self,directory,receiver_module,crypto):
        identity=selected();self.t,self.a,self.p=helpers()
        directory=self.t.outside_git(directory)
        public=directory/'public/identity.json';self.t.no_symlinks(public)
        require(digest(public.read_bytes())==IDENTITY_SHA,'new-selected-trial-directory')
        self.directory,self.profile=self.t.load_profile(directory)
        require(all(self.profile.get(key)==value for key,value in identity.items()),
                'new-profile-public-identity-binding')
        self.domain=bytes.fromhex(identity['domain_hex32'])
        self.module,self.crypto=receiver_module,crypto

    def owner(self,name):
        require(name in ('alice','bob','charlie'),'finite-local-role')
        path=self.directory/'backups'/(name+'.json');self.t.no_symlinks(path)
        require(stat.S_IMODE(path.stat().st_mode)==0o600,'own-new-backup-mode')
        data=parse(path.read_bytes())
        require(set(data)=={'schema','network_id','genesis_hash_hex','domain_hex32','seed_hex32'}
            and data['schema']=='kpx2-tn10-seed-backup/v1' and data['network_id']=='testnet-10'
            and data['genesis_hash_hex']==GENESIS and data['domain_hex32']==self.domain.hex(),
            'own-new-original-backup')
        seed=bytes.fromhex(data['seed_hex32'])
        require(len(seed)==32 and seed.hex()==data['seed_hex32'],'canonical-original-seed')
        receiver=self.module.Receiver(seed,self.domain,self.crypto)
        require(receiver.invoice(0).encode().hex()==self.profile['private_invoices_hex208'][name],
                'original-backup-derived-public-invoice')
        return seed,receiver

    def recognize(self,name,snapshot):
        seed,receiver=self.owner(name)
        recovered=self.module.recover(receiver,snapshot.pin(self.domain),snapshot)
        return seed,receiver,recovered

