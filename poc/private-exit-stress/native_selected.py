"""New-domain native policy adapter; installation selection is external authority.

Only supplied contexts are checked. This adapter does not contact a node,
select a canonical chain, or turn the local selection JSON into trust by itself.
"""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'poc/compact-batch-lifecycle'))
from native_runtime import (Runtime, Executable, NATIVE, NATIVE_SHA, NODE, NODE_SHA,
                            SDK, SDK_SHA)
from receiver import no_symlinks
from primitives import fixed, h, need

INSTANCE = ROOT/'research/next-session/independent-payments/exits/PUBLIC-INSTANCE.json'
SELECTED = Path('/home/luke/projects/kpi-intensive-2026-10-22/capacity-exit-selected-native-01/emitter')
SELECTION = ROOT/'research/next-session/independent-payments/exits/NATIVE-SELECTION.json'


class CapacityRuntime(Runtime):
    def __init__(self):
        selection = json.loads(no_symlinks(SELECTION).read_bytes())
        self.domain = bytes.fromhex(json.loads(no_symlinks(INSTANCE).read_bytes())['domain_hex32'])
        need(selection['domain_hex32'] == self.domain.hex()
             and selection['classification'] == 'PUBLIC_SYNTHETIC_DO_NOT_FUND'
             and selection['native_runtime_sha256'] == NATIVE_SHA,
             'installed-capacity-selection')
        self.emitter = Executable(SELECTED, selection['emitter_sha256'])
        self.native = Executable(NATIVE, NATIVE_SHA)
        self.node = Executable(NODE, NODE_SHA)
        need(hashlib.sha256(no_symlinks(SDK).read_bytes()).hexdigest() == SDK_SHA,
             'selected-offline-SDK-source')

    def emit(self, state, compact_vk, wide_vk):
        request = {'operation':'emit', 'state_hex112':fixed(state,112).hex(),
                   'compact_vk_hex328':fixed(compact_vk,328).hex(),
                   'wide_vk_hex328':fixed(wide_vk,328).hex()}
        result = json.loads(self.emitter.run(request=request).stdout)
        redeem = bytes.fromhex(result['redeem_hex'])
        need(result['domain_hex32'] == self.domain.hex()
             and result['state_hex112'] == state.hex()
             and result['redeem_bytes'] == len(redeem)
             and h(redeem).hex() == result['redeem_sha256']
             and redeem[:2] == b'\x4c\x70' and redeem[2:114] == state,
             'exact-selected-capacity-program')
        return redeem

    def genesis(self, *args, **kwargs):
        raise ValueError('capacity-boundary-experiment-is-not-genesis-or-chain-authority')
