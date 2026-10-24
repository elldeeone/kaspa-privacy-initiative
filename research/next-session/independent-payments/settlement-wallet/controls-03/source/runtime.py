"""Ordinary pinned public processes and actual W templates; no owner secrets.

Use AD0054 normal readonly executables, never special executable FDs. The
trusted host/installation and system OS remain explicit premises.
"""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from reuse import core, public
import selected as s


def load_profile(raw):
    c = core(); p = c.primitives
    p.need(p.h(raw).hex() == s.PROFILE_SHA, 'installed-new-W-child-profile-pin')
    data = p.parse(raw)
    p.need(type(data) is dict and data['selected'] is True
           and data['schema'] == 'kpx5-public-virtual-settlement-child-profile/v1'
           and data['child_domain_hex32'] == s.DOMAIN.hex()
           and data['wrapper_domain_hex32'] == s.WRAPPER_DOMAIN.hex()
           and data['child_role'] == 'compact2' and data['child_count'] == 2
           and data['child_mode'] == 2 and data['payload_bytes'] == 8108
           and data['journal_bytes'] == 424
           and data['child_parameter_manifest_sha256'] == s.MANIFEST_SHA
           and data['child_vk_sha256'] == s.VK_SHA, 'selected-new-W-profile-fields')
    vk = public().wire.hexbytes(data['child_vk_hex328'], 328)
    p.need(p.h(vk).hex() == s.VK_SHA, 'selected-new-capacity-VK')
    tail = public().wire.hexbytes(data['child_template_tail_hex'])
    public().policy.Policy(tail, vk, domain=s.DOMAIN, expected_tail_sha256=p.h(tail).hex(),
                           allow_no_append_exit=True)
    return {'data': data, 'vk': vk, 'tail': tail}


class Runtime:
    def __init__(self, profile):
        c = core(); n = c.native_runtime; p = c.primitives
        self.profile = profile
        self.codec = n.Executable(s.CODEC, s.CODEC_SHA)
        self.native = n.Executable(n.NATIVE, n.NATIVE_SHA)
        self.node = n.Executable(n.NODE, n.NODE_SHA)
        self.verifier = n.Executable(s.PROVER, s.PROVER_SHA)
        p.need(hashlib.sha256(c.receiver.no_symlinks(n.SDK).read_bytes()).hexdigest() == n.SDK_SHA,
               'selected-offline-codec-source')
        self._tail = None

    def normalize(self, *args, **kwargs):
        self.native = core().native_runtime.Executable(core().native_runtime.NATIVE, core().native_runtime.NATIVE_SHA)
        return core().native_runtime.Runtime.normalize(self, *args, **kwargs)

    def validate(self, *args, **kwargs):
        self.native = core().native_runtime.Executable(core().native_runtime.NATIVE, core().native_runtime.NATIVE_SHA)
        return core().native_runtime.Runtime.validate(self, *args, **kwargs)

    def sdk(self, *args, **kwargs):
        self.node = core().native_runtime.Executable(core().native_runtime.NODE, core().native_runtime.NODE_SHA)
        return core().native_runtime.Runtime.sdk(self, *args, **kwargs)

    def body(self, *args, **kwargs):
        body, contexts = core().native_runtime.Runtime.body(self, *args, **kwargs)
        body['inputs'][0]['computeBudget'] = s.DIRECT_BUDGET
        return body, contexts

    def finalize(self, *args, **kwargs):
        return core().native_runtime.Runtime.finalize(self, *args, **kwargs)

    def emit(self, raw_state, compact_vk=None, wide_vk=None):
        p = core().primitives
        public().policy.state(raw_state, s.DOMAIN)
        if compact_vk is not None:
            p.need(compact_vk == self.profile['vk'], 'actual-W-selected-capacity-VK')
        request = {'operation': 'emit', 'state_hex112': raw_state.hex(),
                   'outer_image_hex32': s.IMAGE.hex()}
        self.codec = core().native_runtime.Executable(s.CODEC, s.CODEC_SHA)
        value = p.parse(self.codec.run(request=request).stdout)
        redeem = public().wire.hexbytes(value['redeem_hex'])
        p.need(value['template_kind'] == 'ACTUAL_R0_W'
               and value['outer_image_hex32'] == s.IMAGE.hex()
               and value['child_profile_source_sha256'] == s.PROFILE_SHA
               and value['redeem_bytes'] == len(redeem)
               and value['redeem_sha256'] == p.h(redeem).hex()
               and value['state_hex112'] == raw_state.hex()
               and value['script_public_key'] == core().native_runtime.p2sh(redeem)
               and redeem[:2] == b'\x4c\x70' and redeem[2:114] == raw_state
               and value['actual_funding_native_VM_receipt_or_private_inputs'] is False,
               'exact-installed-actual-W-template')
        if self._tail is None:
            self._tail = redeem[114:]
        p.need(redeem[114:] == self._tail, 'immutable-W-continuation-tail')
        return redeem

    def normalize_case(self, case, output):
        pub = public()
        body, _ = pub.wire.validate_case(case)
        contexts = []
        for entry in case['entries']:
            contexts.append({'amount_sompi': str(entry['amount']),
                'script_public_key': entry['scriptPublicKey'], 'block_daa_score': str(entry['blockDaaScore']),
                'is_coinbase': entry['isCoinbase'], 'covenant_id': entry['covenantId']})
        actual, metrics = self.normalize(body, contexts, output)
        return {'transaction': actual, 'entries': copy.deepcopy(case['entries'])}, contexts, metrics

    def verify(self, role, auth, proof):
        p = core().primitives
        p.need(role == 'compact2' and len(auth) == 528 and len(proof) == 128,
               'selected-public-capacity-proof-width-role')
        with tempfile.TemporaryDirectory(prefix='public-W-proof-') as temporary:
            auth_path, proof_path = Path(temporary) / 'auth.bin', Path(temporary) / 'proof.bin'
            auth_path.write_bytes(auth); proof_path.write_bytes(proof)
            self.verifier = core().native_runtime.Executable(s.PROVER, s.PROVER_SHA)
            result = subprocess.run([str(self.verifier.path), 'verify', role, str(auth_path), str(proof_path)],
                capture_output=True, text=True, stdin=subprocess.DEVNULL, env=dict(core().native_runtime.CLEAN))
        p.need(not result.stderr, 'selected-public-verifier-output')
        event = p.parse(result.stdout)
        if result.returncode == 1 and event in ({'event': 'error', 'code': 'public_auth_invalid'},
                                              {'event': 'error', 'code': 'public_proof_invalid'}):
            return {'verified': False}
        expected = {'event': 'proof-verified', 'role': role, 'authorization_sha256': p.h(auth).hex(),
                    'proof_sha256': p.h(proof).hex(), 'vk_sha256': s.VK_SHA}
        p.need(result.returncode == 0 and event == expected, 'selected-capacity-verifier-identity')
        return {'verified': True}

    def quote_material(self, material, output, rate=100):
        """No witness leaves the owner until ONE stable exact actual quote."""
        c = core(); p = c.primitives
        p.need(type(rate) is int and 0 < rate < 1 << 64, 'canonical-fee-rate')
        output = Path(output)
        output.mkdir(parents=True, mode=0o700)
        fee, seen, attempt = 1, set(), 0
        while True:
            p.need(fee not in seen, 'exact-fee-quote-cycle-incomplete')
            seen.add(fee)
            candidate = material.candidate(fee)
            directory = output / ('PRIVATE-attempt-' + str(attempt));directory.mkdir(mode=0o700)
            body, contexts = self.body(candidate, material.previous, material.reserve,
                                       self.profile['vk'], self.profile['vk'])
            body, metrics = self.normalize(body, contexts, directory / 'normalized')
            self.sdk(body, contexts)
            _, checked = self.validate(body, contexts, directory / 'zero-proof', expect_zero_proof=True)
            p.need(metrics == checked and metrics['actual_fee_sompi'] == fee, 'actual-fee-quote-conformance')
            required = rate * metrics['mining_mass']
            p.amount(required)
            if fee == required:
                quoted = {'transaction': body, 'contexts': contexts, 'rate': rate,
                    'quote_id': c.native_runtime.quote_id(body, contexts, rate), 'metrics': metrics,
                    'actual_candidate_only': True, 'zero_proof_expected_final_G16_failure': True}
                return candidate, quoted
            fee, attempt = required, attempt + 1
