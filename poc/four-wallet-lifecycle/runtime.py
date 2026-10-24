"""Selected new financial runtime with actual contexts and inline W emission.

The immutable W tail is independently selected public data. Owner exits need
no outer prover/compression assets or emitter process. Generic official native
validation, SDK roundtrip and current private public-proof verification remain
required software; compatible host/system libraries are trusted premises.
"""
import copy
import hashlib
from pathlib import Path
import subprocess
import tempfile

from compat import core, public
from contracts import financial
from paths import checked


class Runtime:
    def __init__(self, profile, runtime_root):
        # Reparse owned bytes instead of accepting a caller-created object with
        # arbitrary derived attributes. External SHA remains caller authority.
        self.profile = financial(profile.raw_bytes, profile.profile_sha256)
        self.runtime_root = checked(runtime_root)
        c = core(); n = c.native_runtime; p = c.primitives
        self.paths = {role: self.runtime_root / role for role in
                      ('prover', 'native-validator', 'node', 'crypto')}
        for role, path in self.paths.items():
            selected = self.profile.executables[role]
            p.need(path.stat().st_size == selected['bytes'], 'selected-runtime-length')
        p.need(self.profile.executables['native-validator']['sha256'] == n.NATIVE_SHA
               and self.profile.executables['node']['sha256'] == n.NODE_SHA
               and self.profile.executables['crypto']['sha256'] == c.receiver.CRYPTO_SHA,
               'selected-generic-runtime-byte-identities')
        self.native = n.Executable(self.paths['native-validator'], n.NATIVE_SHA)
        self.node = n.Executable(self.paths['node'], n.NODE_SHA)
        self.verifier = n.Executable(self.paths['prover'], self.profile.prover_sha256)
        self.crypto = c.receiver.Crypto(self.paths['crypto'])
        p.need(hashlib.sha256(checked(n.SDK).read_bytes()).hexdigest() == n.SDK_SHA,
               'selected-offline-SDK-source')

    def emit(self, state, compact_vk=None, wide_vk=None):
        p = core().primitives
        public().policy.state(state, self.profile.domain)
        if compact_vk is not None:
            p.need(compact_vk == self.profile.vk, 'selected-compact-VK')
        if wide_vk is not None:
            p.need(wide_vk == self.profile.vk, 'wide-proving-not-selected')
        # Exact established W prefix construction. selection.load checked tail
        # hash/domain/template/image/kind; State112 checks its own count bounds.
        redeem = b'\x4c\x70' + state + self.profile.w_tail
        p.need(114 < len(redeem) < 65536, 'PUSHDATA2-W-frame-width')
        return redeem

    def normalize(self, *args, **kwargs):
        return core().native_runtime.Runtime.normalize(self, *args, **kwargs)

    def validate(self, *args, **kwargs):
        return core().native_runtime.Runtime.validate(self, *args, **kwargs)

    def sdk(self, body, contexts):
        # Funding signing is a separate owner-local GN2 operation. This reused
        # SDK API is roundtrip only and never receives an ordinary secret.
        return core().native_runtime.Runtime.sdk(self, body, contexts)

    def normalize_case(self, case, output):
        pub = public()
        body, _ = pub.wire.validate_case(case)
        contexts = [{'amount_sompi': str(row['amount']),
            'script_public_key': row['scriptPublicKey'], 'block_daa_score': str(row['blockDaaScore']),
            'is_coinbase': row['isCoinbase'], 'covenant_id': row['covenantId']}
            for row in case['entries']]
        normalized, metrics = self.normalize(body, contexts, output)
        return {'transaction': normalized, 'entries': copy.deepcopy(case['entries'])}, contexts, metrics

    def replay_cases(self, initial_snapshot_record, point, reserve, cases, output):
        # Static selected implementation, never a callback named by history.
        # The owner/chain integration uses this existing runtime namespace.
        from replay import replay_cases
        return replay_cases(initial_snapshot_record, point, reserve, cases, self, output)

    def body(self, candidate, previous, reserve, compact_vk, wide_vk,
             proof=bytes(128), daa=None):
        core().primitives.uint(daa, 64)
        body, contexts = core().native_runtime.Runtime.body(self, candidate, previous,
            reserve, compact_vk, wide_vk, proof, daa)
        body['inputs'][0]['computeBudget'] = self.profile.private_budget
        return body, contexts

    def finalize(self, candidate, previous, reserve, compact_vk, wide_vk,
                 proof, quoted, output, *, daa):
        core().primitives.uint(daa, 64)
        return core().native_runtime.Runtime.finalize(self, candidate, previous, reserve,
            compact_vk, wide_vk, proof, quoted, output, daa=daa)

    def verify(self, role, auth, proof):
        p = core().primitives
        p.need(role == 'compact2' and type(auth) is bytes and len(auth) == 528
               and type(proof) is bytes and len(proof) == 128,
               'selected-private-public-proof-shape')
        with tempfile.TemporaryDirectory(prefix='kpx6-public-verify-') as temporary:
            auth_path, proof_path = Path(temporary) / 'auth.bin', Path(temporary) / 'proof.bin'
            auth_path.write_bytes(auth); proof_path.write_bytes(proof)
            result = subprocess.run([str(self.verifier.path), 'verify', role,
                str(auth_path), str(proof_path)], capture_output=True, text=True,
                stdin=subprocess.DEVNULL, env=dict(core().native_runtime.CLEAN))
        p.need(not result.stderr, 'public-verifier-output')
        event = p.parse(result.stdout)
        if result.returncode == 1 and event in ({'event': 'error', 'code': 'public_auth_invalid'},
                                               {'event': 'error', 'code': 'public_proof_invalid'}):
            return {'verified': False}
        p.need(result.returncode == 0 and event == {'event': 'proof-verified', 'role': role,
            'authorization_sha256': p.h(auth).hex(), 'proof_sha256': p.h(proof).hex(),
            'vk_sha256': p.h(self.profile.vk).hex()}, 'selected-public-verifier-identity')
        return {'verified': True}

    def quote_material(self, material, output, rate, *, daa):
        """Fresh exact candidate quote with actual accepted-entry DAA context."""
        c = core(); p = c.primitives
        p.need(type(rate) is int and 0 < rate < 1 << 64, 'canonical-fee-rate')
        p.uint(daa, 64)
        output = checked(output); output.mkdir(parents=True, mode=0o700)
        fee, seen, attempt = 1, set(), 0
        while True:
            p.need(fee not in seen, 'exact-fee-quote-cycle-incomplete')
            seen.add(fee)
            candidate = material.candidate(fee)
            directory = output / ('PRIVATE-attempt-' + str(attempt))
            directory.mkdir(mode=0o700)
            body, contexts = self.body(candidate, material.previous, material.reserve,
                                       self.profile.vk, self.profile.vk, daa=daa)
            body, metrics = self.normalize(body, contexts, directory / 'normalized')
            self.sdk(body, contexts)
            _, checked_metrics = self.validate(body, contexts, directory / 'zero-proof',
                                               expect_zero_proof=True)
            p.need(metrics == checked_metrics and metrics['actual_fee_sompi'] == fee,
                   'actual-fee-quote-conformance')
            required = p.amount(rate * metrics['mining_mass'])
            if required == fee:
                return candidate, {'transaction': body, 'contexts': contexts, 'rate': rate,
                    'quote_id': c.native_runtime.quote_id(body, contexts, rate), 'metrics': metrics,
                    'witness_context': 'ACTUAL_PRIVATE_BODY_QUOTE',
                    'authorization_sha256': p.h(candidate.auth).hex(),
                    'actual_candidate_only': True, 'zero_proof_expected_final_G16_failure': True}
            fee, attempt = required, attempt + 1
