"""Own witness pipe: selected whole PK/VK READY, exact quote, then one witness."""
import hashlib
import os
from pathlib import Path
import stat
import subprocess

from compat import core
from paths import checked


def parameter_manifest(raw, profile):
    p = core().primitives
    p.need(p.h(raw).hex() == profile.parameter_manifest_sha256, 'selected-parameter-manifest-bytes')
    value = p.parse(raw)
    p.need(type(value) is dict and value['schema'] == 'kpx4-public-proving-parameters/v1'
           and value['role'] == 'compact2' and type(value['output_arity']) is int
           and value['output_arity'] == 2 and value['domain_hex32'] == profile.domain.hex()
           and value['vk_sha256'] == p.h(profile.vk).hex()
           and value['pk_sha256'] == profile.pk_sha256 and value['pk_bytes'] == profile.pk_bytes
           and value['compiled_build_identity_sha256'] == profile.build_identity_sha256,
           'selected-compact-parameter-identity')
    return value


def ready_expected(profile):
    return {'event': 'parameters-ready', 'role': 'compact2', 'output_arity': 2,
        'domain_hex32': profile.domain.hex(),
        'parameter_manifest_sha256': profile.parameter_manifest_sha256,
        'vk_sha256': core().primitives.h(profile.vk).hex(),
        'compiled_build_identity_sha256': profile.build_identity_sha256}


def validate_quote(candidate, quoted, runtime):
    c = core(); p = c.primitives
    p.need(type(quoted) is dict and quoted.get('witness_context') in
           ('ACTUAL_PRIVATE_BODY_QUOTE', 'EXACT_VIRTUAL_OWNER_ALLOCATION'),
           'selected-exact-quote-context')
    c.history.hexbytes(quoted['quote_id'], 32)
    p.need(quoted['authorization_sha256'] == p.h(candidate.auth).hex()
           and quoted['transaction']['payload'] == candidate.payload().hex()
           and c.native_runtime.quote_id(quoted['transaction'], quoted['contexts'], quoted['rate'])
               == quoted['quote_id'], 'exact-candidate-quote-binding-before-witness')
    if quoted['witness_context'] == 'ACTUAL_PRIVATE_BODY_QUOTE':
        p.need(quoted.get('actual_candidate_only') is True and candidate.mode == 0
               and candidate.payout > 0, 'actual-private-candidate-quote-required')
        daa_text = quoted['contexts'][0]['block_daa_score']
        p.need(type(daa_text) is str and daa_text and all('0' <= ch <= '9' for ch in daa_text)
               and str(int(daa_text)) == daa_text, 'canonical-actual-quote-DAA')
        daa = p.uint(int(daa_text), 64)
        expected_body, expected_contexts = runtime.body(candidate,
            {'transactionId': candidate.auth[40:72].hex(),
             'index': int.from_bytes(candidate.auth[72:76], 'little')},
            int.from_bytes(candidate.auth[188:196], 'little'), runtime.profile.vk,
            runtime.profile.vk, daa=daa)
    else:
        p.need(candidate.mode == 2 and candidate.payout == 0, 'scheduled-P0-quote-required')
        from preparation import public_body
        case = public_body(candidate, runtime)
        expected_body = case['transaction']
        expected_contexts = [{'amount_sompi': str(row['amount']),
            'script_public_key': row['scriptPublicKey'], 'block_daa_score': str(row['blockDaaScore']),
            'is_coinbase': row['isCoinbase'], 'covenant_id': row['covenantId']} for row in case['entries']]
    # ID and storage mass are independently normalized before this call. All
    # other bytes and populated context fields must match the exact candidate.
    expected_body['id'] = quoted['transaction']['id']
    expected_body['mass'] = quoted['transaction']['mass']
    p.need(expected_body == quoted['transaction'] and expected_contexts == quoted['contexts'],
           'exact-candidate-body-budget-context-and-output-before-witness')


class Worker:
    def __init__(self, runtime, pk, output, workers):
        c = core(); p = c.primitives
        p.need(type(workers) is int and 1 <= workers <= 14, 'selected-worker-count')
        self.runtime, self.profile = runtime, runtime.profile
        self.output = checked(output)
        pk = checked(pk)
        info = pk.stat()
        p.need(stat.S_ISREG(info.st_mode) and info.st_size == self.profile.pk_bytes
               and not os.access(pk, os.W_OK), 'selected-readonly-public-PK-metadata')
        self.reader, self.writer = os.pipe()
        self.process = None
        try:
            self.process = subprocess.Popen([str(runtime.verifier.path), 'prove', 'compact2',
                str(pk), str(self.reader), str(self.output)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, pass_fds=(self.reader,),
                env=dict(c.native_runtime.CLEAN, RAYON_NUM_THREADS=str(workers)))
        except BaseException:
            os.close(self.reader); os.close(self.writer)
            self.reader = self.writer = None
            raise
        os.close(self.reader); self.reader = None
        self._ready = False

    def ready(self):
        p = core().primitives
        first = self.process.stdout.readline()
        p.need(first and p.parse(first) == ready_expected(self.profile),
               'whole-PK-VK-READY-required-before-original-backup')
        self._ready = True
        return p.parse(first)

    def prove(self, candidate, *, quoted):
        p = core().primitives
        # This flag supplements caller ordering; it does not turn an arbitrary
        # external quote JSON into authority. The selected owner operation
        # constructs/revalidates that exact quote before invoking this method.
        p.need(self._ready, 'READY-required-before-witness')
        validate_quote(candidate, quoted, self.runtime)
        with os.fdopen(self.writer, 'wb') as pipe:
            self.writer = None
            pipe.write(core().native_runtime.encoded(candidate.private_witness()) + b'\n')
        stdout, stderr = self.process.communicate()
        p.need(self.process.returncode == 0 and not stderr, 'selected-own-private-proof-failed')
        done = p.parse(stdout.strip())
        p.need(type(done) is dict and set(done) == {'event', 'role',
               'genuine_Groth16_verified', 'proof_sha256', 'authorization_sha256', 'vk_sha256'}
               and done.get('event') == 'proof-complete'
               and done.get('role') == 'compact2' and done.get('genuine_Groth16_verified') is True,
               'selected-own-proof-completion')
        proof = p.fixed((self.output / 'proof128.bin').read_bytes(), 128)
        vk = (self.output / 'verification-key.bin').read_bytes()
        report = p.parse((self.output / 'report.json').read_bytes())
        p.need((self.output / 'authorization528.bin').read_bytes() == candidate.auth
               and vk == self.profile.vk
               and done['proof_sha256'] == p.h(proof).hex()
               and done['authorization_sha256'] == p.h(candidate.auth).hex()
               and done['vk_sha256'] == p.h(vk).hex()
               and report['genuine_Groth16_verified'] is True
               and report['role'] == 'compact2' and report['output_arity'] == 2
               and report['domain_hex32'] == self.profile.domain.hex()
               and report['parameter_manifest_sha256'] == self.profile.parameter_manifest_sha256
               and report['compiled_build_identity_sha256'] == self.profile.build_identity_sha256
               and report['pk_sha256'] == self.profile.pk_sha256
               and report['pk_bytes'] == self.profile.pk_bytes
               and report['vk_sha256'] == p.h(vk).hex()
               and report['authorization_sha256'] == p.h(candidate.auth).hex()
               and report['proof_sha256'] == p.h(proof).hex(),
               'exact-own-proof-Auth-VK-parameters-and-build')
        return proof

    def close(self):
        for name in ('reader', 'writer'):
            descriptor = getattr(self, name)
            if descriptor is not None:
                os.close(descriptor); setattr(self, name, None)
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate(); self.process.communicate()
            for stream in (self.process.stdout, self.process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
