#!/usr/bin/env python3
"""One original backup, NEW profile, actual-W public replay, private full exit.

No actor/position/expected-value map, other backup, outer prover, hosted service,
dynamic source/key choice, automatic REVEAL or broadcast capability is accepted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from paths import checked, guard, need
from reuse import ROOT, core, source_paths
from runtime import Runtime, load_profile
import no_append
import recovery
import selected as s


def public_paths(args):
    return [args.profile, args.prestate, args.history, args.manifest, s.PROVER, s.CODEC,
        *[Path(__file__).parent / (name + '.py') for name in
          ('owner', 'reuse', 'paths', 'selected', 'no_append', 'runtime', 'recovery')],
        *source_paths(), ROOT / 'poc/future-recipient/v2/recipient.py',
        ROOT / 'poc/private-cashout-trial/sdk.mjs',
        Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto'),
        Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator'),
        Path('/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node'),
        *[Path('/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa') / name
          for name in ('kaspa.js', 'kaspa_bg.wasm', 'package.json')],
        *([args.pk] if args.op == 'prepare-full-cashout' else [])]


class Worker:
    """Private witness pipe remains EMPTY through complete PK auth/READY/quote."""
    def __init__(self, pk, output, workers):
        self.output = output
        core().native_runtime.Executable(s.PROVER, s.PROVER_SHA)
        self.reader, self.writer = os.pipe()
        try:
            self.process = subprocess.Popen([str(s.PROVER), 'prove', 'compact2', str(pk),
                str(self.reader), str(output)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, pass_fds=(self.reader,),
                env=dict(core().native_runtime.CLEAN, RAYON_NUM_THREADS=str(workers)))
        except BaseException:
            os.close(self.reader);os.close(self.writer)
            self.reader = self.writer = None
            raise
        os.close(self.reader);self.reader = None

    def ready(self):
        first = self.process.stdout.readline()
        need(first and core().primitives.parse(first) == s.ready_expected(),
             'whole-new-PK-VK-READY-required-before-backup')
        return core().primitives.parse(first)

    def prove(self, candidate):
        with os.fdopen(self.writer, 'wb') as pipe:
            self.writer = None
            pipe.write(core().native_runtime.encoded(candidate.private_witness()) + b'\n')
        stdout, stderr = self.process.communicate()
        need(self.process.returncode == 0 and not stderr, 'selected-own-private-proof-failed')
        done = core().primitives.parse(stdout.strip())
        need(type(done) is dict and done.get('event') == 'proof-complete'
             and done.get('role') == 'compact2' and done.get('genuine_Groth16_verified') is True,
             'selected-own-proof-completion')
        proof = core().primitives.fixed((self.output / 'proof128.bin').read_bytes(), 128)
        need((self.output / 'authorization528.bin').read_bytes() == candidate.auth
             and hashlib.sha256((self.output / 'verification-key.bin').read_bytes()).hexdigest() == s.VK_SHA
             and done['proof_sha256'] == hashlib.sha256(proof).hexdigest()
             and done['authorization_sha256'] == hashlib.sha256(candidate.auth).hexdigest()
             and done['vk_sha256'] == s.VK_SHA, 'exact-own-proof-and-new-selected-VK')
        return proof

    def close(self):
        for name in ('reader', 'writer'):
            descriptor = getattr(self, name)
            if descriptor is not None:
                os.close(descriptor);setattr(self, name, None)
        if self.process.poll() is None:
            self.process.terminate();self.process.communicate()
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def manifest(raw):
    p = core().primitives
    need(p.h(raw).hex() == s.MANIFEST_SHA, 'installed-new-capacity-manifest-pin')
    value = p.parse(raw)
    need(value['schema'] == 'kpx4-public-proving-parameters/v1'
         and value['program_label'] == 'AUTH528_PRIVATE_CAPACITY_EXIT/v1'
         and value['role'] == 'compact2' and value['output_arity'] == 2
         and value['domain_hex32'] == s.DOMAIN.hex() and value['vk_sha256'] == s.VK_SHA
         and value['pk_sha256'] == s.PK_SHA and value['pk_bytes'] == s.PK_BYTES
         and value['compiled_build_identity_sha256'] == s.BUILD_SHA, 'new-capacity-manifest-identity')
    return value


def run(args):
    need(args.op in ('recover', 'prepare-full-cashout'), 'selected-owner-operation')
    if args.op == 'prepare-full-cashout':
        need(args.pk is not None and args.execute is True, 'root-scheduled-own-proving-release-required')
        need(type(args.workers) is int and 1 <= args.workers <= 14, 'selected-worker-count')
        need(type(args.max_inputs) is int and args.max_inputs in (1, 2), 'one-or-two-own-input-policy')
    backup, output = guard(args.backup, public_paths(args), args.output)
    c = core();p = c.primitives
    for path in args.must_be_absent:
        need(not checked(path).exists(), 'original-source-operator-or-cache-visible')
    profile = load_profile(checked(args.profile).read_bytes())
    selected_manifest = manifest(checked(args.manifest).read_bytes())
    need(p.h(profile['vk']).hex() == selected_manifest['vk_sha256'], 'profile-and-manifest-VK-join')
    if args.op == 'prepare-full-cashout':
        info = checked(args.pk).stat()
        need(stat.S_ISREG(info.st_mode) and info.st_size == s.PK_BYTES
             and not os.access(args.pk, os.W_OK), 'selected-readonly-public-PK-metadata')
    output.mkdir(parents=True, mode=0o700)
    runtime = Runtime(profile)
    replayed = recovery.replay(checked(args.prestate).read_bytes(), checked(args.history).read_bytes(),
                              args.history_sha256, runtime, output / 'public-replay')
    worker = None
    try:
        if args.op == 'prepare-full-cashout':
            worker = Worker(checked(args.pk), output / 'proof', args.workers)
            c.native_runtime.save(output / 'PARAMETERS-READY.json', worker.ready())
        # FIRST own-backup byte read. Preparation requires whole 6c/074c READY;
        # recognition-only deliberately has no PK, witness or spend authority.
        seed = c.receiver.backup(backup, s.DOMAIN)
        wallet = c.receiver.module().Receiver(seed, s.DOMAIN, c.receiver.Crypto())
        recovered = c.receiver.recover(wallet, replayed['snapshot'], replayed['snapshot'].state(s.DOMAIN))
        actionable = no_append.available(recovered)
        summary = {'schema': 'kpx5-one-backup-owner-result/v1',
            'classification': recovery.SCOPE, 'op': args.op,
            'recognized_historical_receipt_count': len(recovered.owned),
            'recognized_spent_receipt_count': sum(claim.spent for claim in recovered.owned),
            'recognized_unspent_claim_count_before': len(actionable),
            **no_append.controlled_payouts(seed, wallet, recovered, replayed['anchor_point'], replayed['payouts']),
            'selected_child_domain_hex32': s.DOMAIN.hex(), 'selected_owner_ELF_sha256': s.PROVER_SHA,
            'accepted_chain_backing_verified': False, 'currentness_verified': False, 'spend_authorized': False,
            'seed_witness_receipt_map_or_private_input_hash_exported': False}
        if worker is not None:
            need(replayed['point'] is not None and actionable, 'live-recognized-supplied-claim-required')
            claims = tuple(actionable[:args.max_inputs])
            material = no_append.prepare(seed, wallet, replayed['snapshot'], recovered, claims,
                replayed['point'], replayed['anchor_point'], replayed['reserve'])
            candidate, quote = runtime.quote_material(material, output / 'PRIVATE-quotes', args.fee_rate)
            proof = worker.prove(candidate)
            body, contexts, report, metrics = runtime.finalize(candidate, replayed['point'], replayed['reserve'],
                profile['vk'], profile['vk'], proof, quote, output / 'prepared')
            after = c.receiver.recover(wallet, material.after, material.after.state(s.DOMAIN))
            remaining = no_append.available(after)
            need(len(remaining) == len(actionable) - len(claims), 'all-recognized-claims-accounted')
            summary.update({'transaction_id': body['id'], 'proof_sha256': p.h(proof).hex(),
                'authorization_sha256': p.h(candidate.auth).hex(), 'quote_id': quote['quote_id'],
                'consumed_same_backup_claim_count': len(claims),
                'recognized_unspent_claim_count_after': len(remaining),
                'native_payout_sompi': candidate.payout, 'fee_sompi': candidate.fee,
                'reserve_after_sompi': candidate.reserve_after,
                'new_compact_whole_PK_READY_before_backup': True,
                'native_Full_all_engines_with_supplied_contexts': report['all_input_engines_accepted'] is True})
        c.native_runtime.save(output / 'RESULTS.json', summary)
        return summary
    finally:
        if worker is not None:
            worker.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('op', choices=('recover', 'prepare-full-cashout'))
    for name in ('profile', 'prestate', 'history', 'manifest', 'backup', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--history-sha256', required=True)
    parser.add_argument('--pk', type=Path)
    parser.add_argument('--workers', type=int, default=14)
    parser.add_argument('--max-inputs', type=int, choices=(1, 2), default=2)
    parser.add_argument('--fee-rate', type=int, default=100)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--must-be-absent', type=Path, action='append', default=[])
    try:
        print(json.dumps(run(parser.parse_args()), sort_keys=True))
    except Exception:
        print(json.dumps({'error': 'owner-operation-incomplete', 'currentness_verified': False,
                          'spend_authorized': False}))
        raise SystemExit(1)
