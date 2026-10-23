#!/usr/bin/env python3
"""One original backup, authenticated public PK, then one synthetic native action.

The trusted launcher supplies selection pins independently of a capsule. The
prover authenticates owned whole PK bytes before its READY and before this
process reads backup bytes. Only the witness data pipe is inherited. No prior
private output, owner map, other backup, hosted prover or network interface is
accepted. Supplied synthetic contexts never become live/current authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

import actions
import history
from native_runtime import (CLEAN, DOMAIN, ROOT, Executable, Runtime, encoded, save,
                            EMITTER, NATIVE, NODE, SDK, SDK_FILES)
from primitives import MAX, NOTE_FLOOR, fixed, h, need, parse
import receiver


def metadata_guard(backup, public_paths, output):
    backup = receiver.no_symlinks(backup)
    info = backup.stat()
    need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600, 'own-backup-metadata')
    inode = info.st_dev, info.st_ino
    for path in public_paths:
        path = receiver.no_symlinks(path)
        row = path.stat()
        need(stat.S_ISREG(row.st_mode) and (row.st_dev, row.st_ino) != inode,
             'public-input-aliases-own-backup')
    output = receiver.no_symlinks(output)
    need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-owner-output-outside-Git')
    return backup, output


def minimum_shape_fee(mode, redeem_bytes, rate):
    """Planning only: exact official actual-body quote must agree before send.

    At allowed floors all supported one-input storage masses are below these
    compute masses: max100000 for native payout plus16666 for reserve. No PK,
    proof tariff or budget saving is assumed. A changed actual quote aborts the
    preparation before witness serialization; it never clips recipient intent.
    """
    need(mode in (0, 2, 32) and type(rate) is int and 0 < rate < 1 << 64, 'shape-fee-input')
    scripts = [36] if mode == 0 else [37] if mode == 32 else [37, 36]
    payload = {0: 2848, 2: 3920, 32: 12672}[mode]
    estimate = 94 + 54 + 199 + redeem_bytes + sum(18 + size - 2 for size in scripts) + payload
    return rate * max(estimate + 10 * sum(scripts) + 160000, 2 * estimate)


def selection(raw, role):
    value = parse(raw)
    need(type(value) is dict and set(value) == {'schema', 'role', 'domain_hex32',
         'descriptor_sha256', 'parameter_manifest_sha256', 'vk_sha256',
         'compiled_build_identity_sha256', 'prover_sha256'}
         and value['schema'] == 'kpx4-compact-batch-owner-selection/v1'
         and value['role'] == role and value['domain_hex32'] == DOMAIN.hex(),
         'externally-installed-owner-selection')
    for name in ('descriptor_sha256', 'parameter_manifest_sha256', 'vk_sha256',
                 'compiled_build_identity_sha256', 'prover_sha256'):
        history.hexbytes(value[name], 32)
    return value


def run(args):
    absent = getattr(args, 'must_be_absent', [])
    need(all(not Path(path).exists() and not Path(path).is_symlink() for path in absent),
         'original-operator-source-or-cache-path-visible')
    public_paths = [args.selection, args.descriptor, args.history, args.manifest, args.pk,
                    args.prover, EMITTER, NATIVE, NODE, SDK, *SDK_FILES, receiver.SOURCE, receiver.CRYPTO]
    if args.invoices:
        public_paths.append(args.invoices)
    own_backup, output = metadata_guard(args.backup, public_paths, args.output)
    selected = selection(Path(args.selection).read_bytes(), args.role)
    descriptor, compact, wide = history.descriptor(Path(args.descriptor).read_bytes(),
                                                  selected['descriptor_sha256'])
    manifest_raw = Path(args.manifest).read_bytes()
    need(hashlib.sha256(manifest_raw).hexdigest() == selected['parameter_manifest_sha256'],
         'installed-parameter-manifest-pin')
    manifest = parse(manifest_raw)
    need(manifest['schema'] == 'kpx4-public-proving-parameters/v1'
         and manifest['role'] == args.role and manifest['domain_hex32'] == DOMAIN.hex()
         and manifest['output_arity'] == (32 if args.role == 'wide32' else 2)
         and manifest['compiled_build_identity_sha256'] == selected['compiled_build_identity_sha256']
         and manifest['vk_sha256'] == selected['vk_sha256'], 'selected-role-parameter-manifest')
    vk = wide if args.role == 'wide32' else compact
    need(history.hexbytes(manifest['vk_hex328'], 328) == vk
         and hashlib.sha256(vk).hexdigest() == selected['vk_sha256'], 'descriptor-role-manifest-and-VK')
    # Explicit keys avoid letting similarly named role strings select fields.
    key = 'wide_public_params_manifest_sha256' if args.role == 'wide32' else 'compact_public_params_manifest_sha256'
    need(descriptor[key] == selected['parameter_manifest_sha256'], 'descriptor-selected-role-manifest')
    need((args.role == 'wide32') == bool(args.invoices), 'role-public-invoice-input')
    invoice_data = None
    if args.invoices:
        invoice_data = parse(Path(args.invoices).read_bytes())
        need(set(invoice_data) == {'schema', 'domain_hex32', 'recipient_public_invoices_hex208'}
             and invoice_data['schema'] == 'kpx4-compact-batch-public-invoices/v1'
             and invoice_data['domain_hex32'] == DOMAIN.hex(), 'public-invoice-roster')
    output.mkdir(mode=0o700, parents=True)
    runtime = Runtime()
    crypto, v2 = receiver.Crypto(), receiver.module()
    replayed = history.replay(Path(args.history).read_bytes(), descriptor,
                              selected['descriptor_sha256'], runtime, output / 'public-replay')
    need(replayed['reserve_sompi'] >= NOTE_FLOOR and replayed['current_outpoint'] is not None,
         'supplied-synthetic-live-claim-required')
    prover = Executable(args.prover, selected['prover_sha256'])
    read_fd, write_fd = os.pipe()
    process = None
    try:
        process = subprocess.Popen([str(prover.path), 'prove', args.role, str(args.pk), str(read_fd),
                                     str(output / 'proof')], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, pass_fds=(read_fd,), env=dict(CLEAN))
        os.close(read_fd)
        read_fd = None
        first = process.stdout.readline()
        need(bool(first), 'prover-did-not-authenticate-parameters')
        ready = parse(first)
        expected = {'event': 'parameters-ready', 'role': args.role,
            'output_arity': 32 if args.role == 'wide32' else 2,
            'parameter_manifest_sha256': selected['parameter_manifest_sha256'],
            'domain_hex32': DOMAIN.hex(), 'vk_sha256': selected['vk_sha256'],
            'compiled_build_identity_sha256': selected['compiled_build_identity_sha256']}
        need(ready == expected, 'authenticated-prover-READY-required-before-backup')
        save(output / 'PARAMETERS-READY.json', ready)
        # This is the first backup-byte read. No witness bytes have been sent.
        seed = receiver.backup(own_backup, DOMAIN)
        wallet = v2.Receiver(seed, DOMAIN, crypto)
        snapshot = replayed['snapshot']
        recovered = receiver.recover(wallet, snapshot, snapshot.state(DOMAIN))
        available = [claim for claim in recovered.owned if claim.owner_action_available]
        need(len(available) == 1, 'one-independently-recognized-current-claim')
        claim = available[0]
        reserve = replayed['reserve_sompi']
        previous = replayed['current_outpoint']
        if args.role == 'wide32':
            need(type(args.recipient_gross_sompi) is int
                 and NOTE_FLOOR <= args.recipient_gross_sompi <= MAX, 'recipient-exact-gross-value')
            mode = 32
            fee = minimum_shape_fee(mode, len(replayed['current_redeem']), args.fee_rate)
            invoices = [history.hexbytes(raw, 208) for raw in invoice_data['recipient_public_invoices_hex208']]
            candidate = actions.payment(wallet, snapshot, claim, previous, reserve, fee,
                invoices, [args.recipient_gross_sompi] * 32)
        else:
            mode = 0 if claim.receipt.value_sompi == reserve else 2
            fee = minimum_shape_fee(mode, len(replayed['current_redeem']), args.fee_rate)
            candidate = actions.cashout(seed, wallet, snapshot, claim, previous,
                descriptor['founding_outpoint'], reserve, fee)
        # Only this immutable legal candidate is quoted. No diagnostic object
        # can serialize a private witness or bypass this exact fee/body check.
        quoted = runtime.quote(candidate, previous, reserve, compact, wide,
                               output / 'actual-quote', args.fee_rate)
        with os.fdopen(write_fd, 'wb') as writer:
            write_fd = None
            writer.write(encoded(candidate.private_witness()) + b'\n')
        remaining_stdout, stderr = process.communicate()
        (output / 'PRIVATE-PROVER-STDERR.log').write_text(stderr)
        need(process.returncode == 0, 'selected-owner-proof-failed')
        done = parse(remaining_stdout.strip())
        need(done['event'] == 'proof-complete' and done['genuine_Groth16_verified'] is True
             and done['role'] == args.role, 'selected-owner-proof-not-verified')
        proof = fixed((output / 'proof/proof128.bin').read_bytes(), 128)
        need((output / 'proof/authorization528.bin').read_bytes() == candidate.auth
             and (output / 'proof/verification-key.bin').read_bytes() == vk
             and h(proof).hex() == done['proof_sha256']
             and h(candidate.auth).hex() == done['authorization_sha256'], 'exact-selected-proof-and-statement')
        body, contexts, report, metrics = runtime.finalize(candidate, previous, reserve, compact, wide,
            proof, quoted, output / 'prepared')
        # Raw recovery, private statement alternatives and operational paths
        # remain private; stdout contains selected public effects/counts only.
        summary = {'schema': 'kpx4-compact-batch-owner-result/v1',
            'classification': 'SUPPLIED_SYNTHETIC_CONTEXTS_NOT_ACCEPTED_OR_CURRENT',
            'role': args.role, 'transaction_id': body['id'], 'proof_sha256': h(proof).hex(),
            'authorization_sha256': h(candidate.auth).hex(), 'quote_id': quoted['quote_id'],
            'own_historical_receipt_count': len(recovered.owned),
            'own_spent_receipt_count': sum(claim.spent for claim in recovered.owned),
            'recognized_current_claim_count_before': len(available),
            'native_payout_sompi': candidate.payout, 'fee_sompi': candidate.fee,
            'reserve_after_sompi': candidate.reserve_after, 'mode': candidate.mode,
            'native_Full_all_engines_with_supplied_contexts': True,
            'prover_authenticated_whole_PK_before_own_backup_read': True,
            'original_path_absence_probe_count': len(absent),
            'all_requested_original_paths_absent': True if absent else None,
            'private_witness_or_backup_or_owner_map_or_input_hash_exported': False,
            'accepted_chain_currentness_or_live_readiness_claimed': False}
        save(output / 'RESULTS.json', summary)
        return summary
    finally:
        if read_fd is not None:
            os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
        if process is not None and process.poll() is None:
            process.terminate()
            process.communicate()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=('compact2', 'wide32'), required=True)
    for name in ('selection', 'descriptor', 'history', 'manifest', 'pk', 'prover', 'backup', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--invoices', type=Path)
    parser.add_argument('--recipient-gross-sompi', type=int, default=1_018_867_700)
    parser.add_argument('--fee-rate', type=int, default=100)
    parser.add_argument('--must-be-absent', type=Path, action='append', default=[])
    args = parser.parse_args()
    try:
        print(json.dumps(run(args), sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError):
        # No exception value, private path, assignment or witness appears here.
        raise SystemExit('compact owner preparation refused') from None
