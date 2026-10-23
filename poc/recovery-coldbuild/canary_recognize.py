"""PUBLIC known-seed canary only; no PK/prover or accepted-current bridge."""
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, '/work/poc/compact-batch-lifecycle')
import history
from native_runtime import DOMAIN, Runtime, encoded
import receiver
from primitives import need

DESCRIPTOR = '61e0f955850f199305bb50ec57ad389aafbc645de2685ff3572d76f11d864ed8'
HISTORY_RAW = 'a88b183ce9ac9a0faad831fd4dac88fa9fe269618ea5c634ee45a5f9381520a4'


def main():
    raw = Path('/history.json').read_bytes()
    need(hashlib.sha256(raw).hexdigest() == HISTORY_RAW, 'root-selected-public-canary-history')
    descriptor, _, _ = history.descriptor(Path('/descriptor.json').read_bytes(), DESCRIPTOR)
    replayed = history.replay(raw, descriptor, DESCRIPTOR, Runtime(), Path('/out/replay'))
    seed = receiver.backup(Path('/own-backup.json'), DOMAIN)
    wallet = receiver.module().Receiver(seed, DOMAIN, receiver.Crypto())
    found = receiver.recover(wallet, replayed['snapshot'], replayed['snapshot'].state(DOMAIN))
    need(len(found.owned) == 1 and found.owned[0].owner_action_available
         and not found.owned[0].spent, 'public-canary-receipt-decrypt-rederive-and-NF')
    result = {'schema': 'kpx4-cold-public-canary-recognition/v1',
        'classification': 'PUBLIC_UNSAFE_KNOWN_SEED_DO_NOT_FUND_SYNTHETIC_CONTEXTS',
        'recognized_historical_count': len(found.owned),
        'recognized_unspent_claim_count_in_supplied_history': 1,
        'fresh_local_native_Full_all_engines': True,
        'decrypted_rederived_commitment_and_positioned_NF_checked': True,
        'public_PK_or_owner_prover_mounted': False,
        'original_source_cache_operator_paths_mounted': False,
        'accepted_chain_backing_verified': False, 'currentness_verified': False,
        'spend_authorized': False}
    Path('/out/RESULTS.json').write_bytes(encoded(result) + b'\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
