#!/usr/bin/env python3
"""Run after the complete prediction barrier; format control, no privacy pass."""
import hashlib
import json
import sys


def digest(v):
    return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def score(public, prediction, truth):
    classes = ('real_receipt_seal', 'old_raw_random_dummy', 'new_throwaway_sealed_dummy')
    if (set(public) != {'schema','classification','ciphertexts'}
            or public['schema'] != 'kpi-padding-public/v1'
            or public['classification'] != 'SYNTHETIC_FORMAT_CONTROL'
            or len(public['ciphertexts']) != 768):
        raise ValueError('public framing')
    if set(truth) != {'schema', 'labels'} or truth['schema'] != 'kpi-padding-truth/v1':
        raise ValueError('truth framing')
    if (set(prediction) != {'schema','public_sha256','byte_index','mask','rows'}
            or prediction['schema'] != 'kpi-padding-predictions/v1'
            or prediction['public_sha256'] != digest(public)
            or prediction['byte_index'] != 31 or prediction['mask'] != 128):
        raise ValueError('prediction identity')
    if len(truth['labels']) != 768 or len(prediction['rows']) != 768:
        raise ValueError('complete predeclared768 samples')
    counts = {c: dict(flagged=0,total=0) for c in classes}
    for i, (label, row) in enumerate(zip(truth['labels'],prediction['rows'],strict=True)):
        if label not in classes or set(row) != {'ordinal','not_honest_seal'}:
            raise ValueError('label/row')
        if row['ordinal'] != i or type(row['not_honest_seal']) is not bool:
            raise ValueError('prediction row')
        observed = public['ciphertexts'][i]
        if set(observed) != {'ordinal','hex'} or observed['ordinal'] != i:
            raise ValueError('public ciphertext row')
        cipher = bytes.fromhex(observed['hex'])
        if len(cipher) != 264 or cipher.hex() != observed['hex']:
            raise ValueError('canonical cipher264')
        if row['not_honest_seal'] != bool(cipher[31] & 128):
            raise ValueError('prediction contradicts fixed bit classifier')
        counts[label]['total'] += 1
        counts[label]['flagged'] += int(row['not_honest_seal'])
    if any(c['total'] != 256 for c in counts.values()):
        raise ValueError('fixed class counts')
    real, old, new = (counts[c] for c in classes)
    return dict(schema='kpi-padding-result/v1', classification='SYNTHETIC_C_ONLY_FORMAT_CANARY',
        public_sha256=digest(public), prediction_sha256=digest(prediction), truth_sha256=digest(truth),
        fixed_attack='ciphertext[31]&0x80 !=0 => not an honest crypto_box0.9.1 seal',
        per_class=counts,
        old_vs_real_forced_choice=dict(correct=old['flagged']+256-real['flagged'],total=512),
        new_vs_real_forced_choice=dict(correct=new['flagged']+256-real['flagged'],total=512),
        positive_flag_means='not honest real seal; within this declared3-class fixture a dummy',
        negative_flag_means='unresolved, never evidence of a positive note',
        stop_if_real_or_new_flagged=bool(real['flagged'] or new['flagged']),
        privacy_qualification=False, crypto_correctness_proof=False,
        accepted_native_history=False, population_evaluation=False,
        limitations=['Shared real control correlates comparisons; no independent CI claimed.',
          'Only the fixed highbit classifier is tested, not all format/curve-membership attacks.',
          'Terminal all-zero ciphertext is intentionally public and excluded.',
          'No target identities, amounts, balances or chain acceptance are scored.'])


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('public prediction truth')
    print(json.dumps(score(*(json.load(open(p)) for p in sys.argv[1:])),sort_keys=True,indent=2))
