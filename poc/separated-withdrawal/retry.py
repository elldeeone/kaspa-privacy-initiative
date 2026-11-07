#!/usr/bin/env python3
"""Fresh unfunded identity for the incomplete tagged arm; earlier results kept."""
import argparse, hashlib, json, pathlib
import run as campaign

def main():
    p = argparse.ArgumentParser()
    p.add_argument('new_private_run', type=pathlib.Path)
    a = p.parse_args()
    root = a.new_private_run.resolve()
    root.mkdir(mode=0o700)
    source = [f for f in campaign.PACKAGE.rglob('*') if f.is_file() and '__pycache__' not in f.parts and 'target' not in f.parts]
    source += [campaign.ROOT / 'research/separated-withdrawal-2026-11-07/SELECTION.md', campaign.HOST]
    campaign.write(root / 'SOURCE-FREEZE.json', {'retryScope': 'only incomplete tagged arm; no application request was received in prior attempt',
                                               'files': [{'path': str(f.relative_to(campaign.ROOT)), 'sha256': hashlib.sha256(f.read_bytes()).hexdigest()} for f in source]})
    img = campaign.image(root)
    campaign.write(root / 'IMAGE.json', {'tag': img})
    result = campaign.arm(root, 'tagged', img, campaign.read(campaign.ROOT / '.local/cached-approval-verification/COMBINED.json'))
    campaign.write(root / 'RESULT.json', result)

if __name__ == '__main__':
    main()
