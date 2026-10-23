#!/usr/bin/env python3
"""Remove researcher filenames/roles; export only declared public-chain inputs."""
import argparse
import hashlib
import json
from pathlib import Path

ORDER = ('fundingprep', 'founding', 'admit', 'private', 'bob-reveal', 'charlie-reveal')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('accepted_packet', type=Path)
    parser.add_argument('new_directory', type=Path)
    args = parser.parse_args()
    if args.new_directory.exists():
        raise ValueError('fresh export directory required')
    args.new_directory.mkdir(parents=True)
    rows, sources = [], []
    for ordinal, name in enumerate(ORDER):
        source = args.accepted_packet / 'chain-public/observations' / (name + '.json')
        record = json.loads(source.read_bytes())
        rows.append({'ordinal': ordinal, 'body': record['accepted_body'],
                     'accepted_input_contexts': record['accepted_input_contexts'],
                     'accepting_header': record['accepting_block_header']})
        sources.append({'ordinal': ordinal, 'source_path': str(source), 'source_sha256': digest(source),
                        'source_scope': 'Actual accepted TN10 public bytes/context/header excerpt'})
    dataset = {'schema': 'kpx2-public-chain-observer/v1', 'observer': 'C',
        'classification': 'ACTUAL_TN10_KNOWN_PILOT_NOT_BLIND_QUALIFICATION', 'transactions': rows}
    output = args.new_directory / 'public-chain.json'
    output.write_text(json.dumps(dataset, indent=2, sort_keys=True) + '\n')
    # Source map is publication provenance, never mounted into the attacker run.
    (args.new_directory / 'SOURCE-MAP.json').write_text(json.dumps({
        'dataset_sha256': digest(output), 'researcher_filename_map_excluded_from_attacker': True,
        'sources': sources}, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'public_transactions': len(rows), 'dataset_sha256': digest(output),
                      'private_data_read': False, 'new_directory': str(args.new_directory)}))


if __name__ == '__main__':
    main()
