"""Select fresh build/run paths and freeze the active source; starts no jobs."""
import argparse
import hashlib
import json
from pathlib import Path


def encode(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-root', type=Path, required=True)
    parser.add_argument('--run-root', type=Path, required=True)
    parser.add_argument('--selection-root', type=Path, required=True)
    parser.add_argument('--freeze-name', default='SOURCE-FREEZE-03.json')
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    for path in [args.build_root, args.run_root, args.selection_root]:
        if not path.is_absolute():
            raise ValueError('ABSOLUTE_SELECTION_PATH')
    if args.build_root.exists() or args.run_root.exists():
        raise ValueError('FRESH_BUILD_AND_RUN_IDENTITIES_REQUIRED')
    changes = {
        '/var/tmp/kpi-nativeauthspend-preparation-vyqdmzti': str(source),
        '/var/tmp/kpi-nativeauthspend-work-01/build-01': str(args.build_root),
        '/var/tmp/kpi-nativeauthspend-work-01/run-01': str(args.run_root),
    }

    def replace(value):
        if isinstance(value, str):
            for old, new in changes.items():
                value = value.replace(old, new)
            return value
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value

    commands = replace(json.loads((source / 'COMMANDS-02.json').read_text()))
    commands.update(schema='kpi-nativeauth-selected-commands/v3', source_root=str(source))
    command_bytes = encode(commands)
    command_path = args.selection_root / 'COMMANDS-03.json'
    with command_path.open('xb') as output:
        output.write(command_bytes)
    records = []
    freeze_path = source / args.freeze_name
    for path in sorted(source.rglob('*')):
        if not path.is_file() or path == freeze_path or 'node_modules' in path.relative_to(source).parts or '__pycache__' in path.parts:
            continue
        if path.is_symlink() or path.stat().st_nlink != 1:
            raise ValueError('SOURCE_SINGLE_LINK')
        content = path.read_bytes()
        records.append({'path': path.relative_to(source).as_posix(), 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
    frozen = {
        'schema': 'kpi-nativeauth-source-freeze/v2',
        'status': 'SOURCE_ONLY_UNCOMPILED_UNEXECUTED',
        'source_root': str(source),
        'baselineFreezeSha256': '9bded95d08ec2a372bd89b89d83b630155b1e095da7909b2696e423962320b71',
        'selected_build_entry': 'harness/build_gate.py',
        'selected_run_entry': 'harness/run_gate-03.py',
        'files': records,
        'financialRelationOrControlExpectationsChanged': False,
        'nativePredicateDelta': 'Two saved AdditiveGroup trait imports only.',
    }
    freeze_bytes = encode(frozen)
    with freeze_path.open('xb') as output:
        output.write(freeze_bytes)
    print(json.dumps({'sourceFreeze': str(freeze_path), 'sourceFreezeSha256': hashlib.sha256(freeze_bytes).hexdigest(), 'commands': str(command_path), 'commandsSha256': hashlib.sha256(command_bytes).hexdigest(), 'buildRoot': str(args.build_root), 'runRoot': str(args.run_root), 'sourceFiles': len(records)}, sort_keys=True))


if __name__ == '__main__':
    main()
