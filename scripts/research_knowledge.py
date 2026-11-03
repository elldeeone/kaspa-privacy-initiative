#!/usr/bin/env python3
"""Read and verify the frozen research library without Git or a network."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

DEFAULT_ROOT = Path(__file__).resolve().parents[1] / 'docs/research-knowledge'


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Library:
    def __init__(self, root):
        self.root = root
        self.manifest = json.loads((root / 'manifest.json').read_text())
        ledger = json.loads((root / 'commits.json').read_text())
        require(self.manifest['schema'] == 'research-knowledge-v1', 'manifest schema')
        require(ledger['schema'] == 'research-knowledge-commits-v1', 'commit ledger schema')
        records = ledger['commits']
        self.commits = {c['sha']: c for c in records}
        require(len(records) == len(self.commits), 'duplicate commit IDs')
        self.documents = self.manifest['documents']
        self.trees = {}

    def tree(self, commit, visiting=None):
        if commit in self.trees:
            return self.trees[commit]
        visiting = set() if visiting is None else visiting
        require(commit not in visiting, 'cycle in commit ledger')
        require(commit in self.commits, 'missing commit: ' + commit)
        visiting.add(commit)
        record = self.commits[commit]
        parents = record['parents']
        require(all(p in self.commits for p in parents), 'missing parent: ' + commit)
        tree = dict(self.tree(parents[0], visiting)) if parents else {}
        seen = set()
        for change in record['document_changes']:
            path = change['path']
            require(path not in seen, 'duplicate document change: ' + commit + ':' + path)
            require(tree.get(path) == change['before'], 'document predecessor mismatch: ' + commit + ':' + path)
            seen.add(path)
            if change['after'] is None:
                tree.pop(path)
            else:
                require(change['after'] in self.documents, 'missing document metadata: ' + path)
                tree[path] = change['after']
        encoded = json.dumps(tree, sort_keys=True, separators=(',', ':')).encode()
        require(hashlib.sha256(encoded).hexdigest() == record['document_tree_sha256'], 'document tree mismatch: ' + commit)
        require(len(tree) == record['document_count'], 'document count mismatch: ' + commit)
        visiting.remove(commit)
        self.trees[commit] = tree
        return tree

    def read(self, blob):
        require(re.fullmatch(r'[0-9a-f]{40}', blob) is not None, 'invalid document ID')
        record = self.documents[blob]
        expected = 'documents/' + blob + '.txt'
        require(record['file'] == expected, 'unexpected document location: ' + blob)
        path = self.root / expected
        require(path.is_file() and not path.is_symlink(), 'missing regular document: ' + expected)
        raw = path.read_bytes()
        require(len(raw) == record['bytes'], 'document size mismatch: ' + expected)
        require(hashlib.sha256(raw).hexdigest() == record['sha256'], 'document SHA-256 mismatch: ' + expected)
        git_blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        require(git_blob == blob, 'original Git blob mismatch: ' + expected)
        return raw.decode('utf-8')

    def check(self):
        m = self.manifest
        require(len(self.commits) == m['commits'] == m['audited_commits'] + m['consolidation_commits'], 'commit coverage count')
        require(m['source_checkpoint'] in self.commits, 'missing source checkpoint')
        require(set(m['recovered_commits']) <= self.commits.keys(), 'missing recovered commit')
        require(len(self.documents) == m['document_versions'], 'document coverage count')
        used = set()
        for commit in self.commits:
            require(re.fullmatch(r'[0-9a-f]{40}', commit) is not None, 'invalid commit ID')
            used.update(self.tree(commit).values())
        require(len(used) == m['committed_document_versions'], 'committed document coverage count')
        for note in m['unfinished_notes']:
            require(note['blob'] in self.documents, 'missing unfinished note')
            require(note['sha256'] == self.documents[note['blob']]['sha256'], 'unfinished source hash mismatch')
            require(any(o['kind'] == 'unfinished-note' and o['path'] == note['path'] and o['source_sha256'] == note['sha256'] for o in self.documents[note['blob']]['origins']), 'unfinished note provenance')
            used.add(note['blob'])
        require(used == self.documents.keys(), 'unreferenced document metadata')
        total = 0
        for blob, record in self.documents.items():
            self.read(blob)
            total += record['bytes']
            require(bool(record['origins']), 'missing provenance: ' + blob)
            for origin in record['origins']:
                path = PurePosixPath(origin['path'])
                require(not path.is_absolute() and '..' not in path.parts, 'nonrelative source path')
                if origin['kind'] == 'committed':
                    require(self.tree(origin['commit']).get(origin['path']) == blob, 'source origin mismatch: ' + origin['path'])
                else:
                    require(origin['kind'] == 'unfinished-note', 'unknown provenance kind')
        require(total == m['document_bytes'], 'document byte count')
        expected = {r['file'] for r in self.documents.values()}
        actual = {p.relative_to(self.root).as_posix() for p in (self.root / 'documents').rglob('*') if p.is_file()}
        require(actual == expected, 'missing or extra document files')
        branches = m['branches']
        require(len({(b['kind'], b['name']) for b in branches}) == len(branches), 'duplicate branch record')
        require(Counter(b['kind'] for b in branches) == {'local': m['original_local_branches'], 'fork': m['fork_branches'], 'upstream': m['upstream_branches']}, 'branch coverage count')
        require(all(b['tip'] in self.commits for b in branches), 'missing original branch tip')
        pulls = m['pull_requests']
        require(len(pulls) == len({p['number'] for p in pulls}) == m['merged_pull_histories'], 'pull history coverage count')
        require(all(p['head'] in self.commits and p['merge_commit'] in self.commits and p['merged_at'] for p in pulls), 'missing pull head/merge history')
        print(f"Knowledge coverage: {len(self.commits)} commits, {len(self.documents)} document versions, {len(branches)} branch refs and {len(pulls)} pull histories: OK.")

    def find(self, term):
        found = 0
        for blob, record in sorted(self.documents.items()):
            for origin in record['origins']:
                if term.casefold() in origin['path'].casefold():
                    label = origin.get('commit', 'unfinished note')
                    print(origin['path'] + '\n  ' + label + '\n  ' + str(self.root / record['file']))
                    found += 1
        require(found > 0, 'no original paths match: ' + term)

    def show(self, prefix, path):
        candidates = [c for c in self.commits if c.startswith(prefix)]
        require(len(candidates) == 1, 'commit prefix must identify exactly one captured commit')
        commit = candidates[0]
        tree = self.tree(commit)
        require(path in tree, 'no document at ' + commit + ':' + path)
        print('Frozen source ' + commit + ':' + path + '; current lessons/corrections govern its interpretation.', file=sys.stderr)
        print(self.read(tree[path]), end='')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('check')
    find = commands.add_parser('find', help='find historical document paths')
    find.add_argument('term')
    show = commands.add_parser('show', help='read a document at its captured commit')
    show.add_argument('commit')
    show.add_argument('path')
    args = parser.parse_args()
    try:
        library = Library(args.root)
        if args.command == 'check':
            library.check()
        elif args.command == 'find':
            library.find(args.term)
        else:
            library.show(args.commit, args.path)
    except (ValueError, KeyError, OSError) as error:
        print('Research knowledge: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
