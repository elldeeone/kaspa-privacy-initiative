"""Persistent metadata exclusions and narrowly registered producer promotion.

The trusted controller registers an exact producer public leaf before launch.
Private staging/logs stay under the separate whole private parent. Producer
exports must already be outside that parent; no private-leaf exception exists.
Only selected honest producer code may create a registered export. This is not
protection against a malicious host or a producer deliberately encoding secrets.
"""
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'construction'))
from backend import PublicGuard, path, write
from codec import sha
from trees import need

PRIVATE = Path('/var/tmp/kpi-owner-private-lifecycle-01/private')


class Ingress:
    def __init__(self, original_trials, retained_private, private_parent=PRIVATE):
        self.original_trials = list(original_trials)
        self.private_parent = path(private_parent)
        self.retained = [path(root) for root in retained_private]
        need(self.private_parent in self.retained, 'whole-current-private-parent-excluded')
        self.forbidden, self.producers = set(), {}
        self.refresh()

    def register(self, job, kind):
        job = path(job)
        need(not job.exists() and job not in self.producers
             and all(not job.is_relative_to(root) for root in self.guard.directories),
             'fresh-public-producer-output')
        need(kind in ('init', 'restore', 'invoice', 'prepare', 'authorize', 'scan', 'exit-ready', 'exit', 'funding-sign'),
             'closed-producer-kind')
        self.producers[job] = kind
        return job / 'PUBLIC.json'

    def refresh(self):
        # Metadata only; a previously observed private inode is never removed.
        # Public producer paths are disjoint from private parents, so no private
        # inode or directory ever needs an exemption.
        guard = PublicGuard(self.original_trials, (), self.retained)
        self.forbidden.update(guard.forbidden)
        guard.forbidden.update(self.forbidden)
        self.guard = guard
        return guard

    def read(self, source, expected):
        guard = self.refresh()
        return guard.read(source, expected)

    def promote(self, job, target, validator):
        """Read one exact registered producer leaf, validate, copy public bytes."""
        job = path(job)
        need(job in self.producers, 'registered-public-producer-only')
        self.refresh()
        leaf, before = self.guard.metadata(job / 'PUBLIC.json')
        identity = (before.st_dev, before.st_ino)
        need(identity not in self.forbidden
             and stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size <= 1 << 20, 'registered-producer-public-inode')
        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        with os.fdopen(descriptor, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            need(all(getattr(opened, key) == getattr(before, key) for key in attributes)
                 and (opened.st_dev, opened.st_ino) not in self.forbidden,
                 'producer-public-swapped-before-open')
            raw = stream.read((1 << 20) + 1)
            after = os.fstat(stream.fileno())
        need(len(raw) == before.st_size
             and all(getattr(after, key) == getattr(before, key) for key in attributes),
             'stable-producer-public-bytes')
        value = validator(raw, self.producers[job])
        target = path(target)
        need(not target.exists() and all(not target.is_relative_to(root)
             for root in self.guard.directories), 'fresh-public-promotion-outside-private')
        write(target, raw)
        return value, {'path': str(target), 'sha256': sha(raw), 'bytes': len(raw)}
