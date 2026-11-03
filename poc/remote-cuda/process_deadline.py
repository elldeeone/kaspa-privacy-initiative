"""An external deadline for one owned Linux session, independent of its caller."""
import math
import os
from pathlib import Path
import signal
import subprocess
import sys


def command(seconds, arguments):
    """The caller must launch this command as a new session/process group."""
    if isinstance(seconds, bool) or not math.isfinite(seconds) or seconds <= 0:
        raise ValueError('finite positive deadline required')
    if not arguments or not all(isinstance(value, str) and value and '\0' not in value for value in arguments):
        raise ValueError('nonempty command arguments required')
    return [sys.executable, str(Path(__file__).resolve()), str(seconds), *arguments]


def active_peers(group):
    for path in Path('/proc').iterdir():
        if not path.name.isdigit() or int(path.name) == group:
            continue
        try:
            fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == group and fields[0] not in ('Z', 'X'):
                return True
        except (OSError, ValueError, IndexError):
            continue
    return False


def run(seconds, arguments):
    command(seconds, arguments)  # Same validation for the CLI and imported caller.
    group = os.getpid()
    if os.getpgrp() != group or os.getsid(0) != group:
        raise ValueError('deadline guard must own a new session and process group')

    def stop_group(*_):
        # The guard is still the session/group leader: this cannot target a
        # reused group or the invoking shell. SIGKILL also stops this guard.
        os.killpg(group, signal.SIGKILL)

    signal.signal(signal.SIGTERM, stop_group)
    signal.signal(signal.SIGINT, stop_group)
    child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL)
    try:
        status = child.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        stop_group()
        raise AssertionError('group kill returned')
    if active_peers(group):
        # A successful parent exit must not leave background work beyond the
        # deadline. Such an incomplete command fails instead of claiming success.
        stop_group()
    return status if status >= 0 else 128 - status


if __name__ == '__main__':
    try:
        if len(sys.argv) < 3:
            raise ValueError('usage: process_deadline.py SECONDS COMMAND [ARG ...]')
        sys.exit(run(float(sys.argv[1]), sys.argv[2:]))
    except ValueError as error:
        raise SystemExit(str(error))
