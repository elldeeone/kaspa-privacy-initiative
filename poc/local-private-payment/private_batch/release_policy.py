"""Durable disclosure-barrier MODEL for synthetic public member tokens.

This module is not private input admission or an MPC implementation. The model
has clear synthetic tokens; actual NF overlap checks must remain in qualified
MPC. Its external checkpoint is a trusted input: rolling back both history and
that checkpoint is undetectable here. No history state authorizes or blocks an
independent Exit, and this module never accepts financial transitions.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from urllib.parse import quote

WIDTH = 3
GENESIS_TAG = b'KPBHIST1'
EVENT_TAG = b'KPBHEVT1'
REFUSAL = 'private batch continuation refused'


class Refused(ValueError):
    """One aggregate refusal; never include NF, owner or client-slot details."""


def _digest(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise Refused(REFUSAL)
    return value


def _json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def _hex_digest(value) -> bool:
    if type(value) is not str or len(value) != 64:
        return False
    try:
        return bytes.fromhex(value).hex() == value
    except ValueError:
        return False


def _event_shape(event, prior: list[dict]) -> bool:
    if type(event) is not dict:
        return False
    if event.get('kind') == 'prepared':
        members = event.get('members')
        return (set(event) == {'kind', 'members', 'effects'}
                and type(members) is list and len(members) == WIDTH
                and all(_hex_digest(member) for member in members)
                and members == sorted(set(members)) and '00' * 32 not in members
                and _hex_digest(event['effects']))
    if event.get('kind') == 'publication':
        sequence = event.get('prepared_sequence')
        return (set(event) == {'kind', 'prepared_sequence', 'artifact'}
                and type(sequence) is int and 1 <= sequence <= len(prior)
                and prior[sequence - 1]['kind'] == 'prepared'
                and not any(old.get('prepared_sequence') == sequence for old in prior)
                and _hex_digest(event['artifact']))
    return False


@dataclass(frozen=True)
class PreparedRelease:
    sequence: int
    checkpoint: bytes
    effects_digest: bytes


class DisclosureHistory:
    """Single-server durable model; a real release needs all server barriers."""

    @classmethod
    def initialize_new_epoch(cls, path: Path, policy_id: bytes) -> 'DisclosureHistory':
        """Explicit research setup only; never restore an existing note this way."""
        policy_id = _digest(policy_id)
        path = Path(path)
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        connection = sqlite3.connect(str(path))
        genesis = hashlib.sha256(GENESIS_TAG + policy_id).digest()
        try:
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('CREATE TABLE metadata (policy BLOB NOT NULL, head BLOB NOT NULL)')
            connection.execute('CREATE TABLE events (sequence INTEGER PRIMARY KEY, payload BLOB NOT NULL, head BLOB NOT NULL)')
            connection.execute('INSERT INTO metadata VALUES (?, ?)', (policy_id, genesis))
            connection.commit()
        finally:
            connection.close()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return cls(path, policy_id, genesis)

    def __init__(self, path: Path, policy_id: bytes, expected_checkpoint: bytes):
        self.path = Path(path)
        self.policy_id = _digest(policy_id)
        self.checkpoint = _digest(expected_checkpoint)
        if not self.path.is_file() or self.path.is_symlink():
            raise Refused(REFUSAL)
        self._read()

    def _connect(self):
        # mode=rw prevents an absent history from becoming an empty new database.
        uri = 'file:' + quote(str(self.path.absolute()), safe='/') + '?mode=rw'
        connection = None
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=300)
            connection.execute('PRAGMA synchronous=FULL')
            return connection
        except sqlite3.Error as error:
            if connection is not None:
                connection.close()
            raise Refused(REFUSAL) from error

    def _read(self, connection=None) -> list[dict]:
        own = connection is None
        try:
            connection = connection or self._connect()
            metadata = connection.execute('SELECT policy, head FROM metadata').fetchall()
            if metadata != [(self.policy_id, self.checkpoint)]:
                raise Refused(REFUSAL)
            head = hashlib.sha256(GENESIS_TAG + self.policy_id).digest()
            events = []
            for expected_sequence, row in enumerate(connection.execute('SELECT sequence, payload, head FROM events ORDER BY sequence'), 1):
                sequence, payload, saved_head = row
                if sequence != expected_sequence:
                    raise Refused(REFUSAL)
                event = json.loads(payload)
                if _json(event) != payload or not _event_shape(event, events):
                    raise Refused(REFUSAL)
                head = hashlib.sha256(EVENT_TAG + head + payload).digest()
                if head != saved_head:
                    raise Refused(REFUSAL)
                events.append(event)
            if head != self.checkpoint:
                raise Refused(REFUSAL)
            return events
        except (sqlite3.Error, OSError, json.JSONDecodeError, TypeError, KeyError) as error:
            raise Refused(REFUSAL) from error
        finally:
            if own and connection is not None:
                connection.close()

    def _append(self, connection, event: dict, prior: list[dict]) -> tuple[int, bytes]:
        payload = _json(event)
        head = hashlib.sha256(EVENT_TAG + self.checkpoint + payload).digest()
        sequence = len(prior) + 1
        connection.execute('INSERT INTO events VALUES (?, ?, ?)', (sequence, payload, head))
        connection.execute('UPDATE metadata SET head = ?', (head,))
        connection.commit()  # FULL synchronous commit precedes release permission.
        self.checkpoint = head
        return sequence, head

    def prepare(self, members: tuple[bytes, ...], effects_digest: bytes) -> PreparedRelease:
        """Persist before any proof-related opening; equal-effects retries only."""
        if type(members) is not tuple or len(members) != WIDTH:
            raise Refused(REFUSAL)
        members = tuple(sorted(_digest(member) for member in members))
        if len(set(members)) != WIDTH or bytes(32) in members:
            raise Refused(REFUSAL)
        effects_digest = _digest(effects_digest)
        member_hex = [member.hex() for member in members]
        event = {'kind': 'prepared', 'members': member_hex,
                 'effects': effects_digest.hex()}
        connection = self._connect()
        try:
            connection.execute('BEGIN IMMEDIATE')
            prior = self._read(connection)
            for old in prior:
                if old['kind'] != 'prepared':
                    continue
                if set(old['members']) & set(member_hex):
                    if old['members'] != member_hex or old['effects'] != event['effects']:
                        raise Refused(REFUSAL)
            sequence, head = self._append(connection, event, prior)
            return PreparedRelease(sequence, head, effects_digest)
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def publish(self, ticket: PreparedRelease, effects: bytes, proof: bytes, emit) -> None:
        """Release model bytes after prepare; callback failure leaves them pinned.

        A final proof is unavailable before its own interactive openings. The
        earlier barrier therefore pins effects, never an as-yet-unknown proof
        hash. Only this model framing is checked here, not a financial proof.
        """
        if (type(ticket) is not PreparedRelease or type(ticket.sequence) is not int
                or ticket.sequence < 1 or type(effects) is not bytes
                or type(proof) is not bytes or not proof):
            raise Refused(REFUSAL)
        artifact = b'KPBMOD01' + len(effects).to_bytes(8, 'little') + effects + len(proof).to_bytes(8, 'little') + proof
        connection = self._connect()
        try:
            connection.execute('BEGIN IMMEDIATE')
            prior = self._read(connection)
            if ticket.sequence > len(prior):
                raise Refused(REFUSAL)
            prepared = prior[ticket.sequence - 1]
            row = connection.execute('SELECT head FROM events WHERE sequence = ?', (ticket.sequence,)).fetchone()
            if (prepared['kind'] != 'prepared' or row != (ticket.checkpoint,)
                    or hashlib.sha256(effects).digest() != ticket.effects_digest
                    or prepared['effects'] != ticket.effects_digest.hex()
                    or any(event.get('prepared_sequence') == ticket.sequence for event in prior)):
                raise Refused(REFUSAL)
            event = {'kind': 'publication', 'prepared_sequence': ticket.sequence,
                     'artifact': hashlib.sha256(artifact).hexdigest()}
            self._append(connection, event, prior)
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        emit(artifact)
