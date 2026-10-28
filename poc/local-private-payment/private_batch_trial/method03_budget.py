"""One METHOD03 vector per admitted identity; source-only and unselected.

No Original, view, prediction, salt or truth body is read here. The selected
launcher must supply facts from its actual fresh bootstrap and actual completed
view roles. Dict fields, PIDs and hashes do not themselves prove that provenance.

Production reservation refuses until Root selects an identity policy AND the
metadata identity of the fixed, pre-created registry. There is no initializer,
reset, resume, caller registry path or cleanup of consumed reservations.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid


REGISTRY_ROOT = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/diagnostics/method03-original-budgets')
SELECTED_IDENTITY_POLICY = 'UNSELECTED'
REGISTRY_ADMISSION = None  # Root-selected (st_dev, st_ino), never a caller value.
FUNDING_POLICY = 'FROZEN_PROFILE_FUNDING_SPK_V1'
DOMAIN = 'a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0'
PROFILE = 'ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700'
PHASE = 'private-exit-route-03'
VIEW_KINDS = {'GLOBAL_UNION': 'coverage', 'PRIMARY': 'prediction', 'TERMINAL_CONTACT': 'coverage'}
FORBIDDEN_METHOD02_FUNDING = frozenset((
    '0000202476e299be2cf2f26118689aa6e38e6a2c0a498209f5950324f31c7cd2162c02ac',
    '000020127ebbbd41bf34e11e54998cf6d6fca6745f5d9c92126ee581096d17ed0fadf6ac',
    '0000207e874b39b14270c134bcf034679a28b65da367192adf5cb9136f1400067f4efaac',
))
_ISSUER = object()


class BudgetRefusal(ValueError):
    pass


def _need(value, category):
    if not value:
        raise BudgetRefusal(category)


def _fields(value, names, category):
    _need(type(value) is dict and set(value) == set(names), category)


def _hex(value, count, category):
    _need(type(value) is str and re.fullmatch('[0-9a-f]{' + str(2 * count) + '}', value) is not None,
          category)
    return value


def _uuid(value, category):
    _need(type(value) is str, category)
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise BudgetRefusal(category) from error
    _need(str(parsed) == value, category)


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def _digest(value):
    return hashlib.sha256(_encoded(value)).hexdigest()


def _binding(value):
    _fields(value, ('method_sha256', 'selection_sha256', 'trial_id', 'phase', 'attempt_id'), 'binding-fields')
    _hex(value['method_sha256'], 32, 'method-hash')
    _hex(value['selection_sha256'], 32, 'selection-hash')
    _uuid(value['trial_id'], 'trial-id')
    _uuid(value['attempt_id'], 'attempt-id')
    _need(value['phase'] == PHASE, 'fixed-method03-phase')


def _bootstrap(value):
    _fields(value, ('trial_id', 'trial_sha256', 'selection_sha256', 'generator_sha256', 'worker_sha256'),
            'bootstrap-reference-fields')
    _uuid(value['trial_id'], 'bootstrap-trial-id')
    for key in ('trial_sha256', 'selection_sha256', 'generator_sha256', 'worker_sha256'):
        _hex(value[key], 32, 'bootstrap-' + key)


def _owners(value):
    _need(type(value) is list and len(value) == 3, 'exactly-three-owner-identities')
    for slot, row in enumerate(value):
        _fields(row, ('owner_component', 'funding_spk_hex36', 'initial_public_sha256'), 'owner-identity-fields')
        _need(type(row['owner_component']) is int and row['owner_component'] == slot, 'canonical-owner-order')
        spk = _hex(row['funding_spk_hex36'], 36, 'public-funding-script')
        _need(spk.startswith('000020') and spk.endswith('ac'), 'funding-script-shape')
        _need(spk not in FORBIDDEN_METHOD02_FUNDING, 'method02-identity-forbidden')
        _hex(row['initial_public_sha256'], 32, 'initial-public-hash')
    _need(len({row['funding_spk_hex36'] for row in value}) == 3, 'distinct-owner-identities')


def validate_spec(spec, bootstrap_public_facts=None):
    """Strict pure validation; it performs no I/O and grants no intake authority.

    Funding scripts are profile-dependent in KPBKDF01. The supported candidate
    policy only identifies aliases in this exact frozen profile; it is NOT a
    universal cross-profile Original identity. Root has not selected it yet.
    """
    _fields(spec, ('schema', 'binding', 'identity_policy', 'profile_id_hex32', 'domain_hex32',
                  'source_sha256', 'slot_grammar_sha256', 'selected_view_labels', 'bootstrap', 'owners'),
            'budget-spec-fields')
    _need(spec['schema'] == 'kpb-method03-budget-spec/v1', 'budget-spec-schema')
    _binding(spec['binding'])
    _need(spec['identity_policy'] in ('UNSELECTED', FUNDING_POLICY), 'explicit-supported-identity-policy')
    _need(spec['profile_id_hex32'] == PROFILE and spec['domain_hex32'] == DOMAIN, 'frozen-profile-domain')
    _hex(spec['source_sha256'], 32, 'source-hash')
    _hex(spec['slot_grammar_sha256'], 32, 'public-pre-intake-slot-grammar-hash')
    labels = spec['selected_view_labels']
    _need(type(labels) is list and labels == sorted(VIEW_KINDS), 'exact-primary-and-two-coverage-labels')
    _bootstrap(spec['bootstrap'])
    _owners(spec['owners'])
    if bootstrap_public_facts is not None:
        facts = bootstrap_public_facts
        _fields(facts, ('schema', 'bootstrap', 'profile_id_hex32', 'domain_hex32', 'owners'), 'bootstrap-fact-fields')
        _need(facts['schema'] == 'kpb-method03-bootstrap-budget-facts/v1', 'bootstrap-fact-schema')
        _bootstrap(facts['bootstrap'])
        _owners(facts['owners'])
        _need(facts['bootstrap'] == spec['bootstrap'] and facts['owners'] == spec['owners']
              and facts['profile_id_hex32'] == PROFILE and facts['domain_hex32'] == DOMAIN,
              'same-selected-bootstrap-identities')
    # Detach caller-owned mutable containers before storing or issuing a claim.
    return json.loads(_encoded(spec))


def _identity_key(row):
    # No method, profile, domain, trial, attempt, label, source or output path is
    # a registry namespace. Profile changes are refused by the frozen policy.
    return hashlib.sha256(b'KPBM3BUD1' + bytes.fromhex(row['funding_spk_hex36'])).hexdigest()


def _meta(info):
    return tuple(getattr(info, name) for name in
                 ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink', 'st_uid', 'st_mode'))


def _open_registry():
    _need(SELECTED_IDENTITY_POLICY == FUNDING_POLICY and REGISTRY_ADMISSION is not None,
          'budget-policy-and-registry-unselected')
    path = REGISTRY_ROOT
    _need(path.is_absolute() and '..' not in path.parts
          and not any(part.is_symlink() for part in (path, *path.parents)), 'fixed-registry-no-alias')
    # Missing/replaced storage is a refusal; reserve never silently initializes it.
    info = path.lstat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o700
          and (info.st_dev, info.st_ino) == REGISTRY_ADMISSION, 'selected-global-registry-identity')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _need(_meta(os.fstat(fd)) == _meta(info) == _meta(path.lstat()), 'registry-open-race')
    except BaseException:
        os.close(fd)
        raise
    return fd


def _open_claim(registry_fd, key, expected=None):
    info = os.stat(key, dir_fd=registry_fd, follow_symlinks=False)
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o700, 'owned-single-claim-directory')
    if expected is not None:
        _need((info.st_dev, info.st_ino) == expected, 'same-claim-directory')
    fd = os.open(key, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=registry_fd)
    try:
        _need((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (info.st_dev, info.st_ino), 'claim-open-race')
    except BaseException:
        os.close(fd)
        raise
    return fd


def _write_metadata(directory_fd, name, value):
    raw = _encoded(value)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o400, dir_fd=directory_fd)
    try:
        remaining = memoryview(raw)
        while remaining:
            count = os.write(fd, remaining)
            _need(count > 0, 'metadata-write-progress')
            remaining = remaining[count:]
        os.fsync(fd)
        info = os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
              and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o400,
              'owned-metadata-file')
    finally:
        os.close(fd)
    os.fsync(directory_fd)
    return {'name': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'metadata': _meta(info)}


class BudgetClaim:
    __slots__ = ('_issuer', '_spec', '_keys', '_directories', '_records', '_ready_ns', '_barrier',
                 '_view_intakes', '_truth_refs', '_truth_times')

    def __init__(self, issuer, spec, keys, directories, records):
        _need(issuer is _ISSUER, 'claim-only-from-durable-reserve')
        self._issuer = issuer
        self._spec = spec
        self._keys = keys
        self._directories = directories
        self._records = records
        self._ready_ns = time.monotonic_ns()
        self._barrier = None
        self._view_intakes = {}
        self._truth_refs = {}
        self._truth_times = {}

    def __reduce__(self):
        raise TypeError('budget claims cannot be serialized or restored')


class SealedViewsBarrier:
    __slots__ = ('_issuer', '_claim', '_refs', '_digest', '_universe_sha256')

    def __init__(self, issuer, claim, refs, digest, universe_sha256):
        _need(issuer is _ISSUER, 'barrier-only-from-durable-all-view-marker')
        self._issuer, self._claim, self._refs, self._digest = issuer, claim, refs, digest
        self._universe_sha256 = universe_sha256

    def __reduce__(self):
        raise TypeError('view barriers cannot be serialized or restored')


def _require_claim(claim):
    _need(type(claim) is BudgetClaim and claim._issuer is _ISSUER, 'actual-in-memory-budget-claim')


def reserve(spec, bootstrap_public_facts):
    """Durably consume all three identities BEFORE any METHOD03 private intake.

    A failed/partial attempt retains every directory already created. Existing
    entries are never body-read, reopened or removed. The selected registry must
    be trusted persistent state outside backup/output trees, not rolled back by
    the storage operator. Loss/replacement of its selected identity fails closed.
    """
    _need(bootstrap_public_facts is not None, 'bootstrap-facts-required-before-reservation')
    selected = validate_spec(spec, bootstrap_public_facts)
    _need(selected['identity_policy'] == SELECTED_IDENTITY_POLICY == FUNDING_POLICY,
          'budget-identity-policy-unselected')
    keys = tuple(_identity_key(row) for row in selected['owners'])
    directories = {}
    records = {}
    owners = {_identity_key(row): row for row in selected['owners']}
    registry = _open_registry()
    try:
        for key in sorted(keys):
            # mkdir has O_EXCL semantics. A pre-existing file, symlink, empty
            # directory or crash residue is consumed budget, never a reset cue.
            os.mkdir(key, mode=0o700, dir_fd=registry)
            os.fsync(registry)  # The tombstone precedes any returned capability.
            own = _open_claim(registry, key)
            try:
                info = os.fstat(own)
                directories[key] = (info.st_dev, info.st_ino)
                row = owners[key]
                records[key] = _write_metadata(own, 'reservation.json', {
                    'schema': 'kpb-method03-consumed-vector-budget/v1',
                    'identity_key': key, 'owner_component': row['owner_component'],
                    'funding_spk_hex36': row['funding_spk_hex36'],
                    'profile_id_hex32': selected['profile_id_hex32'], 'domain_hex32': selected['domain_hex32'],
                    'binding': selected['binding'], 'source_sha256': selected['source_sha256'],
                    'slot_grammar_sha256': selected['slot_grammar_sha256'], 'bootstrap': selected['bootstrap'],
                    'initial_public_sha256': row['initial_public_sha256'], 'spec_sha256': _digest(selected),
                })
            finally:
                os.close(own)
    finally:
        os.close(registry)
    return BudgetClaim(_ISSUER, selected, keys, directories, records)


def _checked_marker_ref(claim, key, ref):
    """Metadata only; its SHA was calculated from public bytes at creation."""
    registry = _open_registry()
    try:
        own = _open_claim(registry, key, claim._directories[key])
        try:
            info = os.stat(ref['name'], dir_fd=own, follow_symlinks=False)
            _need(_meta(info) == ref['metadata'], 'same-budget-metadata-leaf')
        finally:
            os.close(own)
    finally:
        os.close(registry)
    return {'path': str(REGISTRY_ROOT / key / ref['name']), 'sha256': ref['sha256'],
            'metadata': list(ref['metadata'])}


def reservation_refs(claim):
    """One public record ref per owner; caller never reads protected bodies.

    The generation worker checks this record/config before loading its one
    Original, then derives invoice0xffffffff under frozenD/Profile and compares
    its actual funding SPK before constructing any METHOD03 invoice/note.
    """
    _require_claim(claim)
    return [dict(_checked_marker_ref(claim, key, claim._records[key]),
                 owner_component=slot, identity_key=key)
            for slot, key in enumerate(claim._keys)]


def owner_record_ref(claim, owner_component):
    """One issued owner's at-write public reference, with fresh metadata only."""
    _require_claim(claim)
    _need(type(owner_component) is int and owner_component in (0, 1, 2),
          'one-owner-record-component')
    key = claim._keys[owner_component]
    return dict(_checked_marker_ref(claim, key, claim._records[key]),
                owner_component=owner_component, identity_key=key)


def describe_claim(claim):
    """Detached public spec metadata and refs; never open a protected body.

    This is evidence about an actual in-memory issued claim, not a portable
    authority. The selected generator calls it before constructing owner roles;
    each owner separately checks its record against its derived funding SPK.
    """
    _require_claim(claim)
    spec = claim._spec
    value = {'schema': 'kpb-method03-issued-budget-description/v1',
             'binding': spec['binding'], 'spec_sha256': _digest(spec),
             'source_sha256': spec['source_sha256'],
             'slot_grammar_sha256': spec['slot_grammar_sha256'],
             'profile_id_hex32': spec['profile_id_hex32'], 'domain_hex32': spec['domain_hex32'],
             'identity_policy': spec['identity_policy'],
             'selected_view_labels': spec['selected_view_labels'],
             'bootstrap': spec['bootstrap'], 'owners': spec['owners'],
             'owner_record_refs': reservation_refs(claim)}
    return json.loads(_encoded(value))


def _permit(claim, operation, label, kind, owner_component=None, barrier=None):
    return {'schema': 'kpb-method03-budget-permit/v1', 'operation': operation,
            'label': label, 'kind': kind, 'owner_component': owner_component,
            'binding': claim._spec['binding'], 'source_sha256': claim._spec['source_sha256'],
            'slot_grammar_sha256': claim._spec['slot_grammar_sha256'],
            'spec_sha256': _digest(claim._spec), 'reservation_keys': list(claim._keys),
            'actual_unlabelled_universe_sha256': None if barrier is None else barrier._universe_sha256,
            'all_seals_sha256': None if barrier is None else barrier._digest}


def _write_all(claim, name, value):
    refs = {}
    registry = _open_registry()
    try:
        for key in sorted(claim._keys):
            own = _open_claim(registry, key, claim._directories[key])
            try:
                refs[key] = _write_metadata(own, name, value)
            finally:
                os.close(own)
    finally:
        os.close(registry)
    return refs


def claim_view_intake_once(claim, label):
    """Durable one-shot permit before private /state or capsule mount/read."""
    _require_claim(claim)
    _need(type(label) is str and label in VIEW_KINDS and claim._barrier is None,
          'selected-view-before-sealing')
    refs = _write_all(claim, 'view-' + label + '-intake.json',
                      _permit(claim, 'observe-view', label, VIEW_KINDS[label]))
    claim._view_intakes[label] = (refs, time.monotonic_ns())
    return _checked_marker_ref(claim, claim._keys[0], refs[claim._keys[0]])


def _public_ref(value, category):
    _fields(value, ('path', 'sha256'), category)
    path = value['path']
    _need(type(path) is str and Path(path).is_absolute() and '..' not in Path(path).parts
          and str(Path(path)) == path, category + '-path')
    _hex(value['sha256'], 32, category + '-hash')


def _completed_views(claim, refs):
    spec = claim._spec
    _need(type(refs) is list and len(refs) == len(spec['selected_view_labels']), 'all-selected-view-completions')
    now = time.monotonic_ns()
    labels = []
    for ref in refs:
        _fields(ref, ('label', 'kind', 'binding', 'source_sha256', 'public_plan_sha256',
                      'slot_grammar_sha256', 'actual_unlabelled_universe_sha256',
                      'salted_public_seal', 'salted_commitment_sha256', 'completion'), 'sealed-view-ref-fields')
        labels.append(ref['label'])
        _need(type(ref['label']) is str and ref['label'] in VIEW_KINDS
              and ref['kind'] == VIEW_KINDS[ref['label']], 'selected-prediction-or-coverage-kind')
        _binding(ref['binding'])
        _need(ref['binding'] == spec['binding'] and ref['source_sha256'] == spec['source_sha256']
              and ref['slot_grammar_sha256'] == spec['slot_grammar_sha256'], 'same-view-binding-source-grammar')
        _hex(ref['actual_unlabelled_universe_sha256'], 32, 'actual-postcapture-public-universe-hash')
        _hex(ref['public_plan_sha256'], 32, 'public-view-plan-hash')
        _public_ref(ref['salted_public_seal'], 'salted-public-seal')
        _hex(ref['salted_commitment_sha256'], 32, 'salted-private-capsule-hash')
        completion = ref['completion']
        _fields(completion, ('observed_launcher_pid', 'returncode', 'completed_monotonic_ns', 'event_ref'),
                'view-completion-fields')
        _need(type(completion['observed_launcher_pid']) is int and completion['observed_launcher_pid'] > 0
              and type(completion['returncode']) is int and completion['returncode'] == 0
              and type(completion['completed_monotonic_ns']) is int
              and claim._view_intakes[ref['label']][1] <= completion['completed_monotonic_ns'] <= now,
              'observed-completion-after-reserve-before-barrier')
        _public_ref(completion['event_ref'], 'public-completion-event')
    _need(labels == spec['selected_view_labels'], 'exact-selected-view-labels')
    _need(len({ref['actual_unlabelled_universe_sha256'] for ref in refs}) == 1,
          'same-actual-postcapture-unlabelled-universe')
    # Only salted capsule and public metadata commitments are accepted. Raw
    # observation/prediction hashes, models, masks, arrival IDs and salts fail
    # the exact schema. The closed producer must actually generate the salt.
    return json.loads(_encoded(refs))


def mark_views_sealed(claim, completed_view_refs):
    """Record all actual completions before truth; refs are not temporal proof.

    The selected launcher must have waited for those exact roles, admitted the
    public seals, and kept a fresh high-entropy salt inside every private capsule.
    This function never reads a private capsule or manufactures that provenance.
    """
    _require_claim(claim)
    _need(claim._barrier is None, 'view-barrier-one-shot')
    _need(set(claim._view_intakes) == set(VIEW_KINDS), 'all-three-view-intakes-consumed')
    for label, (intake_refs, _created_ns) in claim._view_intakes.items():
        for key in claim._keys:
            _checked_marker_ref(claim, key, intake_refs[key])
    refs = _completed_views(claim, completed_view_refs)
    value = {'schema': 'kpb-method03-all-selected-views-sealed/v2',
             'binding': claim._spec['binding'], 'source_sha256': claim._spec['source_sha256'],
             'slot_grammar_sha256': claim._spec['slot_grammar_sha256'],
             'actual_unlabelled_universe_sha256': refs[0]['actual_unlabelled_universe_sha256'],
             'completed_view_refs': refs}
    digest = _digest(value)
    file_refs = {}
    registry = _open_registry()
    try:
        for key in sorted(claim._keys):
            own = _open_claim(registry, key, claim._directories[key])
            try:
                file_refs[key] = _write_metadata(own, 'views-sealed.json', value)
            finally:
                os.close(own)
    finally:
        os.close(registry)
    barrier = SealedViewsBarrier(_ISSUER, claim, file_refs, digest,
                                 refs[0]['actual_unlabelled_universe_sha256'])
    claim._barrier = barrier
    return barrier


def barrier_ref(claim, barrier):
    _require_claim(claim)
    _need(type(barrier) is SealedViewsBarrier and barrier is claim._barrier
          and barrier._issuer is _ISSUER and barrier._claim is claim, 'actual-all-view-barrier')
    for key in claim._keys:
        _checked_marker_ref(claim, key, barrier._refs[key])
    return _checked_marker_ref(claim, claim._keys[0], barrier._refs[claim._keys[0]])


def claim_truth_once(claim, barrier, owner_component):
    """Selected launcher calls this immediately BEFORE each owner's truth mount.

    The returned public reference is evidence, not a portable accepted:true
    ticket. The selected launcher must invoke this stateful path for every mount.
    No direct mount or replay path is implemented here.
    """
    _require_claim(claim)
    _need(type(barrier) is SealedViewsBarrier and barrier._issuer is _ISSUER
          and barrier is claim._barrier and barrier._claim is claim, 'actual-all-view-barrier')
    _need(type(owner_component) is int and owner_component in (0, 1, 2), 'one-owner-truth-component')
    registry = _open_registry()
    try:
        for key in sorted(claim._keys):
            own = _open_claim(registry, key, claim._directories[key])
            try:
                expected = barrier._refs[key]
                info = os.stat(expected['name'], dir_fd=own, follow_symlinks=False)
                _need(_meta(info) == expected['metadata'], 'same-durable-all-view-marker')
            finally:
                os.close(own)
        key = claim._keys[owner_component]
        own = _open_claim(registry, key, claim._directories[key])
        try:
            ref = _write_metadata(own, 'truth-' + str(owner_component) + '.json',
                                  _permit(claim, 'score-owner', 'PRIMARY', 'score', owner_component, barrier))
        finally:
            os.close(own)
    finally:
        os.close(registry)
    claim._truth_refs[owner_component] = ref
    claim._truth_times[owner_component] = time.monotonic_ns()
    return dict(_checked_marker_ref(claim, key, ref), owner_component=owner_component)


def claim_aggregate_once(claim, barrier, completed_score_refs):
    """One closed aggregate intake, after all three actual owner scores finish.

    Refs contain public completion metadata only. Actual scoring and private
    mask/capsule identity remain the selected launcher's/closed aggregate's job.
    """
    barrier_ref(claim, barrier)
    _need(set(claim._truth_refs) == {0, 1, 2}, 'all-owner-truth-intakes-consumed')
    _need(type(completed_score_refs) is list and len(completed_score_refs) == 3, 'three-completed-owner-scores')
    now = time.monotonic_ns()
    for owner, ref in enumerate(completed_score_refs):
        _fields(ref, ('owner_component', 'binding', 'source_sha256', 'slot_grammar_sha256',
                      'actual_unlabelled_universe_sha256', 'completion'), 'score-completion-ref-fields')
        _need(type(ref['owner_component']) is int and ref['owner_component'] == owner
              and ref['binding'] == claim._spec['binding'] and ref['source_sha256'] == claim._spec['source_sha256']
              and ref['slot_grammar_sha256'] == claim._spec['slot_grammar_sha256']
              and ref['actual_unlabelled_universe_sha256'] == barrier._universe_sha256,
              'same-owner-score-binding-and-universe')
        completion = ref['completion']
        _fields(completion, ('observed_launcher_pid', 'returncode', 'completed_monotonic_ns', 'event_ref'),
                'score-completion-fields')
        _need(type(completion['observed_launcher_pid']) is int and completion['observed_launcher_pid'] > 0
              and type(completion['returncode']) is int and completion['returncode'] == 0
              and type(completion['completed_monotonic_ns']) is int
              and claim._truth_times[owner] <= completion['completed_monotonic_ns'] <= now,
              'actual-score-completion-after-truth-intake')
        _public_ref(completion['event_ref'], 'public-score-completion-event')
        _checked_marker_ref(claim, claim._keys[owner], claim._truth_refs[owner])
    refs = _write_all(claim, 'aggregate-intake.json', _permit(claim, 'aggregate', 'PRIMARY', 'aggregate', barrier=barrier))
    return _checked_marker_ref(claim, claim._keys[0], refs[claim._keys[0]])
