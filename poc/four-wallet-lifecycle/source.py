"""Distinct supplied-local and verified accepted-network owner input paths."""
from compat import core
from contracts import chain
from local_source import replay_local
from paths import checked, regular, need


def input_paths(args):
    if args.source_kind == 'local':
        return (args.history,)
    need(args.source_kind == 'accepted', 'selected-public-source-kind')
    return args.descriptor, args.fetch


def page_paths(args, forbidden):
    """Called after all first-level public metadata has passed alias guards."""
    if args.source_kind == 'local':
        return ()
    path, _ = regular(args.fetch, forbidden)
    raw = path.read_bytes()
    pages = tuple(chain().bundle_public_files(raw, args.fetch_sha256, args.bundle_directory))
    # Metadata for ALL pages precedes the first page byte/hash/decompression.
    for path in pages:
        regular(path, forbidden)
    return pages


def replay_source(args, profile, runtime, output):
    if args.source_kind == 'local':
        return replay_local(checked(args.history).read_bytes(), args.history_sha256,
                            profile, runtime, output)
    p = core().primitives
    p.need(args.source_kind == 'accepted', 'selected-public-source-kind')
    descriptor = checked(args.descriptor).read_bytes()
    fetch = checked(args.fetch).read_bytes()
    result = chain().replay_bundle(descriptor, args.descriptor_sha256,
        fetch, args.fetch_sha256, profile, runtime, output, bundle_directory=args.bundle_directory)
    # The selected adapter has already checked the complete descriptor and its
    # external byte pin. Retain its trial identity for the owner backup check.
    return {**result, 'trial_id': p.parse(descriptor)['trial_id']}


def actual_daa(replayed, runtime):
    p = core().primitives
    context = replayed['head_context']
    p.need(replayed['point'] is not None and type(context) is dict
           and set(context) == {'amount_sompi', 'script_public_key', 'block_daa_score',
                                'is_coinbase', 'covenant_id'}, 'live-head-context-required')
    p.need(context['amount_sompi'] == str(replayed['reserve'])
           and context['script_public_key'] == core().native_runtime.p2sh(
               runtime.emit(replayed['snapshot'].state(runtime.profile.domain)))
           and context['is_coinbase'] is False and context['covenant_id'] is None,
           'exact-current-head-reserve-program-and-flags')
    raw = context['block_daa_score']
    p.need(type(raw) is str and raw and all('0' <= c <= '9' for c in raw)
           and str(int(raw)) == raw, 'canonical-DAA-decimal-boundary')
    return p.uint(int(raw), 64)
