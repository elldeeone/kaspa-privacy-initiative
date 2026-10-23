#!/usr/bin/env python3
"""Select only the two actual public prefix acceptance records; never read secrets."""
import argparse
import hashlib
import json
from pathlib import Path

import funding_packet as funding

ROOT = funding.ROOT
SOURCE = Path('/home/luke/projects/kpi-intensive-2026-10-22/private-service-loss-tn10-01/live-prefix-01')
CLOSED = ROOT / 'research/next-session/private-service-loss/trial/local-public-01'
STAGES = (
    ('founding', '006d46b0fabbf551a50186d9e9edf2f873f39ba0d871342c3dd254c1b4a4fbbf',
     'e10feaf59bb56d6e46ad4ac654b6126b73df2cb1b3f31d3a2443ed077264b634', 604176575, 1411200),
    ('payment', '16c8a7d82f10eeac0d3da4609c518ade73f7da3294ec26e91cb1ae1b47486fd5',
     '7004aed3e69e5ee17ff7240a18340627e23360fc7ae42d46e11d5822b7ef7221', 604180733, 18958700))


def checked(value, body, context, expected_daa, txid, exporter):
    funding.need(value['transaction_id'] == txid and value['accepted_body'] == exporter.canonical_body(body),
                 'exact-prefix-observed-body')
    sdk_raw = json.dumps(value['accepted_body'], separators=(',', ':'), ensure_ascii=False).encode()
    funding.need(value['accepted_body_sha256'] == funding.sha(sdk_raw), 'exact-prefix-SDK-body-hash')
    funding.need(value['post_query_related_spend_check'] is True, 'post-query-related-spend-required')
    expected = dict(context, outpoint=body['inputs'][0]['previousOutpoint'], block_daa_score=str(expected_daa))
    funding.need(len(body['inputs']) == 1 and value['accepted_input_contexts'] == [expected],
                 'actual-prefix-input-context')
    spent = value['spent_inputs']
    funding.need(len(spent) == 1 and spent[0]['outpoint'] == expected['outpoint']
                 and spent[0]['script_public_key'] == expected['script_public_key'], 'prefix-spent-query-binding')
    funding.need(len(value['current_outputs']) == len(body['outputs']), 'all-prefix-output-queries')
    for index, (row, output) in enumerate(zip(value['current_outputs'], body['outputs'])):
        point = {'transactionId': txid, 'index': index}
        funding.need(row['index'] == index and row['outpoint'] == point
                     and int(row['amount_sompi']) == int(output['value'])
                     and row['script_public_key'] == output['scriptPublicKey'], 'prefix-output-query-binding')
        entry = row['utxo']
        funding.need(entry is not None and entry['outpoint'] == point
                     and int(entry['amount_sompi']) == int(output['value'])
                     and entry['script_public_key'] == output['scriptPublicKey']
                     and entry['is_coinbase'] is False and entry['covenant_id'] is None,
                     'prefix-output-unspent-at-its-observation')
    return {key: val for key, val in value.items() if key != 'post_query_related_spend_check'}


def export(output):
    exporter = funding.base_exporter()
    funding.need(not any(path.is_symlink() for path in (output, *output.parents)) and not output.exists()
                 and output.resolve() != SOURCE.resolve() and SOURCE.resolve() not in output.resolve().parents,
                 'fresh-public-prefix-output')
    payloads, originals, rows = {}, {}, []
    previous_output = None
    for index, (name, txid, body_sha, daa, fee) in enumerate(STAGES):
        raw = exporter.safe_file(SOURCE, name + '-confirmed-observation.json').read_bytes()
        value = json.loads(raw)
        body_raw = exporter.safe_file(CLOSED, f'case-{index:04d}/transaction.json').read_bytes()
        funding.need(funding.sha(body_raw) == body_sha, 'closed-prefix-body-pin')
        body = json.loads(body_raw)
        context = json.loads(exporter.safe_file(CLOSED, f'case-{index:04d}/supplied-context.json').read_bytes())[0]
        plain = checked(value, body, context, daa, txid, exporter)
        if previous_output is not None:
            funding.need(value['accepted_input_contexts'][0] == previous_output, 'confirmed-prefix-DAA-link')
        else:
            funding.need(value['accepted_input_contexts'][0]['outpoint'] == {'transactionId': funding.TXID, 'index': 0},
                         'exact-confirmed-ordinary-funding-link')
        funding.need(int(context['amount_sompi']) - sum(int(row['value']) for row in body['outputs']) == fee,
                     'prefix-fee-reconciliation')
        selected = exporter.sanitize_observation(plain, funding.sha(raw), len(raw))
        selected['post_query_related_spend_check'] = True
        payloads[name + '-selected-observation.json'] = funding.encoded(selected)
        originals[name + '-confirmed-observation.json'] = {'sha256': funding.sha(raw), 'bytes': len(raw),
                                                          'bulk_pages_not_published': True}
        previous_output = value['current_outputs'][0]['utxo']
        rows.append({'transaction_id': txid, 'body_sha256': body_sha, 'input_block_daa_score': str(daa),
                     'fee_sompi': fee, 'confirmation_policy': value['confirmation_policy'],
                     'reserve_output_sompi': int(body['outputs'][0]['value']),
                     'all_outputs_unspent_at_own_observation': True})
    payloads['PREFIX-CLOSURE.json'] = funding.encoded({
        'schema': 'kpx3-private-prefix-observation-closure/v1', 'stages': rows,
        'final_prefix_reserve_sompi': 120000000, 'prefix_fee_sum_sompi': 20369900,
        'ordinary_change_sompi': 88630000, 'funding_source_sompi': 228999900,
        'original_observations': originals, 'assertions_are_observation_time_only': True,
        'adapter_selected_node_headers_are_not_independently_rehashed': True,
        'fresh_network_header_and_current_head_checks_are_separate': True,
        'cold_exit_or_privacy_qualification_claimed': False,
        'private_backup_profile_recipe_PK_witness_or_operator_exit_read': False,
        'rpc_native_proof_signing_broadcast_runs': 0})
    output.mkdir(parents=True)
    files = []
    for name, raw in sorted(payloads.items()):
        with (output / name).open('xb') as file:
            file.write(raw)
        files.append({'path': name, 'sha256': funding.sha(raw), 'bytes': len(raw)})
    manifest = {'schema': 'kpx3-prefix-observations-manifest/v1', 'files': files,
                'exporter_sha256': funding.sha(Path(__file__).read_bytes()),
                'funding_extractor_sha256': funding.sha(Path(funding.__file__).read_bytes())}
    with (output / 'MANIFEST.json').open('xb') as file:
        file.write(funding.encoded(manifest))
    return {'manifest_sha256': funding.sha((output / 'MANIFEST.json').read_bytes()), 'public_payloads': len(files)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('new_public_output', type=Path)
    args = parser.parse_args()
    print(json.dumps(export(args.new_public_output), sort_keys=True))
