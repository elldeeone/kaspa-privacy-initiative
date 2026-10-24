"""Read-only inspection of published components; no proof/sign/key operation."""
import argparse
import hashlib
import json
from pathlib import Path
from ledger import digest,canonical
from partitions import recover_public_partitions


def main(args):
    repo=Path(args.repo).resolve();path=Path(args.manifest).resolve();raw=path.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==args.manifest_sha256
    manifest=json.loads(raw)
    for item in manifest['files']:
        p=repo/item['path'];data=p.read_bytes()
        assert len(data)==item['bytes'] and hashlib.sha256(data).hexdigest()==item['sha256']
    components=[];rows=[]
    for index in (0,1):
        directory=path.parent/('owner-'+str(index));c=json.loads((directory/'COMPONENT.json').read_bytes());s=json.loads((directory/'SUCCESSOR.json').read_bytes())
        auth=bytes.fromhex(c['auth_hex528']);assert len(auth)==528
        mode=auth[300];start=int.from_bytes(auth[304:308],'little');assert mode==2
        deliveries={r['position']:r for r in s['snapshot']['deliveries']}
        outs=[{'position':p,'cm':deliveries[p]['cm_hex32'],'cipher':deliveries[p]['cipher_hex264']} for p in range(start,start+mode)]
        cm=b''.join(bytes.fromhex(o['cm']) for o in outs);cf=b''.join(bytes.fromhex(o['cipher']) for o in outs)
        assert hashlib.sha256(cm).digest()==auth[268:300] and hashlib.sha256(cf).digest()==auth[332:364]
        components.append({'component_id':'published-child-'+str(index),'ordered_outputs':outs,'public_output_digest':digest(outs)})
        rows.append({'component':str((directory/'COMPONENT.json').relative_to(repo)),'positions':[o['position'] for o in outs],
            'public_Auth_ordered_CM_digest_matches':True,'public_Auth_ordered_cipher_digest_matches':True,
            'packet_reports_genuine_child_proof_verified':s['genuine_child_proof_verified'],
            'packet_reports_actual_wrapper_or_chain_accepted':s['actual_wrapper_or_chain_accepted']})
    display=[o for c in components for o in c['ordered_outputs']][::-1]
    result=recover_public_partitions({'classification':'PUBLIC_COMPONENT_ENVELOPE_NOT_NATIVE_SETTLEMENT','components':components,'permuted_display':display})
    report={'schema':'independent-payment-published-component-inspection/v1','source_manifest_sha256':args.manifest_sha256,
        'inspections':rows,'recovered_components':result['public_partitions'],
        'observation_scope':'published child components / pre-aggregation coordinator; not an assertion about an uninspected final native W surface',
        'conditional_conclusion':'if original component arrays remain disclosed, their CM/CF partitions remain recoverable under a display permutation',
        'hidden_assignment_new_wrapper_not_evaluated':True,'proof_verification_rerun':False,'private_keys_or_witnesses_read':False,
        'third_party_privacy_score_computed':False,'privacy_qualification':False,'native_acceptance_claimed':False}
    Path(args.output).write_bytes(canonical(report));print(json.dumps({'public_components_inspected':2,'CM_and_CF_digests_matched':2,'private_material_read':False,'privacy_qualification':False}))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--repo',required=True);p.add_argument('--manifest',required=True);p.add_argument('--manifest-sha256',required=True);p.add_argument('--output',required=True);main(p.parse_args())
