#!/usr/bin/env python3
"""Trusted operator caller for reviewed helpers; no network submission method."""
import hashlib,json,sys,time
from pathlib import Path

def main():
    config_path,config_sha=sys.argv[1:]
    raw=Path(config_path).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==config_sha
    config=json.loads(raw)
    bootstrap=Path(config['bootstrap_root'])
    assert hashlib.sha256((bootstrap/'poc/owner-private-lifecycle/integration/closed_exits.py').read_bytes()).hexdigest()=='0a7adbd0472842735531a382316b538152d32faaa9f63b4d94db3c76f6bb1d7a'
    sys.path[:0]=[str(bootstrap/'poc/owner-private-lifecycle/integration'),str(bootstrap/'poc/owner-private-lifecycle/recovery')]
    from closed_exits import ClosedStageRunner,restore_clients,prepare_next,terminal_scans,retained_private_roots
    from campaign import confirmed,ExitSequence
    from codec import canonical_json,parse_json,sha
    from backend import write
    from public import need
    class ColdClientRunner(ClosedStageRunner):
        def initialize_directories(self):
            super().initialize_directories()
            # Generic stages precreate empty leaves; cold_owner.restore owns
            # their fresh creation. rmdir refuses any nonempty/private data.
            for index in range(3):
                for name in ('owner','mpc'):
                    (self.private/('party-%d'%index)/name).rmdir()
    runner=ColdClientRunner(config['private_base'],config['public_base'],retained_private_roots(),config['source_manifest'])
    runner.authenticate()
    control=Path(config['control_directory'])
    control.mkdir(parents=True,exist_ok=True,mode=0o700)
    def selected_json(pair):return parse_json(runner.ingress.read(*pair))
    def emit(name,value):
        write(control/(name+'.json'),canonical_json(value))
        print(canonical_json({'event':name,'record':str(control/(name+'.json'))}).decode(),flush=True)
    selection=selected_json(config['selection'])
    owners=selected_json(config['owners'])['owners']
    accepted=confirmed(runner,config['handoff'],trial_id=config['trial_id'],expected_txid=config['expected_transaction_id'],transition_count=2,tail_hex=config['tail_hex'],previous_history=config['previous_history'],prepared_projection=config['prepared_projection'])
    sequence=ExitSequence(accepted)
    # The observer supplies raw protocol bytes. This pure conversion uses the
    # same downloaded source as the independent closed native replay.
    software=Path(selection['software_root'])
    sys.path[:0]=[str(software/'poc/owner-private-lifecycle/chain'),str(software/'poc/owner-private-lifecycle/bootstrap')]
    import replay
    assert Path(replay.__file__).is_relative_to(software)
    restore_clients(runner,selection,owners,config['original_private'])
    emit('restores-complete',{'fresh_seed_only_clients':3,'client_associations_exported':False})
    original_inventory_hash=selection['software_inventory'][1]
    for ordinal in range(1,10):
        candidate=prepare_next(runner,sequence,selection,owners)
        emit('candidate-%02d'%ordinal,candidate)
        activation=control/('advance-%02d.json'%ordinal)
        while not activation.exists():
            if (control/'STOP').exists():raise RuntimeError('operator-stopped')
            time.sleep(1)
        step=parse_json(runner.ingress.refresh().policy.read(activation))
        need(step['schema']=='kpx8-live-exit-advance/v1' and step['ordinal']==ordinal and step['expected_transaction_id']==candidate['transaction_id'],'exact-external-next-prefix-activation')
        actual=confirmed(runner,step['handoff'],trial_id=config['trial_id'],expected_txid=candidate['transaction_id'],transition_count=2+ordinal,tail_hex=config['tail_hex'],previous_history=sequence.accepted['history_selector'],prepared_projection=candidate['projection'])
        fetch_selector=actual['handoff']['selectors']['fetch.json']
        fetched=selected_json([fetch_selector['path'],fetch_selector['sha256']])
        actual_case=replay.native_case(fetched['transactions'][-1])
        submitted=selected_json(candidate['case'])
        need(actual_case==submitted,'actual-accepted-CASE-matches-submitted-witness-budget-gas-and-entries')
        next_selection=selected_json(step['selection'])
        need(next_selection['software_inventory'][1]==original_inventory_hash,'unchanged-selected-static-software-inventory')
        # Transport paths may rebind to byte-identical HTTPS objects. Reviewed
        # cold_owner/cold_case independently authenticate every role/profile.
        sequence.advance(actual)
        selection=next_selection
        emit('confirmed-%02d'%ordinal,{'ordinal':ordinal,'transaction_id':candidate['transaction_id'],'reserve_sompi':actual['checkpoint']['reserve_sompi'],'exact_actual_CASE_including_witness_and_budget_matched':True})
    final=ColdClientRunner(config['terminal_private_base'],config['terminal_public_base'],retained_private_roots(),config['source_manifest'])
    restore_clients(final,selection,owners,config['original_private'])
    result=terminal_scans(final,sequence,selection,owners)
    emit('complete',result)

if __name__=='__main__':
    try:main()
    except Exception:
        # Detailed diagnostics belong only in the operator's private stream.
        import traceback
        traceback.print_exc(file=sys.stderr)
        raise SystemExit(2)
