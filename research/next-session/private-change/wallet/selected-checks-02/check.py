"""Public selected-source wiring only; no owner/proving inputs exist here."""
import json
from pathlib import Path
import sys
sys.path.insert(0,'/app/poc/private-change-wallet')
import change_wallet as wallet
wallet.selected(True)
for name in ('/backup.json','/public-params.bin','/own-prover','/native-helper','/recipient.invoice'):
    assert not Path(name).exists(),name
try:
    wallet.network_replay({}, {}, {}, Path('/out/invalid-network-input'))
except ValueError as error:
    assert str(error)=='private-network-descriptor-fields',str(error)
else:
    raise AssertionError('empty public descriptor accepted')
print(json.dumps({'schema':'kpx3-private-change-selected-wiring/v1','passed':True,
 'concrete_owner_software_constants_selected':True,
 'full_network_source_and_installed_software_gate_passed':True,
 'empty_descriptor_rejected_after_authenticated_import':True,
 'backup_public_pk_owner_prover_cashout_helper_invoice_mounted':False,
 'actual_sdk_native_vm_proof_rpc_or_owner_input_used':False},sort_keys=True))
