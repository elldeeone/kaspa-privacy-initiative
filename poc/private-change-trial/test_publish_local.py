"""Public synthetic field-canaries; not proof/native/body validity tests."""
import copy
import unittest

from publish_local import canary_public_types


class Publication(unittest.TestCase):
    def values(self):
        script='0000aa20'+'11'*32+'87'
        body={'version':1,'id':'22'*32,'lockTime':0,'gas':0,'subnetworkId':'00'*20,
            'payload':'00'*4400,'mass':0,'inputs':[{'previousOutpoint':{'transactionId':'33'*32,'index':0},
            'signatureScript':'00'*24616,'sequence':(1<<64)-1,'computeBudget':1600}],
            'outputs':[{'value':981_000_000,'scriptPublicKey':script,'covenant':None}]}
        context=[{'amount_sompi':'1000000000','script_public_key':script,
                  'block_daa_score':'0','is_coinbase':False,'covenant_id':None}]
        engine={'accepted':True,'allowed_script_units':16_009_999,'input_index':0,'units':14_900_000}
        native={'Full':{'accepted':True,'fee_sompi':19_000_000},'ScriptEngine':engine,
                'all_input_engines_accepted':True,'isolation':'PASS','per_input_ScriptEngine':[engine]}
        return body,context,native

    def test_typed_public_projection(self):canary_public_types(*self.values())

    def test_nested_private_canaries_rejected(self):
        for mutation in (
            lambda b,c,n:b['inputs'][0].update(private_seed_hex32='aa'*32),
            lambda b,c,n:b['outputs'][0].update(private_receipt='canary'),
            lambda b,c,n:c[0].update(private_witness_path='/private/canary'),
            lambda b,c,n:n['Full'].update(private_owner_map='canary')):
            values=copy.deepcopy(self.values());mutation(*values)
            with self.assertRaises(ValueError):canary_public_types(*values)

    def test_nonhex_payload_rejected_before_public_writes(self):
        body,contexts,native=self.values();body['payload']='PRIVATE_CANARY'
        with self.assertRaises(ValueError):canary_public_types(body,contexts,native)


if __name__=='__main__':unittest.main()
