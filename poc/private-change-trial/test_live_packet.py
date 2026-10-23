"""Pure projection/privacy controls; no native acceptance or network evidence."""
import copy
import hashlib
import json
import unittest

import live_packet as m


def sample():
    body={'version':1,'id':'11'*32,'inputs':[{'previousOutpoint':{'transactionId':'22'*32,'index':0},
        'signatureScript':'00'*66,'sequence':(1<<64)-1,'computeBudget':10}],
        'outputs':[{'value':100,'scriptPublicKey':'000020'+'33'*32+'ac','covenant':None}],
        'lockTime':0,'subnetworkId':'00'*20,'gas':0,'payload':'','mass':1}
    contexts=[{'amount_sompi':'200','script_public_key':'000020'+'44'*32+'ac','block_daa_score':'5',
        'is_coinbase':False,'covenant_id':None}]
    header={k:'00'*32 for k in ('acceptedIdMerkleRoot','hash','hashMerkleRoot','pruningPoint','utxoCommitment')}
    header.update(bits=1,blueScore='100',blueWork='1',daaScore='8',nonce='0',parentsByLevel={},timestamp='1',version=2)
    cb=m.canonical_body(body)
    policy={'accepting_blue_score':'100','actual_blue_score_distance':'21','comparison':'sinkBlueScore-acceptingBlueScore > min',
        'immutable_finality':False,'min_confirmation_count':20,'passes':True,'sink_blue_score':'121'}
    outpoint={'transactionId':body['id'],'index':0}
    entry={'outpoint':outpoint,'amount_sompi':'100','script_public_key':body['outputs'][0]['scriptPublicKey'],
        'block_daa_score':'8','is_coinbase':False,'covenant_id':None}
    obs={'transaction_id':body['id'],'accepted_body':cb,'accepted_body_sha256':hashlib.sha256(json.dumps(cb,separators=(',',':')).encode()).hexdigest(),
        'network':'testnet-10','expected_genesis':m.phase.GENESIS,'chain_delta_removed':[],
        'post_query_related_spend_check':True,'accepting_block_header':header,'confirmation_policy':policy,
        'accepted_input_contexts':[dict(contexts[0],outpoint=body['inputs'][0]['previousOutpoint'])],
        'spent_inputs':[{'outpoint':body['inputs'][0]['previousOutpoint'],'queried':True,'unspent':False,
            'script_public_key':contexts[0]['script_public_key']}],
        'current_outputs':[{'index':0,'outpoint':outpoint,'amount_sompi':'100','script_public_key':entry['script_public_key'],'utxo':entry}],
        'pages':[{'response':{'removedChainBlockHashes':[],'addedChainBlockHashes':[header['hash']],
            'chainBlockAcceptedTransactions':[{'chainBlockHeader':header,'acceptedTransactions':[cb]}]}}],
        'start_hash':'55'*32,'observed_sink':'66'*32,'final_cursor':'77'*32,'virtual_daa_score':'30'}
    return body,contexts,obs


class Controls(unittest.TestCase):
    def test_exact_selected_only_no_unrelated_pages_or_diagnostics(self):
        body,contexts,obs=sample();obs['pages'][0]['response']['chainBlockAcceptedTransactions'][0]['acceptedTransactions'].append(
            {'id':'88'*32,'private_canary':'DO_NOT_EXPORT'})
        obs['unselected_diagnostic']='/private/owner/path'
        result=m.observation(obs,body,contexts)
        raw=json.dumps(result)
        self.assertNotIn('DO_NOT_EXPORT',raw);self.assertNotIn('/private/owner/path',raw);self.assertNotIn('pages',result)
        self.assertEqual(result['accepted_body'],m.canonical_body(body))

    def test_nested_body_canary_rejected(self):
        body,_,_=sample();body['outputs'][0]['private_canary']='DO_NOT_EXPORT'
        with self.assertRaises(ValueError):m.body_types(body)

    def test_nested_observation_canaries_rejected(self):
        for field in ('accepting_block_header','current_outputs'):
            body,contexts,obs=sample()
            if field=='accepting_block_header':obs[field]['private_canary']='DO_NOT_EXPORT'
            else:obs[field][0]['utxo']['private_canary']='DO_NOT_EXPORT'
            with self.assertRaises(ValueError):m.observation(obs,body,contexts)

    def test_unconfirmed_wrong_context_or_changed_body_rejected(self):
        for change in ('depth','context','body'):
            body,contexts,obs=sample()
            if change=='depth':obs['confirmation_policy']['passes']=False
            elif change=='context':obs['accepted_input_contexts'][0]['amount_sompi']='201'
            else:obs['accepted_body']['outputs'][0]['value']='99'
            with self.assertRaises(ValueError):m.observation(obs,body,contexts)

    def test_old_merge_marker_not_promoted(self):
        body,contexts,obs=sample();del obs['post_query_related_spend_check']
        with self.assertRaises(ValueError):m.observation(obs,body,contexts)
        self.assertFalse(m.observation(obs,body,contexts,False)['post_query_related_spend_check'])

    def test_native_nested_diagnostic_rejected(self):
        body,contexts,_=sample();engine={'accepted':True,'allowed_script_units':10,'input_index':0,'units':1}
        native={'Full':{'accepted':True,'fee_sompi':100},'ScriptEngine':engine,
            'per_input_ScriptEngine':[engine],'all_input_engines_accepted':True,'isolation':'PASS'}
        m.native_types(native,contexts,body);native['Full']['private_canary']='DO_NOT_EXPORT'
        with self.assertRaises(ValueError):m.native_types(native,contexts,body)


if __name__=='__main__':unittest.main()
