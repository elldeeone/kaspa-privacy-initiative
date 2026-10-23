"""Owner-authenticated release selection; unselected build halts before seed.

Root fills the new-trial constants only after fresh parameter/source review and
the final cold-client build. Neither a request nor a node can override them.
"""
CRYPTO_SHA256 = '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'
# ADR0054 ordinary-runtime public replay, separately source/artifact reviewed.
NETWORK_REPLAY_SHA256 = '00e034780c059febd92166148829ac7c15f27a3395d06df055ccc9c82a2ce0df'
NETWORK_SOURCE_FREEZE_SHA256 = '19dffcaa74e4f45ac681bbfbb26e8b42783467f4348cd1fd6e20ae9eab83e207'
NETWORK_SOURCE_FREEZE_RELATIVE_PATH = 'research/next-session/private-service-loss/network/ORDINARY-NETWORK-SOURCE-FREEZE-01.json'
NATIVE_SHA256 = 'f6139cea85a30f092447efe199796f62c540b0399d63e949845423678d4bdc44'
PROVER_SHA256 = '870e61f60d002900bfc39dfad5fbdb8e54319ec083072618b027c297d94477aa'
PARAMETER_MANIFEST_SHA256 = '008689b84cd171187cc75d32402dbf13d6d4e3ed149d3349ecfbc418bfcaad54'
DOMAIN_HEX32 = 'caf85e3b34cd9b426559f57bb1ab647835c5dfaf255d17bf3d1291c0f7408470'
VK_SHA256 = 'a82c94918d93008160ea9af4b709b05ce41ed5fe6e4b85d66d0fb310b02d94f5'
COMPILED_BUILD_IDENTITY_SHA256 = 'b2845ba58f2a895abbfddbbb43300e06fb528811b4bc5d3d0f7e1843c6491a43'
