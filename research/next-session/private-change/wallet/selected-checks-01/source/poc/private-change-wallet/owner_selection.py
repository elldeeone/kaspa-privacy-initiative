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
PROVER_SHA256 = '3252c28f2e3b08aa85aab5ff82dc3adf481dec84dbb9d5514e0fb69012250b43'
PARAMETER_MANIFEST_SHA256 = 'b440d08fddcdbbfb7d6b8355ab097a7bedd3fb85b8aa228f07070d4fcb3a91d0'
DOMAIN_HEX32 = 'bd9a7227d8f027f1fa1e284c2ff9af86fbce8722eca1e8e043b6d7b9a5cba4bc'
VK_SHA256 = 'dade8f90f1bec1c9b150f5eb126d73a1c8a1959ef1fb9da1178820debf693bae'
COMPILED_BUILD_IDENTITY_SHA256 = 'a26f7b4958168f26536b9fe90e30fa9abd030aa7fa8c04555022ad2c426b747d'
