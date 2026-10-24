"""Root-selected NEW capacity/W identities; no request-selectable code/key."""
from pathlib import Path

DOMAIN = bytes.fromhex('d55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb')
WRAPPER_DOMAIN = bytes.fromhex('becdc8b30d3724ec79c773f0af662e3e25695b9d9a203d636fc3f6aef5c3b067')
IMAGE = bytes.fromhex('633b3244225320ddc029a7b3b18d76b5f579bed808bbaecff25a50341b76f7f4')
PROFILE_SHA = '492a0981ad04891ea68243f2c8221976f436501acf940e42211bb8773744fbdd'
PRESTATE_SHA = '82ae8087adf61fd65cf20a539d10f446ee31f0f224aec5fcd87b99f0d62a08be'
MANIFEST_SHA = 'd6f0e2bbafab39a72106ef0a0ebd6483362a858926117721a8be5aa37a459011'
PK_SHA = '6c518076ed6194d1f0e1925be6902182951ddf8f17347fe4aa8ec200a2a8fb11'
PK_BYTES = 1_307_894_256
VK_SHA = '074c06a5f21f46c7c87a948c8ca6a0896198cc9fc255b8d5e08cc01ceb73a987'
BUILD_SHA = 'fcf6e8c757613e6fea9a5dd776727f1c2456865f1185c545ac9751ef9fb26419'
PROVER_SHA = '4ef4fc4f6290bc1c5472e732e118476b6ad20b692438c0957e27cf3f6bc00621'
CODEC_SHA = '76cfc5cc381e503e5517864044fd9a66826864f2790154157e351bff08fd4ee1'
PROVER = Path('/home/luke/projects/kpi-intensive-2026-10-22/capacity-exit-selected-prover-01/prover')
CODEC = Path('/home/luke/projects/kpi-intensive-2026-10-22/shared-settlement-wallet-release-01/w-codec')
AGGREGATE_BUDGET = 1600
DIRECT_BUDGET = 1500  # Root-selected complete private-path bound; actual Full still required.
DIRECT_ACCEPTED_BUDGETS = (1500,)


def ready_expected():
    return {'event': 'parameters-ready', 'role': 'compact2', 'output_arity': 2,
            'domain_hex32': DOMAIN.hex(), 'parameter_manifest_sha256': MANIFEST_SHA,
            'vk_sha256': VK_SHA, 'compiled_build_identity_sha256': BUILD_SHA}
