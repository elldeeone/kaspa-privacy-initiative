#pragma once

// Exact source-owned authority candidate for retained unfunded trial-03.
// This file deliberately does not define selected_configuration() and cannot
// switch KPI_REGISTERED_FINANCIAL_CONFIGURED to 1. Acquisition/exporter specs,
// a concrete roster-pinned Player, a durable identity registry admission, and
// a separately reviewed activation header remain mandatory.
#include "registered_roster_transport.hpp"

namespace kpi::mpc::financial::registered_detail {

inline RegisteredRosterBinding trial03_authority_candidate() {
    return {
        "46c16c64-2ba3-4d69-89e0-c00bd3a1277b",
        history::unhex("77252d3ca1a4faffa3ee8e03706a93604e0909034cc274309c7ea2300c198401"),
        history::unhex("101b682fcd64f51ec4214ee5858f06f1adefa49f225be89b32a3318d71c8f92d"),
        history::unhex("520b0983849b7cd777c266a4d706994d804836fb1612610c5dd9ec16ab1fd672"),
        history::unhex("5bf83f9dc55264a7908337dafdf32c3f19c6ee74638b405b5d6d83c378818a5e"),
        history::unhex("b7b01ec85773ac19389441befed50a349fb9c21d9f438711bc8905cd8dec927f"),
        {
            history::unhex("c1f0a1c3500a850ff68d0e13b105de3621b11040e78a09ec79b838ff039bc556"),
            history::unhex("55d70d4f5611a57ccb197e17de498ab2871c7282944cbd7f2827de66abdfa9e8"),
            history::unhex("3bff49233fd98b71fc8121e57d059b590282b09fef7859768f5d280d8c475e8d")
        },
        history::unhex("a63868c1cbb8fad1e184833a60f8c2c67e8766ca605f78949738a87834c2595b"),
        history::unhex("f6fb3926efcf158fa5553a727a72b342f4af4da2daef061ea01427de832d1e16"),
        history::unhex("edc99f410e61aa1d1e391e71ad27c11e7a0d01b0b82dfc19fd76c72bcfb04979"),
        history::unhex("943c1c82e9990b5b9207714c1867a78a75381e8a891fc0a83c7c2c7b502292df"),
        history::unhex("7e90412697bd71b2e0e85c7a40d3c95933ab838809bf47b13013ef7d46ad9247"),
        history::unhex("22b7c027c7c51e892fc4d552cf3db0723e475acfe85f0b5b33452a1a21f8c9d4"),
        history::unhex("637d4a76ab40d72c8a49a8ad7f0d0113d76aa800a7e513fdec32463871ab8fdd"),
        history::unhex("a5a37ca8d7d52671156975898eb8d9b9fd6fb3a8f7287b85e64c73b373a948bb"),
        history::unhex("45e580b0e03969d3d92892e843a2542543ca14bbd15a161a70fc47b9c098d517"),
        history::unhex("f6ad556c12ffa97656b928df662ed61258d0a1f3e568bff294b0b6f1e77c964a"),
        history::unhex("3f9f2f294c8203c8fc99ba66e1a78e769a1eecc4ecc5cf8f8b631eea28138751"),
        history::unhex("4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d"),
        history::unhex("2598cd4baa438e6fb5c95bc4d1f6b8f1f7db607879f428c43f82a5247aca7f36"),
        history::unhex("d62eaf8b01ed970048bd8f2565e55ae9f2af3dcad8b7f12d94a40819805dd119"),
        history::unhex("af7064025876e1045a88f42119ef95a79b1a6a44334a43fcad0d2528d840450c"),
        history::unhex("cc498d61898d15e077f483f8786d2b5993e0bd2a89e30a01d8489e03a31103c7")
    };
}

inline constexpr const char* trial03_root =
    "/home/luke/projects/kpi-intensive-2026-10-22/continuation/"
    ".local/registered-financial-trial-03";

// Round labels select fresh accepted heads, not fixed contexts. The same
// selected relation/key may be reused only after every dynamic head-dependent
// program and AttemptBinding check succeeds.
inline constexpr std::array<const char*, 2> trial03_rounds{"ROUND1", "ROUND2"};
inline constexpr bool source05_retag_allowed = false;

} // namespace kpi::mpc::financial::registered_detail
