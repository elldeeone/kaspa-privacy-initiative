#include "privacy_measurement_output_abi_v4.hpp"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <fstream>
#include <span>

using namespace kpb::measurement::runtime_bridge;

int main(int argc, char** argv) {
    static_assert(OBSERVER_OUTPUT_ABI_V4.version == 4);
    static_assert(OBSERVER_OUTPUT_ABI_V4.used_bytes == 152192);
    static_assert(OBSERVER_OUTPUT_ABI_V4.exact_bytes == 155648);
    static_assert(OBSERVER_V4_SECTION_OFFSET ==
                  OBSERVER_OUTPUT_ABI.exact_bytes);
    static_assert(OBSERVER_V4_SECTION_BYTES == 640);
    static_assert(OBSERVER_V4_FAMILY_ROWS.size() == 12);
    static_assert(!kObserverV4OutputSourceStatus.serialized_body_is_authority);
    static_assert(!kObserverV4OutputSourceStatus
                       .historical_local_s4_s12_eligible);
    static_assert(!kObserverV4OutputSourceStatus
                       .all_live_applicability_identities_present);
    static_assert(!kObserverV4OutputSourceStatus.live_family_authority_join);
    static_assert(!kObserverV4OutputSourceStatus.all_fresh_trial_ledger_join);
    static_assert(!kObserverV4OutputSourceStatus.source_runtime_freshness_join);
    static_assert(!kObserverV4OutputSourceStatus.selected_worker);
    static_assert(!kObserverV4OutputSourceStatus.configured);

    constexpr auto s5_s6a = OBSERVER_V4_FAMILY_ROWS[5];
    constexpr auto joint_hmac = OBSERVER_V4_FAMILY_ROWS[6];
    constexpr auto s14_s12 = OBSERVER_V4_FAMILY_ROWS[8];
    static_assert(s5_s6a.mode ==
                  ObserverV4RequirementMode::StrictConjunction);
    static_assert(s5_s6a.prerequisite_mask ==
                  (observer_v4_family_bit(
                       ObserverV4Family::S5CryptoboxConfidentiality) |
                   observer_v4_family_bit(
                       ObserverV4Family::S6aHiddenDeliveryPrf)));
    static_assert(joint_hmac.mode ==
                  ObserverV4RequirementMode::JointSameSourceGame);
    static_assert(joint_hmac.prerequisite_mask ==
                  (observer_v4_family_bit(
                       ObserverV4Family::S6aHiddenDeliveryPrf) |
                   observer_v4_family_bit(
                       ObserverV4Family::S7NullifierHmacPrf)));
    static_assert(s14_s12.mode ==
                  ObserverV4RequirementMode::StrictConjunction);
    static_assert(s14_s12.prerequisite_mask ==
                  (observer_v4_family_bit(
                       ObserverV4Family::NarrowS14MpcRealization) |
                   observer_v4_family_bit(
                       ObserverV4Family::S12AggregateGroth16)));
    for (const auto& row : OBSERVER_V4_FAMILY_ROWS)
        assert(row.applicability ==
               ObserverV4Applicability::MissingLiveAuthority);

    auto body = test_only_observer_output_v4_body();
    assert(validate_observer_output_v4(body));
    assert(validate_measurement_output_abi(
        RuntimeChildRole::Observer,
        std::span<const unsigned char>(body).first(
            OBSERVER_V4_PREFIX_BYTES)));

    for (std::size_t offset = 0; offset < OBSERVER_V4_SECTION_BYTES;
         ++offset) {
        body.at(OBSERVER_V4_SECTION_OFFSET + offset) ^= 1;
        assert(!validate_observer_output_v4(body));
        body.at(OBSERVER_V4_SECTION_OFFSET + offset) ^= 1;
    }

    body.front() ^= 1;
    assert(!validate_observer_output_v4(body));
    body.front() ^= 1;
    body.at(OBSERVER_V4_USED_BYTES) = 1;
    assert(!validate_observer_output_v4(body));
    body.at(OBSERVER_V4_USED_BYTES) = 0;
    assert(!validate_observer_output_v4(
        std::span<const unsigned char>(body).first(body.size() - 1)));
    const auto v3 = test_only_measurement_output_abi_body(
        RuntimeChildRole::Observer);
    assert(!validate_observer_output_v4(v3));

    assert(argc == 2);
    std::ofstream stream(argv[1], std::ios::binary | std::ios::trunc);
    assert(stream);
    stream.write(reinterpret_cast<const char*>(body.data()),
                 static_cast<std::streamsize>(body.size()));
    assert(stream.good());
}
