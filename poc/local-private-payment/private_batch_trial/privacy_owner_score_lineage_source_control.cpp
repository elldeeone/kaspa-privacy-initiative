#include "privacy_owner_score_lineage_source_authority.hpp"

#include <cassert>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace source =
    kpb::measurement::score_output_lineage_source;

namespace {

using Bytes = std::vector<unsigned char>;

Bytes read_file(const char* path) {
    std::ifstream input(path, std::ios::binary);
    assert(input.good());
    return Bytes(std::istreambuf_iterator<char>(input),
                 std::istreambuf_iterator<char>());
}

source::TestOnlyPrivacyLaunchLineageExpected expected() {
    return source::TestOnlyPrivacyLaunchLineageExpected{
        .method_sha256 = source::test_only_digest("frozen-method"),
        .run_selection_sha256 = source::test_only_digest(
            "{\"schema\":\"kpb-source-owned-diagnostic-run/v1\","
            "\"selected\":true}\n"),
        .diagnostic_selection_sha256 = source::test_only_digest(
            "exact-diagnostic-selection"),
        .source_closure_sha256 = source::test_only_digest(
            "{\"diagnostic-launcher\":\""
            "1111111111111111111111111111111111111111111111111111111111111111"
            "\"}\n"),
        .runtime_identity_sha256 = source::test_only_digest(
            "runtime-closure"),
        .measurement_attempt_identity =
            source::measurement_attempt_from_outer_ascii(
                "actual-candidate-attempt-01"),
        .trial_id = "22222222-2222-4222-8222-222222222222",
        .attempt_id = "actual-candidate-attempt-01",
        .classification = source::OwnerScoreSourceClassification::
            HiddenCandidate,
    };
}

template<class Function>
void refuses(Function&& function) {
    bool refused = false;
    try { function(); }
    catch (...) { refused = true; }
    assert(refused);
}

void success(const Bytes& archive) {
    auto authenticated = source::AuthenticatedPrivacyLaunchLineageSourceAuthority::
        test_only_mint(archive, expected());
    auto transfer = source::SelectedOwnerScoreLineageAdmissionBridge::admit(
        std::move(authenticated));
    auto summary = source::SelectedOwnerScoreLineageAdmissionBridge::
        test_only_consume(std::move(transfer));
    assert(summary.trial_id == expected().trial_id);
    assert(summary.attempt_id == expected().attempt_id);
    assert(summary.measurement_attempt_identity ==
           expected().measurement_attempt_identity);
    assert(summary.classification == expected().classification);
    assert(summary.run_selection_bytes ==
           std::string("{\"schema\":\"kpb-source-owned-diagnostic-run/v1\","
                       "\"selected\":true}\n").size());
}

void forge(const Bytes& archive) {
    const auto refuse_archive = [&](Bytes changed) {
        refuses([&] {
            (void)source::AuthenticatedPrivacyLaunchLineageSourceAuthority::
                test_only_mint(changed, expected());
        });
    };
    for (const std::size_t at : {std::size_t{0}, std::size_t{8},
                                 std::size_t{16}, std::size_t{24},
                                 std::size_t{232}, std::size_t{372},
                                 std::size_t{416}}) {
        auto changed = archive;
        changed.at(at) ^= 0x01;
        refuse_archive(std::move(changed));
    }
    auto changed = archive; changed.at(220) = 3; refuse_archive(changed);
    changed = archive; changed.at(221) = 2; refuse_archive(changed);
    changed = archive; changed.at(222) = 0; changed.at(223) = 0;
    refuse_archive(changed);
    changed = archive; changed.at(264) = '!'; refuse_archive(changed);
    changed = archive; changed.pop_back(); refuse_archive(changed);
    changed = archive; changed.push_back(0); refuse_archive(changed);
    refuses([&] {
        (void)source::AuthenticatedPrivacyLaunchLineageSourceAuthority::
            test_only_mint(
                archive, expected(),
                source::TestOnlyPrivacyLaunchSourceFault::WritableDescriptor);
    });
    refuses([&] {
        (void)source::AuthenticatedPrivacyLaunchLineageSourceAuthority::
            test_only_mint(
                archive, expected(),
                source::TestOnlyPrivacyLaunchSourceFault::MissingSeals);
    });
}

void cross_run(const Bytes& archive) {
    const auto refuses_expected = [&](const auto& wrong) {
        refuses([&] {
            (void)source::AuthenticatedPrivacyLaunchLineageSourceAuthority::
                test_only_mint(archive, wrong);
        });
    };
    auto wrong = expected();
    wrong.trial_id = "11111111-1111-4111-8111-111111111111";
    refuses_expected(wrong);
    wrong = expected(); wrong.attempt_id = "other-attempt";
    refuses_expected(wrong);
    wrong = expected(); wrong.method_sha256[0] ^= 0x80;
    refuses_expected(wrong);
    wrong = expected(); wrong.run_selection_sha256[0] ^= 0x80;
    refuses_expected(wrong);
    wrong = expected(); wrong.diagnostic_selection_sha256[0] ^= 0x80;
    refuses_expected(wrong);
    wrong = expected(); wrong.source_closure_sha256[0] ^= 0x80;
    refuses_expected(wrong);
    wrong = expected(); wrong.runtime_identity_sha256[0] ^= 0x80;
    refuses_expected(wrong);
    wrong = expected(); wrong.measurement_attempt_identity[0] ^= 0x80;
    refuses_expected(wrong);
    wrong = expected();
    wrong.classification =
        source::OwnerScoreSourceClassification::TransparentBaseline;
    refuses_expected(wrong);
}

void replay(const Bytes& archive) {
    auto authenticated = source::AuthenticatedPrivacyLaunchLineageSourceAuthority::
        test_only_mint(archive, expected());
    auto transfer = source::SelectedOwnerScoreLineageAdmissionBridge::admit(
        std::move(authenticated));
    refuses([&] {
        (void)source::SelectedOwnerScoreLineageAdmissionBridge::admit(
            std::move(authenticated));
    });
    (void)source::SelectedOwnerScoreLineageAdmissionBridge::test_only_consume(
        std::move(transfer));
    refuses([&] {
        (void)source::SelectedOwnerScoreLineageAdmissionBridge::
            test_only_consume(std::move(transfer));
    });
}

void fault(const Bytes& archive) {
    auto authenticated = source::AuthenticatedPrivacyLaunchLineageSourceAuthority::
        test_only_mint(archive, expected());
    refuses([&] {
        (void)source::SelectedOwnerScoreLineageAdmissionBridge::
            test_only_admit(
                std::move(authenticated),
                source::TestOnlyLineageAdmissionFault::AllocationBeforeClaim);
    });
    auto transfer = source::SelectedOwnerScoreLineageAdmissionBridge::admit(
        std::move(authenticated));
    (void)source::SelectedOwnerScoreLineageAdmissionBridge::test_only_consume(
        std::move(transfer));
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 3);
    const std::string mode(argv[1]);
    const auto archive = read_file(argv[2]);
    if (mode == "success") success(archive);
    else if (mode == "forge") forge(archive);
    else if (mode == "cross-run") cross_run(archive);
    else if (mode == "replay") replay(archive);
    else if (mode == "fault") fault(archive);
    else assert(false);
}
