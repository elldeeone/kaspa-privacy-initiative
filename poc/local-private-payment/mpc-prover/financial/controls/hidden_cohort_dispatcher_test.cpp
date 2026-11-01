#include "../hidden_cohort_dispatcher.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <concepts>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using namespace kpi::mpc::financial::hidden_cohort;

namespace {
Digest digest(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

Selection selection() {
    return Selection{
        .attempt = digest(0x11),
        .cohort = digest(0x22),
        .owner_certificates = {digest(0x31), digest(0x32), digest(0x33)},
        .masked_frame_bytes = 64,
        .permutation = PrivatePermutationEvidence{
            .model = "f3ca3c18f17ed8175fa420364e9aa2824a12af4320ca1dc00ba2508f60ba28ff",
            .source = "3ff31adfc6f2666ac53606ecf60336366d850951fda22a38b7445262f380d829",
            .trace = "4c3dec7c553f66e45775bff2c950417060980cf443ab83a2d198587fc604808e",
            .layout = "9a3ee5f5eb98384273e2b608f71a60f89c49e6fc9c1029586f8f201b84617e1e",
            .recipe = "ef6279fa5633c77230a8a8b8ae9b70a58770a30e6c6f5e0bcf97edba0d0e0edb",
            .random_bits = 768,
            .input_rows = 3,
            .output_rows = 6,
            .nf_sort_private = true,
            .output_sort_private = true,
            .dispatcher_chosen = false,
        },
    };
}

Ingress ingress(int role, std::uint64_t ordinal, const Selection& selected) {
    return Ingress{
        .owner_role = role,
        .owner_certificate = selected.owner_certificates.at(role),
        .attempt = selected.attempt,
        .cohort = selected.cohort,
        .connection_ordinal = ordinal,
        .attempt_ordinal = 0,
        .route = std::string(COMMON_INGRESS_ROUTE),
        .retry = false,
        .opaque_masked_frame = std::vector<unsigned char>(selected.masked_frame_bytes,
                                                           static_cast<unsigned char>(0x40 + role)),
    };
}

template<class T>
concept HasOwnerRelease = requires(T value) {
    value.release_for_owner(0, digest(0x44));
};

template<class T>
concept HasBodyGetter = requires(T value) {
    value.owner_frame(0);
};

template<class T>
concept CaptureHasPublicAssociation = requires(T value) {
    value.owner_to_public_effect;
};

void expect_refusal(auto callable) {
    bool refused = false;
    try { callable(); } catch (const Refused&) { refused = true; }
    assert(refused);
}

void full_order_controls() {
    static_assert(!HasOwnerRelease<Dispatcher>);
    static_assert(!HasBodyGetter<SealedCohort>);
    static_assert(!CaptureHasPublicAssociation<PublicCapture>);

    const auto selected = selection();
    std::array<int, 3> order{0, 1, 2};
    std::string invariant_release;
    do {
        Dispatcher dispatcher(selected);
        for (std::size_t i = 0; i < order.size(); ++i)
            dispatcher.admit(ingress(order[i], i, selected));
        auto sealed = dispatcher.seal();
        const auto capture = sealed.capture();
        assert(capture.connection_order == std::vector<int>(order.begin(), order.end()));
        assert(capture.upload_order == std::vector<int>(order.begin(), order.end()));
        assert(capture.owner_mapping_exported == false);
        assert(capture.public_slot_association_exported == false);
        assert(capture.filenames_exported == false);
        assert(capture.per_owner_release_routes == 0);

        const auto release = sealed.release_unlabelled_aggregate(digest(0x70));
        assert(release.route == COMMON_AGGREGATE_ROUTE);
        assert(release.owner_mapping_exported == false);
        assert(release.release_count == 1);
        if (invariant_release.empty()) invariant_release = release.invariant_identity;
        assert(release.invariant_identity == invariant_release);
        expect_refusal([&] { sealed.release_unlabelled_aggregate(digest(0x70)); });
    } while (std::next_permutation(order.begin(), order.end()));
}

void incomplete_duplicate_retry_and_metadata_refuse() {
    const auto selected = selection();
    {
        Dispatcher dispatcher(selected);
        dispatcher.admit(ingress(0, 0, selected));
        dispatcher.admit(ingress(1, 1, selected));
        expect_refusal([&] { dispatcher.seal(); });
    }
    {
        Dispatcher dispatcher(selected);
        dispatcher.admit(ingress(0, 0, selected));
        expect_refusal([&] { dispatcher.admit(ingress(0, 1, selected)); });
    }
    for (const std::string mutation : {"retry", "route", "length", "attempt", "cohort",
                                       "certificate", "attempt-ordinal", "ordinal"}) {
        Dispatcher dispatcher(selected);
        auto row = ingress(0, 0, selected);
        if (mutation == "retry") row.retry = true;
        if (mutation == "route") row.route = "owner/0";
        if (mutation == "length") row.opaque_masked_frame.pop_back();
        if (mutation == "attempt") row.attempt = digest(0x90);
        if (mutation == "cohort") row.cohort = digest(0x91);
        if (mutation == "certificate") row.owner_certificate = digest(0x92);
        if (mutation == "attempt-ordinal") row.attempt_ordinal = 1;
        if (mutation == "ordinal") row.connection_ordinal = 2;
        expect_refusal([&] { dispatcher.admit(std::move(row)); });
    }
    {
        Dispatcher dispatcher(selected);
        dispatcher.admit(ingress(0, 0, selected));
        auto duplicate_ordinal = ingress(1, 0, selected);
        expect_refusal([&] { dispatcher.admit(std::move(duplicate_ordinal)); });
    }
}

void permutation_authority_refuses_dispatcher_choice() {
    for (const std::string mutation : {"model", "source", "trace", "layout", "recipe",
                                       "random-bits", "input-rows", "output-rows",
                                       "nf-public", "output-public", "dispatcher"}) {
        auto selected = selection();
        if (mutation == "model") selected.permutation.model[0] = '0';
        if (mutation == "source") selected.permutation.source[0] = '0';
        if (mutation == "trace") selected.permutation.trace[0] = '0';
        if (mutation == "layout") selected.permutation.layout[0] = '0';
        if (mutation == "recipe") selected.permutation.recipe[0] = '0';
        if (mutation == "random-bits") --selected.permutation.random_bits;
        if (mutation == "input-rows") --selected.permutation.input_rows;
        if (mutation == "output-rows") --selected.permutation.output_rows;
        if (mutation == "nf-public") selected.permutation.nf_sort_private = false;
        if (mutation == "output-public") selected.permutation.output_sort_private = false;
        if (mutation == "dispatcher") selected.permutation.dispatcher_chosen = true;
        expect_refusal([&] { Dispatcher dispatcher(selected); });
    }
    const auto status = source_status();
    assert(status.schema == "kpb-hidden-cohort-dispatcher-source-only/v1");
    assert(status.status == "UNQUALIFIED_SOURCE_ONLY");
    assert(status.authenticated_mpc_integration == false);
    assert(status.registered_driver_integration == false);
    assert(status.launch_authorized == false);
    assert(status.privacy_qualified == false);
}
}

int main() {
    full_order_controls();
    incomplete_duplicate_retry_and_metadata_refuse();
    permutation_authority_refuses_dispatcher_choice();
}
