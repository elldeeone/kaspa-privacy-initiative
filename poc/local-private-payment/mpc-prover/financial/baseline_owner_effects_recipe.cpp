#include "baseline_owner_effects_recipe.hpp"
#include "baseline_public_effects_collector.hpp"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <optional>
#include <openssl/sha.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
namespace {
using Bytes = std::vector<unsigned char>;

[[noreturn]] void parse_refuse(const char* reason) {
    throw std::runtime_error(reason);
}
[[noreturn]] void authority_refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) authority_refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

bool canonical_hash(const std::string& value) {
    return value.size() == 64 &&
        value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

std::string hex(std::span<const unsigned char> value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2);
    for (auto byte : value) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

Bytes read_stable_file(const std::filesystem::path& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) parse_refuse("owner-effects-recipe-open");
    struct Close { int fd; ~Close() { if (fd >= 0) ::close(fd); } } close{fd};
    struct stat before{}, after{};
    if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_nlink != 1 || before.st_size <= 0 ||
        before.st_size > 1024 * 1024)
        parse_refuse("owner-effects-recipe-file-shape");
    Bytes result(static_cast<std::size_t>(before.st_size));
    std::size_t at = 0;
    while (at < result.size()) {
        const auto count = ::read(fd, result.data() + at, result.size() - at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) parse_refuse("owner-effects-recipe-read");
        at += static_cast<std::size_t>(count);
    }
    unsigned char extra{};
    if (::read(fd, &extra, 1) != 0 || ::fstat(fd, &after) != 0 ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        parse_refuse("owner-effects-recipe-changed-during-read");
    return result;
}

struct Reader {
    std::span<const unsigned char> data;
    std::size_t at{};
    std::span<const unsigned char> take(std::size_t count) {
        if (count > data.size() - std::min(at, data.size()))
            parse_refuse("owner-effects-recipe-truncated");
        const auto result = data.subspan(at, count);
        at += count;
        return result;
    }
    std::uint64_t integer() {
        const auto value = take(8);
        std::uint64_t result{};
        for (unsigned i = 0; i < 8; ++i)
            result |= static_cast<std::uint64_t>(value[i]) << (8 * i);
        return result;
    }
    std::size_t count() {
        const auto value = integer();
        if (value > std::numeric_limits<std::size_t>::max())
            parse_refuse("owner-effects-recipe-integer-overflow");
        return static_cast<std::size_t>(value);
    }
};

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void text(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}
void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

Digest owner_authority_identity(const PublicOwnerPrivateEffects& value) {
    Bytes bytes;
    text(bytes, "KPB_BASELINE_OWNER_PRIVATE_EFFECTS_V1\n");
    integer(bytes, static_cast<std::uint8_t>(value.classification));
    integer(bytes, value.round); integer(bytes, value.owner);
    for (const auto* field : {
             &value.run, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity, &value.owner_contract_identity,
             &value.public_nullifier,
             &value.public_tuple_hashes[0], &value.public_tuple_hashes[1],
             &value.public_tuple_commitments[0],
             &value.public_tuple_commitments[1],
             &value.relation_source_identity,
             &value.owner_effects_recipe_identity,
             &value.baseline_plan_identity,
             &value.verified_egress_identity,
             &value.policy_identity}) add(bytes, *field);
    return identity_registry::digest(bytes);
}

void validate_owner(const PublicOwnerPrivateEffects& value) {
    need(value.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
         (value.round == 1 || value.round == 2) && value.owner < 3 &&
         value.public_tuple_hashes[0] < value.public_tuple_hashes[1] &&
         value.public_tuple_commitments[0] !=
             value.public_tuple_commitments[1]);
    for (const auto* field : {
             &value.run, &value.attempt, &value.cohort,
             &value.capture_plan_identity, &value.projection_identity,
             &value.context_identity, &value.owner_contract_identity,
             &value.public_nullifier,
             &value.public_tuple_hashes[0], &value.public_tuple_hashes[1],
             &value.public_tuple_commitments[0],
             &value.public_tuple_commitments[1],
             &value.relation_source_identity,
             &value.owner_effects_recipe_identity,
             &value.baseline_plan_identity,
             &value.verified_egress_identity,
             &value.policy_identity}) need(nonzero(*field));
}

template<std::size_t N>
void exact_public_set(std::array<Digest, N> actual,
                      const std::array<Digest, N>& expected) {
    for (const auto& value : actual) need(nonzero(value));
    std::sort(actual.begin(), actual.end());
    need(std::adjacent_find(actual.begin(), actual.end()) == actual.end() &&
         actual == expected);
}

template<std::size_t N>
void unique_public_set(std::array<Digest, N> actual) {
    for (const auto& value : actual) need(nonzero(value));
    std::sort(actual.begin(), actual.end());
    need(std::adjacent_find(actual.begin(), actual.end()) == actual.end());
}
} // namespace

BaselineOwnerEffectsRecipe::BaselineOwnerEffectsRecipe(
        std::string identity, std::string source, std::string layout,
        std::size_t variables, std::size_t instances,
        std::array<OwnerEffectsColumns, 3> owners)
    : identity_(std::move(identity)), source_identity_(std::move(source)),
      layout_identity_(std::move(layout)), model_variables_(variables),
      instances_(instances), owners_(std::move(owners)) {}

std::shared_ptr<const BaselineOwnerEffectsRecipe>
BaselineOwnerEffectsRecipe::load(
        const std::filesystem::path& path,
        const std::string& expected_identity,
        const std::string& expected_source_identity,
        const std::string& expected_layout_identity,
        std::size_t model_variables, std::size_t instances,
        const std::array<std::span<const std::size_t>, 3>& owner_layout) {
    if (!canonical_hash(expected_identity) ||
        !canonical_hash(expected_source_identity) ||
        !canonical_hash(expected_layout_identity) || instances != 3 ||
        model_variables <= instances)
        parse_refuse("owner-effects-recipe-expected-binding");
    for (const auto columns : owner_layout)
        if (columns.empty() || !std::is_sorted(columns.begin(), columns.end()) ||
            std::adjacent_find(columns.begin(), columns.end()) != columns.end())
            parse_refuse("owner-effects-recipe-owner-layout");

    const auto bytes = read_stable_file(path);
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    if (!SHA256(bytes.data(), bytes.size(), digest.data()) ||
        hex(digest) != expected_identity)
        parse_refuse("owner-effects-recipe-file-identity");

    Reader input{bytes};
    constexpr std::array<unsigned char, 8> magic{
        'K','P','B','O','E','R','0','1'};
    const auto tag = input.take(magic.size());
    if (!std::equal(tag.begin(), tag.end(), magic.begin()) ||
        input.count() != model_variables || input.count() != instances ||
        input.count() != 3 || input.count() != 256 ||
        input.count() != 2 || input.count() != 6 ||
        hex(input.take(32)) != expected_source_identity ||
        hex(input.take(32)) != expected_layout_identity)
        parse_refuse("owner-effects-recipe-header-or-binding");

    std::array<OwnerEffectsColumns, 3> owners{};
    std::unordered_set<std::size_t> selected;
    for (std::size_t owner = 0; owner < owners.size(); ++owner) {
        if (input.count() != owner)
            parse_refuse("owner-effects-recipe-owner-order");
        for (auto& column : owners[owner].input_nf_bits) {
            column = input.count();
            if (column < instances || column >= model_variables ||
                !std::binary_search(owner_layout[owner].begin(),
                                    owner_layout[owner].end(), column) ||
                !selected.insert(column).second)
                parse_refuse("owner-effects-recipe-nf-column");
        }
        for (auto& row : owners[owner].output_permutation)
            for (auto& column : row) {
                column = input.count();
                bool is_owner_input = false;
                for (const auto columns : owner_layout)
                    is_owner_input = is_owner_input ||
                        std::binary_search(columns.begin(), columns.end(),
                                           column);
                if (column < instances || column >= model_variables ||
                    is_owner_input || !selected.insert(column).second)
                    parse_refuse("owner-effects-recipe-selector-column");
            }
    }
    if (input.at != bytes.size())
        parse_refuse("owner-effects-recipe-trailing-data");
    return std::shared_ptr<const BaselineOwnerEffectsRecipe>(
        new BaselineOwnerEffectsRecipe(
            expected_identity, expected_source_identity,
            expected_layout_identity, model_variables, instances,
            std::move(owners)));
}

OwnerPrivateEffectsAuthority::OwnerPrivateEffectsAuthority(
        PublicOwnerPrivateEffects value) : value_(std::move(value)) {
    // Keep each public row commitment attached to its full-row hash while
    // canonicalizing the pair. Sorting hashes alone would silently attribute
    // the wrong commitment to a created row at the private scorer boundary.
    if (value_.public_tuple_hashes[1] < value_.public_tuple_hashes[0]) {
        std::swap(value_.public_tuple_hashes[0],
                  value_.public_tuple_hashes[1]);
        std::swap(value_.public_tuple_commitments[0],
                  value_.public_tuple_commitments[1]);
    }
    validate_owner(value_);
    value_.authority_identity = owner_authority_identity(value_);
}

OwnerPrivateEffectsAuthority::OwnerPrivateEffectsAuthority(
        OwnerPrivateEffectsAuthority&& other) noexcept
    : value_(other.value_), live_(other.live_.exchange(false)) {}

ConsumedOwnerPrivateEffects OwnerPrivateEffectsReceiverBridge::consume(
        OwnerPrivateEffectsAuthority&& source) {
    need(source.live_.exchange(false));
    validate_owner(source.value_);
    return ConsumedOwnerPrivateEffects(source.value_);
}

struct PreparedBaselineOwnerEffects::Storage {
    std::mutex mutex;
    std::optional<BaselineEffectsPlanAuthority> plan;
    std::array<std::optional<OwnerPrivateEffectsAuthority>, 3> owners;
    Storage(BaselineEffectsPlanAuthority&& selected,
            std::array<OwnerPrivateEffectsAuthority, 3>&& values)
        : plan(std::move(selected)), owners{
              std::move(values[0]), std::move(values[1]),
              std::move(values[2])} {}
};

PreparedBaselineOwnerEffects::PreparedBaselineOwnerEffects(
        std::unique_ptr<Storage> storage) : storage_(std::move(storage)) {}
PreparedBaselineOwnerEffects::PreparedBaselineOwnerEffects(
        PreparedBaselineOwnerEffects&&) noexcept = default;
PreparedBaselineOwnerEffects::~PreparedBaselineOwnerEffects() = default;

BaselineEffectsPlanAuthority PreparedBaselineOwnerEffects::take_plan() {
    if (!storage_) authority_refuse();
    std::lock_guard guard(storage_->mutex);
    if (!storage_->plan) authority_refuse();
    auto result = std::move(*storage_->plan);
    storage_->plan.reset();
    return result;
}

OwnerPrivateEffectsAuthority PreparedBaselineOwnerEffects::take_owner(
        unsigned owner) {
    if (!storage_) authority_refuse();
    std::lock_guard guard(storage_->mutex);
    if (owner >= storage_->owners.size() ||
        !storage_->owners[owner]) authority_refuse();
    auto result = std::move(*storage_->owners[owner]);
    storage_->owners[owner].reset();
    return result;
}

#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
const PublicOwnerPrivateEffects& PreparedBaselineOwnerEffects::test_only_owner(
        unsigned owner) const {
    // Test-only inspection is single-threaded by contract.
    if (!storage_ || owner >= storage_->owners.size() ||
        !storage_->owners[owner]) authority_refuse();
    return storage_->owners[owner]->value_;
}
#endif

BaselineEffectsPlanAuthority BaselineOwnerEffectsRecipeBridge::claim_plan(
        BaselineEffectsPlanAuthority&& selected) {
    // Claim before any non-atomic read. Concurrent/replayed callers lose here
    // and cannot observe or mint owner sources from this authority.
    need(selected.live_.exchange(false));
    const auto plan = selected.value_;
    const auto plan_identity = selected.identity_;
    return BaselineEffectsPlanAuthority(
        plan, plan_identity, BaselineEffectsPlanAuthority::ClaimedTransfer{});
}

PreparedBaselineOwnerEffects BaselineOwnerEffectsRecipeBridge::derive_claimed(
        BaselineEffectsPlanAuthority&& retained, OpenedOwnerEffects opened) {
    try {
        need(retained.live_.load());
        const auto& plan = retained.value_;
        const auto plan_identity = retained.identity_;
        need(plan.classification ==
                 CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
             (plan.round == 1 || plan.round == 2) &&
             nonzero(opened.context_identity) &&
             nonzero(opened.relation_source_identity) &&
             nonzero(opened.owner_effects_recipe_identity));

        std::array<unsigned, 6> destinations{};
        std::array<bool, 6> columns{};
        for (unsigned source = 0; source < 6; ++source) {
            unsigned ones = 0;
            for (unsigned destination = 0; destination < 6; ++destination) {
                const auto bit = opened.output_permutation[source][destination];
                need(bit <= 1);
                if (bit == 1) {
                    ++ones;
                    destinations[source] = destination;
                    need(!columns[destination]);
                    columns[destination] = true;
                }
            }
            need(ones == 1);
        }
        need(std::all_of(columns.begin(), columns.end(),
                         [](bool value) { return value; }));
        exact_public_set(opened.nullifiers, plan.public_nullifiers);
        exact_public_set(opened.egress_tuple_hashes,
                         plan.public_tuple_hashes);
        unique_public_set(opened.egress_tuple_commitments);

        const auto make_owner = [&](unsigned owner) {
            const auto first = destinations[2 * owner];
            const auto second = destinations[2 * owner + 1];
            PublicOwnerPrivateEffects value{
                .classification = plan.classification,
                .round = plan.round,
                .owner = owner,
                .run = plan.run,
                .attempt = plan.attempt,
                .cohort = plan.cohort,
                .capture_plan_identity = plan.capture_plan_identity,
                .projection_identity = plan.projection_identity,
                .context_identity = opened.context_identity,
                .owner_contract_identity = plan.owner_contracts[owner],
                .public_nullifier = opened.nullifiers[owner],
                .public_tuple_hashes = {
                    opened.egress_tuple_hashes[first],
                    opened.egress_tuple_hashes[second]},
                .public_tuple_commitments = {
                    opened.egress_tuple_commitments[first],
                    opened.egress_tuple_commitments[second]},
                .relation_source_identity =
                    opened.relation_source_identity,
                .owner_effects_recipe_identity =
                    opened.owner_effects_recipe_identity,
                .baseline_plan_identity = plan_identity,
                .verified_egress_identity = plan.verified_egress_identity,
                .policy_identity = plan.policy_identity,
            };
            return OwnerPrivateEffectsAuthority(std::move(value));
        };
        std::array<OwnerPrivateEffectsAuthority, 3> owners{
            make_owner(0), make_owner(1), make_owner(2)};
        return PreparedBaselineOwnerEffects(
            std::make_unique<PreparedBaselineOwnerEffects::Storage>(
                std::move(retained), std::move(owners)));
    } catch (const identity_registry::Refused&) { throw; }
    catch (...) { authority_refuse(); }
}

PreparedBaselineOwnerEffects BaselineOwnerEffectsRecipeBridge::derive_opened(
        BaselineEffectsPlanAuthority&& selected, OpenedOwnerEffects opened) {
    auto retained = claim_plan(std::move(selected));
    return derive_claimed(std::move(retained), std::move(opened));
}

#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
PreparedBaselineOwnerEffects
BaselineOwnerEffectsRecipeBridge::test_only_derive_opened(
        BaselineEffectsPlanAuthority&& selected,
        TestOpenedOwnerEffects opened) {
    return derive_opened(std::move(selected), OpenedOwnerEffects{
        .nullifiers = opened.nullifiers,
        .output_permutation = opened.output_permutation,
        .egress_tuple_hashes = opened.egress_tuple_hashes,
        .egress_tuple_commitments = opened.egress_tuple_commitments,
        .context_identity = opened.context_identity,
        .relation_source_identity = opened.relation_source_identity,
        .owner_effects_recipe_identity =
            opened.owner_effects_recipe_identity,
    });
}
#endif

BaselineOwnerEffectsSourceStatus baseline_owner_effects_source_status() {
    return {
        .schema = "kpb-baseline-owner-effects-recipe-source-only/v1",
        .status = "CONFIGURED0_UNQUALIFIED",
        .exact_selected_owner_nf_columns = true,
        .authenticated_output_permutation_columns = true,
        .raw_pre_shuffle_tuples_opened = false,
        .post_egress_mac_checked_opening = true,
        .exact_egress_set_join = true,
        .hidden_candidate_factory_absent = true,
        .registered_recipe_selected = true,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::registered_driver::baseline_disclosure
