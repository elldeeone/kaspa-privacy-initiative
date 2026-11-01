#include "registered_role_model_admission.hpp"

#include "../trace/sealed_trace.hpp"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <span>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver {
namespace {

using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) { return value != Digest{}; }

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, std::string_view value) {
    add(out, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}
void number(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void text(Bytes& out, std::string_view value) {
    number(out, value.size());
    add(out, value);
}
void path(Bytes& out, const std::filesystem::path& value) {
    text(out, value.string());
}

void require_hex(std::string_view value) {
    need(value.size() == 64 &&
         value.find_first_not_of("0123456789abcdef") ==
             std::string_view::npos);
}

void require_absolute_normal(const std::filesystem::path& value) {
    need(value.is_absolute() && value.lexically_normal() == value);
}

void require_directory(const std::filesystem::path& value) {
    require_absolute_normal(value);
    struct stat status{};
    need(::lstat(value.c_str(), &status) == 0 && S_ISDIR(status.st_mode) &&
         status.st_uid == ::geteuid() &&
         !(status.st_mode & (S_IWGRP | S_IWOTH)) &&
         std::filesystem::canonical(value) == value);
}

Bytes read_public_file(
        const std::filesystem::path& value, std::size_t maximum_bytes) {
    require_absolute_normal(value);
    const int descriptor = ::open(
        value.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    need(descriptor >= 0);
    struct Close final {
        int value;
        ~Close() { if (value >= 0) ::close(value); }
    } close{descriptor};
    struct stat before{}, after{};
    need(::fstat(descriptor, &before) == 0 && S_ISREG(before.st_mode) &&
         before.st_size >= 0 &&
         static_cast<std::uint64_t>(before.st_size) <= maximum_bytes);
    Bytes result(static_cast<std::size_t>(before.st_size));
    std::size_t offset = 0;
    while (offset < result.size()) {
        const auto count = ::pread(
            descriptor, result.data() + offset, result.size() - offset,
            static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        offset += static_cast<std::size_t>(count);
    }
    need(::fstat(descriptor, &after) == 0 &&
         before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
         before.st_size == after.st_size &&
         before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
         before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
         before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
         before.st_ctim.tv_nsec == after.st_ctim.tv_nsec);
    return result;
}

Digest configuration_identity(
        const PublicCompiledRoleModelConfiguration& selected) {
    const auto& value = selected.configuration;
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_ROLE_MODEL_CONFIGURATION_V1\n");
    number(bytes, selected.role);
    for (const auto* digest : {
             &selected.driver_selection_identity, &selected.source_identity,
             &selected.build_identity}) {
        need(nonzero(*digest));
        add(bytes, *digest);
    }
    path(bytes, value.model_directory);
    path(bytes, value.model_metadata);
    text(bytes, value.model_metadata_sha256);
    path(bytes, value.compressed_query_transport);
    path(bytes, value.verifying_key);
    path(bytes, value.independent_verifier);
    text(bytes, value.independent_verifier_sha256);
    number(bytes, value.query_shape.instances);
    number(bytes, value.query_shape.witnesses);
    number(bytes, value.query_shape.domain);
    for (const auto* pin : {
             &value.query_pins.container_sha256,
             &value.query_pins.canonical_pk_sha256,
             &value.query_pins.decoder_identity,
             &value.query_pins.vk_sha256})
        text(bytes, *pin);
    number(bytes, value.query_pins.container_bytes);
    number(bytes, value.query_pins.canonical_pk_bytes);
    number(bytes, value.rows.instances);
    number(bytes, value.rows.witnesses);
    number(bytes, value.rows.constraints);
    for (const auto& file : value.rows.files) path(bytes, file);
    for (const auto& hash : value.rows.compressed_sha256) text(bytes, hash);
    for (const auto& hash : value.rows.raw_sha256) text(bytes, hash);
    for (const auto count : value.rows.compressed_bytes) number(bytes, count);
    for (const auto count : value.rows.raw_bytes) number(bytes, count);
    text(bytes, value.rows.matrix_fingerprint);
    for (const auto& root : value.private_candidate_roots) path(bytes, root);
    for (const auto& root : value.public_result_roots) path(bytes, root);
    need(value.owner_port_base >= 0);
    number(bytes, static_cast<std::uint64_t>(value.owner_port_base));
    number(bytes, value.multiplication_batch);
    return identity_registry::digest(bytes);
}

void require_configuration(
        const PublicCompiledRoleModelConfiguration& selected) {
    const auto& value = selected.configuration;
    need(selected.role < 3 &&
         nonzero(selected.driver_selection_identity) &&
         nonzero(selected.source_identity) && nonzero(selected.build_identity) &&
         value.owner_port_base >= 1024 && value.owner_port_base <= 65531 &&
         value.multiplication_batch > 0 &&
         value.query_shape.instances > 0 && value.query_shape.witnesses > 0 &&
         value.query_shape.domain > 0 && value.query_pins.container_bytes > 0 &&
         value.query_pins.canonical_pk_bytes > 0 &&
         value.rows.instances == value.query_shape.instances &&
         value.rows.witnesses == value.query_shape.witnesses);
    for (const auto* hash : {
             &value.model_metadata_sha256,
             &value.independent_verifier_sha256,
             &value.query_pins.container_sha256,
             &value.query_pins.canonical_pk_sha256,
             &value.query_pins.decoder_identity,
             &value.query_pins.vk_sha256,
             &value.rows.matrix_fingerprint})
        require_hex(*hash);
    for (const auto& hash : value.rows.compressed_sha256) require_hex(hash);
    for (const auto& hash : value.rows.raw_sha256) require_hex(hash);
    for (const auto& candidate : {
             value.model_directory, value.model_metadata,
             value.compressed_query_transport, value.verifying_key,
             value.independent_verifier})
        require_absolute_normal(candidate);
    need(value.model_metadata == value.model_directory / "model.meta");
    for (const auto& file : value.rows.files) require_absolute_normal(file);
    for (const auto& root : value.private_candidate_roots)
        require_absolute_normal(root);
    for (const auto& root : value.public_result_roots)
        require_absolute_normal(root);
    need(nonzero(configuration_identity(selected)));
}

} // namespace

CompiledRoleModelConfigurationAuthority::
CompiledRoleModelConfigurationAuthority(
        PublicCompiledRoleModelConfiguration value)
    : value_(std::move(value)), identity_(configuration_identity(value_)) {
    require_configuration(value_);
}

CompiledRoleModelConfigurationAuthority::
CompiledRoleModelConfigurationAuthority(
        CompiledRoleModelConfigurationAuthority&& other) noexcept
    : value_(std::move(other.value_)), identity_(other.identity_),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_REGISTERED_ROLE_MODEL_ADMISSION_TEST_SETUP
CompiledRoleModelConfigurationAuthority
CompiledRoleModelConfigurationAuthority::test_only_mint(
        PublicCompiledRoleModelConfiguration value) {
    return CompiledRoleModelConfigurationAuthority(std::move(value));
}
#endif

RegisteredRoleModelAdmission::RegisteredRoleModelAdmission(
        PublicRegisteredRoleModelAdmission receipt,
        registered_detail::DriverConfiguration configuration,
        packed::PackedModel model)
    : receipt_(std::move(receipt)),
      configuration_(std::move(configuration)), model_(std::move(model)) {}

RegisteredRoleModelAdmission RegisteredRoleModelAdmission::admit(
        CompiledRoleModelConfigurationAuthority&& selected,
        const RegisteredChildBootstrapPending& pending) {
    try {
        need(selected.live_.exchange(false));
        require_configuration(selected.value_);
        need(configuration_identity(selected.value_) == selected.identity_);
        const auto bootstrap = pending.public_receipt();
        need(bootstrap.role == selected.value_.role &&
             bootstrap.driver_selection_identity ==
                 selected.value_.driver_selection_identity &&
             nonzero(bootstrap.inherited_query_artifact_identity) &&
             nonzero(bootstrap.model_preimage_identity) &&
             nonzero(bootstrap.query_store_preimage_identity));
        const auto artifact =
            RegisteredParentBootstrapTransport::query_artifact(pending);
        need(artifact != nullptr);
        const auto& config = selected.value_.configuration;
        const auto vk = read_public_file(config.verifying_key, 1024 * 1024);
        need(sha256_hex(vk) == config.query_pins.vk_sha256);
        const auto verifier = read_public_file(
            config.independent_verifier, 64 * 1024 * 1024);
        need(sha256_hex(verifier) == config.independent_verifier_sha256);
        require_directory(config.model_directory);
        for (const auto& root : config.private_candidate_roots)
            require_directory(root);
        for (const auto& root : config.public_result_roots)
            require_directory(root);
        const auto queries = packed::GzipQueryStore::admit(
            artifact, vk, config.query_shape, config.query_pins);
        auto model = packed::PackedModel::admit_compressed(
            config.model_directory, queries, config.verifying_key,
            config.model_metadata_sha256, config.rows);
        model.check_backing_unchanged();
        need(identity_registry::unhex(model.identity()) ==
                 bootstrap.model_preimage_identity &&
             identity_registry::unhex(model.query_transport_identity()) ==
                 bootstrap.query_store_preimage_identity);
        auto receipt = PublicRegisteredRoleModelAdmission{
            .role = selected.value_.role,
            .driver_selection_identity =
                selected.value_.driver_selection_identity,
            .configuration_identity = selected.identity_,
            .inherited_query_artifact_identity =
                bootstrap.inherited_query_artifact_identity,
            .model_preimage_identity = bootstrap.model_preimage_identity,
            .query_store_preimage_identity =
                bootstrap.query_store_preimage_identity,
        };
        auto configuration = std::move(selected.value_.configuration);
        return RegisteredRoleModelAdmission(
            std::move(receipt), std::move(configuration), std::move(model));
    } catch (...) { refuse(); }
}

std::filesystem::path RegisteredRoleModelAdmission::private_candidate_path(
        const Digest& attempt) const {
    try {
        need(receipt_.role < configuration_.private_candidate_roots.size() &&
             nonzero(attempt));
        const auto& root = configuration_.private_candidate_roots[receipt_.role];
        require_directory(root);
        return root / ("registered-proof-" + identity_registry::hex(attempt) +
                       ".bin");
    } catch (...) { refuse(); }
}

RegisteredRoleModelAdmissionSourceStatus
registered_role_model_admission_source_status() {
    return {
        .schema = "kpb-registered-role-model-admission-source-only/v1",
        .status = "UNQUALIFIED_SOURCE_ONLY",
        .inherited_sealed_query_artifact_consumed = true,
        .full_query_point_admission = true,
        .full_r1cs_row_admission = true,
        .actual_model_and_query_identity_join = true,
        .caller_packed_model_factory = false,
        .production_compiled_configuration_minter = false,
        .selected_child_callsite = true,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::registered_driver
