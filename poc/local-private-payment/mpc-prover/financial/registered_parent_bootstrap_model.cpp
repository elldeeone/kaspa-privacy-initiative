#include "registered_parent_bootstrap.hpp"

#include "../packed/packed_model.hpp"
#include "../trace/sealed_trace.hpp"

#include <span>
#include <string>
#include <vector>

namespace kpi::mpc::financial::registered_driver {
namespace {

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }

Digest actual_query_transport_identity(
        const PublicInheritedSealedQueryArtifact& artifact,
        const packed::Metadata& model) {
    std::vector<unsigned char> bytes;
    const auto text = [&](const std::string& value) {
        bytes.insert(bytes.end(), value.begin(), value.end());
    };
    const auto number = [&](std::uint64_t value) {
        for (unsigned shift = 0; shift < 64; shift += 8)
            bytes.push_back(static_cast<unsigned char>(value >> shift));
    };
    text("KPI_GZIP_STOCK_PK_V1\n");
    text(identity_registry::hex(artifact.container_sha256));
    text(identity_registry::hex(artifact.canonical_pk_sha256));
    text(model.vk_sha256);
    text(identity_registry::hex(artifact.decoder_identity));
    number(artifact.container_bytes);
    number(artifact.canonical_pk_bytes);
    number(model.instances);
    number(model.witnesses);
    number(model.domain);
    return identity_registry::digest(bytes);
}

} // namespace

RegisteredAdmittedRoleBootstrap
RegisteredParentBootstrapTransport::authorize_admitted_model(
        RegisteredChildBootstrapPending&& pending,
        const packed::PackedModel& model) {
    try {
        const auto receipt = pending.public_receipt();
        const auto inherited = query_artifact(pending);
        need(inherited != nullptr);
        model.check_backing_unchanged();
        PublicInheritedSealedQueryArtifact artifact{
            .container_sha256 = identity_registry::unhex(
                inherited->container_sha256()),
            .canonical_pk_sha256 = identity_registry::unhex(
                inherited->canonical_sha256()),
            .decoder_identity = identity_registry::unhex(
                inherited->decoder_identity()),
            .container_bytes = inherited->container_bytes(),
            .canonical_pk_bytes = inherited->canonical_bytes(),
            .snapshot_device = inherited->snapshot_device(),
            .snapshot_inode = inherited->snapshot_inode(),
        };
        need(receipt.inherited_query_artifact_identity != Digest{});
        const auto& metadata = model.metadata();
        need(metadata.pk_sha256 ==
                 identity_registry::hex(artifact.canonical_pk_sha256) &&
             metadata.pk_bytes == artifact.canonical_pk_bytes &&
             actual_query_transport_identity(artifact, metadata) ==
                 identity_registry::unhex(model.query_transport_identity()));
        auto result = authorize_impl(
            std::move(pending), model.identity(),
            model.query_transport_identity(), false);
        model.check_backing_unchanged();
        return result;
    } catch (...) { refuse(); }
}

} // namespace kpi::mpc::financial::registered_driver

