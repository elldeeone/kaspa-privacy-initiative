#pragma once

// Complete, dependency-neutral friend contract joining source-owned honest
// owner production to the V3 invoice lifecycle.  Implementations live in the
// honest-owner authority TU; this file intentionally exposes no material,
// invoice, index, owner, round, or output accessor.

namespace kpb::measurement {
struct RunBinding;
}

namespace kpb::future_recipient::v3_native {
class InvoiceMaterialAuthority;
class AcceptedInvoiceAuthority;
class ParentV3Authority;
}

namespace kpb::honest_owner_material {

class HonestInvoiceSourceAuthority;
class HonestOwnerOutputAuthority;
class HonestOwnerProductionAuthority;

class V3InvoiceMaterialMinter final {
    V3InvoiceMaterialMinter() = delete;
public:
    static future_recipient::v3_native::InvoiceMaterialAuthority mint(
        HonestInvoiceSourceAuthority&&,
        future_recipient::v3_native::ParentV3Authority&,
        const measurement::RunBinding&);

    static HonestOwnerProductionAuthority consume_for_output(
        future_recipient::v3_native::ParentV3Authority&,
        future_recipient::v3_native::AcceptedInvoiceAuthority&&,
        HonestOwnerOutputAuthority&&);
#ifdef KPB_HONEST_OWNER_MATERIAL_TEST_SETUP
    static HonestInvoiceSourceAuthority test_only_bind_to_parent(
        HonestInvoiceSourceAuthority&&,
        future_recipient::v3_native::ParentV3Authority&);
    static HonestOwnerOutputAuthority test_only_bind_to_parent(
        HonestOwnerOutputAuthority&&,
        future_recipient::v3_native::ParentV3Authority&);
#endif
};

} // namespace kpb::honest_owner_material
