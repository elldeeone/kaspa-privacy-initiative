#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "c1_contact_value_authority.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <openssl/sha.h>
#include <span>
#include <sstream>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::c1_capture {
namespace {

using Bytes = std::vector<unsigned char>;

constexpr std::array<unsigned char, 8> OFFER_MAGIC{
    'K', 'P', 'B', 'C', '1', 'O', 'F', '1'};
constexpr std::string_view ATTEMPT_DOMAIN = "KPB_CAPTURE_ATTEMPT_ID_V1\n";
constexpr std::string_view CAPTURE_DOMAIN = "KPB_CAPTURE_IDENTITY_V1\n";
constexpr std::string_view AUTHORITY_DOMAIN =
    "KPB_C1_CONTACT_VALUE_AUTHORITY_V1\n";
constexpr std::string_view STAGE_PLAN_DOMAIN =
    "KPB_C1_CONTACT_VALUE_STAGE_PLAN_V1\n";
constexpr std::string_view ROUTE_DOMAIN =
    "KPB_C1_AUTHENTICATED_INVOICE_ROUTE_V1\n";

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    (void)::close(fd);
    fd = -1;
}

class InstalledFdRollback final {
    int& source_fd_;
    bool source_is_target_{};
    bool armed_{true};
public:
    InstalledFdRollback(int& source_fd, bool source_is_target) noexcept
        : source_fd_(source_fd), source_is_target_(source_is_target) {}
    InstalledFdRollback(const InstalledFdRollback&) = delete;
    InstalledFdRollback& operator=(const InstalledFdRollback&) = delete;
    ~InstalledFdRollback() {
        if (!armed_) return;
        int target = C1_CONTACT_VALUE_OFFER_FIXED_FD;
        if (source_is_target_) source_fd_ = -1;
        close_fd(target);
    }
    void disarm() noexcept { armed_ = false; }
};

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

Digest hash(std::string_view value) {
    return hash(std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

Digest domain_hash(std::string_view domain, std::string_view value) {
    Bytes bytes(domain.begin(), domain.end());
    bytes.insert(bytes.end(), value.begin(), value.end());
    return hash(bytes);
}

std::string hex(const Digest& value) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto byte : value) {
        result.push_back(alphabet[byte >> 4]);
        result.push_back(alphabet[byte & 0x0f]);
    }
    return result;
}

bool hex_digit(char value) {
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f');
}

bool uuid4(const std::string& value) {
    if (value.size() != 36 || value[8] != '-' || value[13] != '-' ||
        value[18] != '-' || value[23] != '-' || value[14] != '4' ||
        std::string_view("89ab").find(value[19]) == std::string_view::npos)
        return false;
    for (unsigned index = 0; index < value.size(); ++index)
        if (index != 8 && index != 13 && index != 18 && index != 23 &&
            !hex_digit(value[index]))
            return false;
    return true;
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(Bytes& out, const Digest& value) { add(out, std::span(value)); }

void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

Digest stage_plan_identity(
        unsigned round, const std::array<std::string, 3>& operations) {
    Bytes bytes(STAGE_PLAN_DOMAIN.begin(), STAGE_PLAN_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(round));
    bytes.push_back(1);
    for (unsigned index = 0; index < operations.size(); ++index) {
        bytes.push_back(static_cast<unsigned char>(index));
        bytes.push_back(static_cast<unsigned char>(index + 1));
        add(bytes, operations[index]);
        bytes.push_back(index == 1 ? 1 : 0);
        if (index == 1)
            add(bytes, operations[0]);
        else
            bytes.insert(bytes.end(), 36, 0);
    }
    return hash(bytes);
}

Digest route_identity(
        unsigned round, const std::array<unsigned, 3>& contacts,
        const std::array<std::string, 3>& operations,
        const Digest& route_source) {
    Bytes bytes(ROUTE_DOMAIN.begin(), ROUTE_DOMAIN.end());
    bytes.push_back(static_cast<unsigned char>(round));
    bytes.push_back(1);
    add(bytes, route_source);
    for (unsigned index = 0; index < operations.size(); ++index) {
        bytes.push_back(static_cast<unsigned char>(index));
        bytes.push_back(static_cast<unsigned char>(contacts[index]));
        add(bytes, operations[index]);
        bytes.push_back(index == 1 ? 1 : 0);
        if (index == 1)
            add(bytes, operations[0]);
        else
            bytes.insert(bytes.end(), 36, 0);
    }
    return hash(bytes);
}

WorkerBinding c1_worker(const RunBinding& binding) {
    const auto index = static_cast<unsigned>(ManifestComponent::C1Supervisor) - 1;
    need(index < binding.finite_manifest.entries.size());
    const auto& entry = binding.finite_manifest.entries[index];
    need(entry.component == ManifestComponent::C1Supervisor);
    for (const auto* value : {
             &entry.source_identity, &entry.build_identity,
             &entry.runtime_identity, &entry.assets_identity,
             &entry.pinned_executable_identity, &entry.launcher_identity})
        need(nonzero(*value));
    return WorkerBinding{
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

std::string authority_preimage(
        const PublicC1LifecycleStagePlan& selected,
        const RunBinding& binding, unsigned fixed_fd,
        const WorkerBinding& worker, const Digest& route_manifest,
        const Digest& route_source,
        const Digest& role_launch, const Digest& process,
        const Digest& stage_plan,
        const std::array<unsigned, 3>& contacts,
        const std::array<Digest, 3>& operation_identities) {
    // This is exactly Python's canonical sort_keys/separators JSON plus LF.
    std::ostringstream out;
    out << "{\"assets_sha256\":\"" << hex(worker.assets_identity)
        << "\",\"attempt_id\":\"" << selected.capture_attempt_id
        << "\",\"build_sha256\":\"" << hex(worker.build_identity)
        << "\",\"capture_identity\":\"" << selected.capture_identity
        << "\",\"cohort_sha256\":\""
        << hex(binding.round_cohorts[selected.round - 1])
        << "\",\"contact_owner_components\":[" << contacts[0] << ','
        << contacts[1] << ',' << contacts[2] << ']'
        << ",\"financial_run_id\":\""
        << hex(binding.financial_runs[selected.round - 1])
        << "\",\"fixed_fd\":" << fixed_fd
        << ",\"launcher_sha256\":\"" << hex(worker.launcher_identity)
        << "\",\"operation_id_sha256\":[\""
        << hex(operation_identities[0]) << "\",\""
        << hex(operation_identities[1]) << "\",\""
        << hex(operation_identities[2])
        << "\"],\"owner_component\":1,\"pinned_executable_sha256\":\""
        << hex(worker.pinned_executable_identity)
        << "\",\"process_sha256\":\""
        << hex(process) << "\",\"role_launch_sha256\":\""
        << hex(role_launch) << "\",\"round\":" << selected.round
        << ",\"route_manifest_sha256\":\"" << hex(route_manifest)
        << "\",\"route_source_sha256\":\"" << hex(route_source)
        << "\",\"runtime_sha256\":\"" << hex(worker.runtime_identity)
        << "\",\"schema\":\"kpb-c1-contact-value-authority-preimage/v2\""
        << ",\"source_sha256\":\"" << hex(worker.source_identity)
        << "\",\"stage_plan_sha256\":\"" << hex(stage_plan)
        << "\"}\n";
    return out.str();
}

Bytes offer_bytes(
        const PublicC1LifecycleStagePlan& selected,
        const RunBinding& binding, unsigned fixed_fd,
        const WorkerBinding& worker, const Digest& route_manifest,
        const Digest& route_source,
        const Digest& role_launch, const Digest& process,
        const Digest& stage_plan,
        const std::array<unsigned, 3>& contacts,
        const std::array<Digest, 3>& operation_identities,
        Digest& authority_identity) {
    const auto preimage = authority_preimage(
        selected, binding, fixed_fd, worker, route_manifest, route_source,
        role_launch, process, stage_plan, contacts, operation_identities);
    Bytes authority_input(AUTHORITY_DOMAIN.begin(), AUTHORITY_DOMAIN.end());
    add(authority_input, preimage);
    authority_identity = hash(authority_input);

    Bytes out;
    out.reserve(C1_CONTACT_VALUE_OFFER_BYTES);
    add(out, OFFER_MAGIC);
    out.push_back(2);
    out.push_back(static_cast<unsigned char>(selected.round));
    out.push_back(1);
    out.push_back(static_cast<unsigned char>(fixed_fd));
    out.push_back(C1_CONTACT_VALUE_OFFER_FIXED_FD);
    out.push_back(3);
    out.push_back(static_cast<unsigned char>(contacts[0]));
    out.push_back(static_cast<unsigned char>(contacts[1]));
    out.push_back(static_cast<unsigned char>(contacts[2]));
    out.push_back(0);
    add(out, selected.capture_attempt_id);
    add(out, selected.capture_identity);
    add(out, binding.round_cohorts[selected.round - 1]);
    add(out, binding.financial_runs[selected.round - 1]);
    add(out, worker.source_identity);
    add(out, worker.build_identity);
    add(out, worker.runtime_identity);
    add(out, worker.assets_identity);
    add(out, worker.pinned_executable_identity);
    add(out, worker.launcher_identity);
    add(out, route_manifest);
    add(out, route_source);
    add(out, role_launch);
    add(out, process);
    add(out, stage_plan);
    for (const auto& operation : selected.operation_ids) add(out, operation);
    add(out, authority_identity);
    need(out.size() == C1_CONTACT_VALUE_OFFER_BYTES);
    return out;
}

void write_all(int fd, std::span<const unsigned char> value) {
    std::size_t at = 0;
    while (at < value.size()) {
        const auto count = ::write(fd, value.data() + at, value.size() - at);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
}

int sealed_memfd(std::span<const unsigned char> value) {
    int fd = ::memfd_create(
        "kpb-c1-contact-value-offer", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    need(fd >= 0);
    try {
        need(::fchmod(fd, 0600) == 0);
        write_all(fd, value);
        need(::lseek(fd, 0, SEEK_SET) == 0);
        constexpr int seals = F_SEAL_SEAL | F_SEAL_SHRINK |
                              F_SEAL_GROW | F_SEAL_WRITE;
        need(::fcntl(fd, F_ADD_SEALS, seals) == 0 &&
             (::fcntl(fd, F_GET_SEALS) & seals) == seals);
        return fd;
    } catch (...) {
        close_fd(fd);
        throw;
    }
}

} // namespace

C1LifecycleStagePlanAuthority::C1LifecycleStagePlanAuthority(
        PublicC1LifecycleStagePlan value) : value_(std::move(value)) {
    need((value_.round == 1 || value_.round == 2) &&
         uuid4(value_.capture_attempt_id) &&
         uuid4(value_.capture_identity) &&
         nonzero(value_.expected_route_identity) &&
         nonzero(value_.expected_route_source_identity));
    for (const auto& operation : value_.operation_ids) need(uuid4(operation));
    const auto index = value_.round - 1;
    need(value_.binding.round_attempts[index] == domain_hash(
             ATTEMPT_DOMAIN, value_.capture_attempt_id) &&
         value_.binding.capture == domain_hash(
             CAPTURE_DOMAIN, value_.capture_identity) &&
         value_.operation_ids[0] != value_.operation_ids[1] &&
         value_.operation_ids[0] != value_.operation_ids[2] &&
         value_.operation_ids[1] != value_.operation_ids[2] &&
         value_.stage_plan_identity == stage_plan_identity(
             value_.round, value_.operation_ids));
}

C1LifecycleStagePlanAuthority::C1LifecycleStagePlanAuthority(
        C1LifecycleStagePlanAuthority&& other) noexcept
    : value_(std::move(other.value_)),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
C1LifecycleStagePlanAuthority
C1LifecycleStagePlanAuthority::test_only_mint(
        PublicC1LifecycleStagePlan value) {
    return C1LifecycleStagePlanAuthority(std::move(value));
}
#endif

C1InvoiceRouteAuthority::C1InvoiceRouteAuthority(
        PublicC1InvoiceRoute value) : value_(std::move(value)) {
    need((value_.round == 1 || value_.round == 2) &&
         nonzero(value_.route_identity) &&
         nonzero(value_.route_source_identity));
    for (const auto& operation : value_.operation_ids) need(uuid4(operation));
    for (const auto contact : value_.contact_owner_components)
        need(contact < 3 && contact != 1);
    need(value_.operation_ids[0] != value_.operation_ids[1] &&
         value_.operation_ids[0] != value_.operation_ids[2] &&
         value_.operation_ids[1] != value_.operation_ids[2] &&
         value_.contact_owner_components[0] ==
             value_.contact_owner_components[2] &&
         value_.contact_owner_components[0] !=
             value_.contact_owner_components[1] &&
         value_.route_identity == route_identity(
             value_.round, value_.contact_owner_components,
             value_.operation_ids, value_.route_source_identity));
}

C1InvoiceRouteAuthority::C1InvoiceRouteAuthority(
        C1InvoiceRouteAuthority&& other) noexcept
    : value_(std::move(other.value_)),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
C1InvoiceRouteAuthority C1InvoiceRouteAuthority::test_only_mint(
        PublicC1InvoiceRoute value) {
    return C1InvoiceRouteAuthority(std::move(value));
}
#endif

C1ContactValueOfferAuthority::C1ContactValueOfferAuthority(int fd) : fd_(fd) {
    try {
        struct stat state{};
        constexpr int seals = F_SEAL_SEAL | F_SEAL_SHRINK |
                              F_SEAL_GROW | F_SEAL_WRITE;
        need(fd_ >= 0 && ::fstat(fd_, &state) == 0 && S_ISREG(state.st_mode) &&
             state.st_uid == ::geteuid() && (state.st_mode & 0077) == 0 &&
             state.st_size ==
                 static_cast<off_t>(C1_CONTACT_VALUE_OFFER_BYTES) &&
             (::fcntl(fd_, F_GET_SEALS) & seals) == seals &&
             (::fcntl(fd_, F_GETFD) & FD_CLOEXEC) != 0);
        device_ = static_cast<std::uint64_t>(state.st_dev);
        inode_ = static_cast<std::uint64_t>(state.st_ino);
        need(device_ != 0 && inode_ != 0);
    } catch (...) {
        close_fd(fd_);
        throw;
    }
}

C1ContactValueOfferAuthority::C1ContactValueOfferAuthority(
        C1ContactValueOfferAuthority&& other) noexcept
    : fd_(other.fd_), device_(other.device_), inode_(other.inode_),
      live_(other.live_.exchange(false))
#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
      , test_only_install_fault_(other.test_only_install_fault_)
#endif
{
    other.fd_ = -1;
#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
    other.test_only_install_fault_ = TestC1OfferInstallFault::None;
#endif
}

C1ContactValueOfferAuthority::~C1ContactValueOfferAuthority() {
    close_fd(fd_);
}

void C1ContactValueOfferAuthority::install_for_child() && {
    try {
        need(live_.exchange(false) && fd_ >= 0);
        constexpr int seals = F_SEAL_SEAL | F_SEAL_SHRINK |
                              F_SEAL_GROW | F_SEAL_WRITE;
        struct stat before{};
        const int source_flags = ::fcntl(fd_, F_GETFD);
        need(::fstat(fd_, &before) == 0 && S_ISREG(before.st_mode) &&
             before.st_uid == ::geteuid() && (before.st_mode & 0077) == 0 &&
             before.st_size ==
                 static_cast<off_t>(C1_CONTACT_VALUE_OFFER_BYTES) &&
             static_cast<std::uint64_t>(before.st_dev) == device_ &&
             static_cast<std::uint64_t>(before.st_ino) == inode_ &&
             (::fcntl(fd_, F_GET_SEALS) & seals) == seals &&
             source_flags >= 0 && (source_flags & FD_CLOEXEC) != 0);
        const int source = fd_;
        const bool source_is_target =
            source == C1_CONTACT_VALUE_OFFER_FIXED_FD;
        if (!source_is_target)
            need(::dup3(source, C1_CONTACT_VALUE_OFFER_FIXED_FD,
                        O_CLOEXEC) == C1_CONTACT_VALUE_OFFER_FIXED_FD);
        InstalledFdRollback rollback(fd_, source_is_target);
#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
        need(test_only_install_fault_ != TestC1OfferInstallFault::AfterDup);
#endif
        struct stat installed{};
        need(::fstat(C1_CONTACT_VALUE_OFFER_FIXED_FD, &installed) == 0 &&
             S_ISREG(installed.st_mode) &&
             installed.st_uid == ::geteuid() &&
             static_cast<std::uint64_t>(installed.st_dev) == device_ &&
             static_cast<std::uint64_t>(installed.st_ino) == inode_ &&
             installed.st_size ==
                 static_cast<off_t>(C1_CONTACT_VALUE_OFFER_BYTES) &&
             (::fcntl(C1_CONTACT_VALUE_OFFER_FIXED_FD, F_GET_SEALS) & seals) ==
                 seals);
#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
        need(test_only_install_fault_ !=
             TestC1OfferInstallFault::AfterInstalledFstat);
#endif
        const int flags = ::fcntl(C1_CONTACT_VALUE_OFFER_FIXED_FD, F_GETFD);
        need(flags >= 0 && (flags & FD_CLOEXEC) != 0 &&
             ::fcntl(C1_CONTACT_VALUE_OFFER_FIXED_FD, F_SETFD,
                     flags & ~FD_CLOEXEC) == 0);
#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
        need(test_only_install_fault_ !=
             TestC1OfferInstallFault::AfterClearCloexec);
#endif
        const int installed_flags =
            ::fcntl(C1_CONTACT_VALUE_OFFER_FIXED_FD, F_GETFD);
        need(installed_flags >= 0 &&
             (installed_flags & FD_CLOEXEC) == 0);
        if (source_is_target) fd_ = -1;
        else close_fd(fd_);
        rollback.disarm();
    } catch (...) {
        close_fd(fd_);
        throw;
    }
}

#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
int C1ContactValueOfferAuthority::test_only_take_fd() {
    need(live_.exchange(false) && fd_ >= 0);
    const int result = fd_;
    fd_ = -1;
    return result;
}

int C1ContactValueOfferAuthority::test_only_source_fd() const {
    need(live_.load() && fd_ >= 0);
    return fd_;
}

void C1ContactValueOfferAuthority::test_only_set_install_fault(
        TestC1OfferInstallFault fault) {
    need(live_.load() && fd_ >= 0 &&
         test_only_install_fault_ == TestC1OfferInstallFault::None &&
         fault != TestC1OfferInstallFault::None);
    test_only_install_fault_ = fault;
}
#endif

C1PostcaptureAdmissionAuthority::C1PostcaptureAdmissionAuthority(
        RunBinding binding, unsigned round, unsigned fixed_capture_fd,
        Digest contact_value_authority_identity, Digest role_launch_identity,
        Digest route_manifest_identity, Digest route_source_identity,
        Digest stage_plan_identity, Digest process_identity,
        Digest expected_child_exit_identity, WorkerBinding worker,
        std::array<unsigned, 3> contacts,
        std::array<Digest, 3> operation_identities)
    : binding_(std::move(binding)), round_(round),
      fixed_capture_fd_(fixed_capture_fd),
      contact_value_authority_identity_(contact_value_authority_identity),
      role_launch_identity_(role_launch_identity),
      route_manifest_identity_(route_manifest_identity),
      route_source_identity_(route_source_identity),
      stage_plan_identity_(stage_plan_identity),
      process_identity_(process_identity),
      expected_child_exit_identity_(expected_child_exit_identity),
      c1_worker_(worker), contact_owner_components_(contacts),
      operation_identities_(operation_identities) {
    need((round_ == 1 || round_ == 2) &&
         fixed_capture_fd_ == (round_ == 1 ? 24U : 29U));
    for (const auto* value : {
             &contact_value_authority_identity_, &role_launch_identity_,
             &route_manifest_identity_, &route_source_identity_,
             &stage_plan_identity_,
             &process_identity_, &expected_child_exit_identity_,
             &c1_worker_.source_identity, &c1_worker_.build_identity,
             &c1_worker_.runtime_identity, &c1_worker_.assets_identity,
             &c1_worker_.pinned_executable_identity,
             &c1_worker_.launcher_identity,
             &operation_identities_[0], &operation_identities_[1],
             &operation_identities_[2]})
        need(nonzero(*value));
    for (const auto contact : contact_owner_components_)
        need(contact < 3 && contact != 1);
    need(contact_owner_components_[0] == contact_owner_components_[2] &&
         contact_owner_components_[0] != contact_owner_components_[1] &&
         operation_identities_[0] != operation_identities_[1] &&
         operation_identities_[0] != operation_identities_[2] &&
         operation_identities_[1] != operation_identities_[2]);
}

C1PostcaptureAdmissionAuthority::C1PostcaptureAdmissionAuthority(
        C1PostcaptureAdmissionAuthority&& other) noexcept
    : binding_(std::move(other.binding_)), round_(other.round_),
      fixed_capture_fd_(other.fixed_capture_fd_),
      contact_value_authority_identity_(
          other.contact_value_authority_identity_),
      role_launch_identity_(other.role_launch_identity_),
      route_manifest_identity_(other.route_manifest_identity_),
      route_source_identity_(other.route_source_identity_),
      stage_plan_identity_(other.stage_plan_identity_),
      process_identity_(other.process_identity_),
      expected_child_exit_identity_(other.expected_child_exit_identity_),
      c1_worker_(other.c1_worker_),
      contact_owner_components_(other.contact_owner_components_),
      operation_identities_(other.operation_identities_),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_C1_CONTACT_VALUE_AUTHORITY_TEST_SETUP
C1PostcaptureAdmissionAuthority
C1PostcaptureAdmissionAuthority::test_only_mint(
        RunBinding binding, unsigned round, unsigned fixed_capture_fd,
        Digest contact_value_authority_identity, Digest role_launch_identity,
        Digest route_manifest_identity, Digest route_source_identity,
        Digest stage_plan_identity, Digest process_identity,
        Digest expected_child_exit_identity, WorkerBinding worker,
        std::array<unsigned, 3> contacts,
        std::array<Digest, 3> operation_identities) {
    return C1PostcaptureAdmissionAuthority(
        std::move(binding), round, fixed_capture_fd,
        contact_value_authority_identity, role_launch_identity,
        route_manifest_identity, route_source_identity, stage_plan_identity,
        process_identity, expected_child_exit_identity, worker, contacts,
        operation_identities);
}

bool C1PostcaptureAdmissionAuthority::test_only_matches(
        const RunBinding& binding, unsigned round,
        const Digest& authority, const Digest& stage_plan,
        const std::array<Digest, 3>& operations) const {
    return live_.load() && binding_ == binding && round_ == round &&
           contact_value_authority_identity_ == authority &&
           stage_plan_identity_ == stage_plan &&
           operation_identities_ == operations;
}
#endif

C1ContactValueAuthoritySplit::C1ContactValueAuthoritySplit(
        C1ContactValueOfferAuthority&& offer,
        C1PostcaptureAdmissionAuthority&& residual)
    : offer_(std::move(offer)), residual_(std::move(residual)) {}

C1ContactValueOfferAuthority
C1ContactValueAuthoritySplit::take_offer() {
    need(offer_.has_value());
    C1ContactValueOfferAuthority result(std::move(*offer_));
    offer_.reset();
    return result;
}

C1PostcaptureAdmissionAuthority
C1ContactValueAuthoritySplit::take_postcapture_residual() {
    need(residual_.has_value());
    C1PostcaptureAdmissionAuthority result(std::move(*residual_));
    residual_.reset();
    return result;
}

C1ContactValueAuthoritySplit C1ContactValueAuthorityBridge::prepare_impl(
        producer_runtime::ParentTenReadEndsAuthority& parent,
        C1LifecycleStagePlanAuthority&& stage_authority,
        C1InvoiceRouteAuthority&& route_authority,
        bool parent_round_already_claimed) {
    try {
        need(stage_authority.live_.exchange(false) &&
             route_authority.live_.exchange(false));
        const auto selected = std::move(stage_authority.value_);
        const auto route = std::move(route_authority.value_);
        need(parent.live_.load() &&
             (selected.round == 1 || selected.round == 2));
        const unsigned index = selected.round - 1;
        // Any attempted join consumes this parent/round, including a binding
        // mismatch. Retrying a failed prelaunch admission would otherwise
        // turn refusal into a selective-validity oracle.
        if (parent_round_already_claimed)
            need(parent.c1_contact_value_prepared_[index].load());
        else
            need(!parent.c1_contact_value_prepared_[index].exchange(true));
        need(
             selected.binding == parent.plan_.binding &&
             route.binding == parent.plan_.binding &&
             route.round == selected.round &&
             route.operation_ids == selected.operation_ids &&
             route.route_identity == selected.expected_route_identity &&
             route.route_source_identity ==
                 selected.expected_route_source_identity &&
             uuid4(selected.capture_attempt_id) &&
             uuid4(selected.capture_identity) &&
             nonzero(selected.stage_plan_identity) &&
             nonzero(route.route_identity) &&
             nonzero(route.route_source_identity));

        const auto& binding = parent.plan_.binding;
        need(binding.round_attempts[index] == domain_hash(
                 ATTEMPT_DOMAIN, selected.capture_attempt_id) &&
             binding.capture == domain_hash(
                 CAPTURE_DOMAIN, selected.capture_identity));

        const unsigned stream_index = index * 5 + 4;
        const auto& stream = parent.plan_.streams[stream_index];
        const unsigned fixed_fd = selected.round == 1 ? 24 : 29;
        need(stream.round == selected.round &&
             stream.kind == CaptureKind::ColluderWallet &&
             stream.fixed_fd == fixed_fd &&
             nonzero(stream.process_identity) &&
             nonzero(stream.child_exit_identity) &&
             nonzero(parent.plan_.role_closure_identity));

        const auto worker = c1_worker(binding);
        std::array<Digest, 3> operations{};
        for (unsigned operation = 0; operation < operations.size(); ++operation)
            operations[operation] = hash(selected.operation_ids[operation]);
        need(selected.stage_plan_identity == stage_plan_identity(
                 selected.round, selected.operation_ids) &&
             route.route_identity == route_identity(
                 route.round, route.contact_owner_components,
                 route.operation_ids, route.route_source_identity));
        Digest authority_identity{};
        const auto wire = offer_bytes(
            selected, binding, fixed_fd, worker,
            route.route_identity, route.route_source_identity,
            parent.plan_.role_closure_identity, stream.process_identity,
            selected.stage_plan_identity, route.contact_owner_components,
            operations, authority_identity);
        C1ContactValueOfferAuthority offer(sealed_memfd(wire));
        C1PostcaptureAdmissionAuthority residual(
            binding, selected.round, fixed_fd, authority_identity,
            parent.plan_.role_closure_identity,
            route.route_identity, route.route_source_identity,
            selected.stage_plan_identity, stream.process_identity,
            stream.child_exit_identity, worker,
            route.contact_owner_components, operations);
        return C1ContactValueAuthoritySplit(
            std::move(offer), std::move(residual));
    } catch (...) { refuse(); }
}

C1ContactValueAuthoritySplit C1ContactValueAuthorityBridge::prepare(
        producer_runtime::ParentTenReadEndsAuthority& parent,
        C1LifecycleStagePlanAuthority&& stage_authority,
        C1InvoiceRouteAuthority&& route_authority) {
    return prepare_impl(parent, std::move(stage_authority),
                        std::move(route_authority), false);
}

C1ContactValueAuthoritySplit
C1ContactValueAuthorityBridge::prepare_after_registered_claim(
        producer_runtime::ParentTenReadEndsAuthority& parent,
        C1LifecycleStagePlanAuthority&& stage_authority,
        C1InvoiceRouteAuthority&& route_authority) {
    return prepare_impl(parent, std::move(stage_authority),
                        std::move(route_authority), true);
}

} // namespace kpb::measurement::c1_capture
