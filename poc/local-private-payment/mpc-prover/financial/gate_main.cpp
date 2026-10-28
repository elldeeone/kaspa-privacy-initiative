// The fixed public, unfunded qualification has no registration or settlement
// authority. There is deliberately no initialization/reset or production-mode
// fallback in this executable: every journal must already exist.
#include "construction.hpp"
#include "financial_assignment.hpp"
#include "../history/qualification_descriptor.hpp"
#include "../packed/gzip_queries.hpp"
#include "../trace/prefix_recipe.hpp"
#include "../trace/sealed_trace.hpp"
#include <algorithm>
#include <charconv>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
using namespace kpi::mpc;
namespace h = kpi::mpc::history;
namespace f = kpi::mpc::financial;
using Bytes = std::vector<unsigned char>;
constexpr const char* MODEL = "f3ca3c18f17ed8175fa420364e9aa2824a12af4320ca1dc00ba2508f60ba28ff";
constexpr const char* SOURCE = "3ff31adfc6f2666ac53606ecf60336366d850951fda22a38b7445262f380d829";
constexpr const char* MATRIX = "c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab";
constexpr const char* TRACE = "4c3dec7c553f66e45775bff2c950417060980cf443ab83a2d198587fc604808e";
constexpr const char* LAYOUT = "9a3ee5f5eb98384273e2b608f71a60f89c49e6fc9c1029586f8f201b84617e1e";
constexpr const char* RECIPE = "ef6279fa5633c77230a8a8b8ae9b70a58770a30e6c6f5e0bcf97edba0d0e0edb";
constexpr const char* PK = "170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945";
constexpr const char* PK_GZ = "4a3d0ac3143ecc32a875af8107c923b851036363a68a8a744b97c74d0a3879ff";
constexpr const char* VK = "2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102";
constexpr const char* HEAD = "910c09f5ea30ece29b36b1d0428a7c04c10e3b2e7f6ab65457c248b45c6cddf9";
constexpr const char* CONTEXT = "6efa0e97ae8868b12743d72d45dcd46e858214e3413a1c63c1dee1ab56aacdc0";
constexpr const char* OLD_SPK = "0000aa2070e9dd7935b4467d5fab3f243bdafae624a8129efdb913e9d7e6180578557e1e87";
constexpr const char* POINT = "255798360cfa4d4c6b51b7a2f2443d1668a7e5f87cd45d01c4d683bcd76b26e800000000";
constexpr const char* STATE =
    "4b50424153543031a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0"
    "7a57ca7b22d02b09e754543daffa55519806a71d74d365673dd23f0a1db82a4b03000000"
    "7c0266741d661e9f82372372fca9e7cdccc020005a85e7a998b0b5c5dd61882401000000";
constexpr const char* SCOPE = "PUBLIC_UNFUNDED_UNREGISTERED_QUALIFICATION_ONLY";
std::filesystem::path result_path;
std::string current_phase = "public-preflight";
void need(bool condition) { if (!condition) throw std::runtime_error("financial-gate-refused"); }
void stage(const char* phase, const char* status = "running") {
    current_phase = phase;
    if (result_path.empty()) return;
    const auto temporary = result_path / "PUBLIC-STAGE.new";
    std::ofstream output(temporary);
    output << "{\"schema\":\"kpi-mascot-public-stage/v1\",\"phase\":\"" << phase
           << "\",\"status\":\"" << status << "\"}\n";
    output.close(); need(bool(output));
    std::filesystem::rename(temporary, result_path / "PUBLIC-STAGE.json");
    std::ofstream history(result_path / "PUBLIC-STAGES.jsonl", std::ios::app);
    history << "{\"schema\":\"kpi-mascot-public-stage/v1\",\"phase\":\"" << phase
            << "\",\"status\":\"" << status << "\"}\n";
    history.close(); need(bool(history));
}
Bytes bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary); need(bool(input));
    return {std::istreambuf_iterator<char>(input), {}};
}
uint64_t natural(const std::string& text, uint64_t lower, uint64_t upper) {
    need(!text.empty() && (text.size() == 1 || text[0] != '0'));
    uint64_t value{};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    need(parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && value >= lower && value <= upper);
    return value;
}
template<size_t N> std::array<unsigned char, N> fixed_hex(const std::string& text) {
    need(text.size() == 2 * N);
    std::array<unsigned char, N> result{};
    const auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
        throw std::runtime_error("financial-gate-refused");
    };
    for (size_t i = 0; i < N; ++i) result[i] = static_cast<unsigned char>(16 * digit(text[2*i]) + digit(text[2*i+1]));
    return result;
}
packed::RowsDescriptor rows() {
    return {3, 12949818, 13093029,
        {"/app/rows/A.r1cs.bin.gz", "/app/rows/B.r1cs.bin.gz", "/app/rows/C.r1cs.bin.gz"},
        {"4a78fccf7f49e9f25a77b2f212fb99b9beb0a6da63240567c13ae2d7754ff048",
         "8fe2d65194704b601f911099a5ed4123a2fd4f374aaefb1b1d620cc1603ca34c",
         "7e921a7eda84e389c91e2a9b6674b74c8c0dbc056ac78d9953976a95912f6d92"},
        {"002b86f052e75f6e98eebfd27f977c5dcb7362a15d0a25d5af6642ac0cd2ecee",
         "a32c39c1e0a087172fb396a019ee3ad3ebff5b5833281ef1d72162e38cf5d565",
         "000b71a3433cb0b0e0ed3bb155a064314710fca5be5e26088ab5606aa588dbae"},
        {132280879, 39357111, 71201926}, {1439778032, 703804592, 1036906272}, MATRIX};
}
h::Digest check_jobs(const std::array<OwnerInputContract, 3>& jobs) {
    const auto identity = f::FinancialConstruction::owner_contracts_identity(jobs);
    for (const auto& job : jobs) need(job.model_identity == MODEL && job.source_identity == SOURCE &&
        job.proving_key_identity == PK && job.verifying_key_identity == VK &&
        job.trace_identity == TRACE && job.layout_identity == LAYOUT);
    return identity;
}
void write_bytes(const char* name, std::span<const unsigned char> value) {
    const auto path = result_path / name;
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    need(fd >= 0);
    size_t offset = 0;
    while (offset < value.size()) {
        const auto count = write(fd, value.data() + offset, value.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); need(false); }
        offset += static_cast<size_t>(count);
    }
    const bool ok = fsync(fd) == 0; const bool closed = close(fd) == 0; need(ok && closed);
}
int receive_public_pk_fd(int party, const std::string& run_nonce) {
    const int socket_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    need(socket_fd >= 0);
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    const auto name = "kpb-public-pk-" + run_nonce;
    need(name.size() + 1 <= sizeof(address.sun_path));
    std::copy(name.begin(), name.end(), address.sun_path + 1); // Linux abstract socket; no pathname alias.
    const auto length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name.size());
    if (connect(socket_fd, reinterpret_cast<const sockaddr*>(&address), length) != 0) {
        close(socket_fd); need(false);
    }
    const char role = static_cast<char>('0' + party);
    if (send(socket_fd, &role, 1, MSG_NOSIGNAL) != 1) { close(socket_fd); need(false); }
    char tag{};
    iovec vector{&tag, 1};
    alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(sizeof(int))> ancillary{};
    msghdr message{};
    message.msg_iov = &vector; message.msg_iovlen = 1;
    message.msg_control = ancillary.data(); message.msg_controllen = ancillary.size();
    const auto count = recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC);
    close(socket_fd);
    const auto* header = CMSG_FIRSTHDR(&message);
    need(count == 1 && tag == 'P' && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) && header &&
        header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
        header->cmsg_len == CMSG_LEN(sizeof(int)) && CMSG_NXTHDR(&message, const_cast<cmsghdr*>(header)) == nullptr);
    int result{};
    std::memcpy(&result, CMSG_DATA(header), sizeof(result));
    need(result >= 0); return result;
}

int qualify(int argc, char** argv) {
    need(argc == 11);
    const int party = static_cast<int>(natural(argv[2], 0, 2));
    const int network_port = static_cast<int>(natural(argv[3], 1024, 65520));
    const int owner_port = static_cast<int>(natural(argv[4], 1024, 65520));
    const auto role = h::qualification::admit_role_spec(bytes(argv[5]), static_cast<unsigned>(party));
    const auto& descriptor = role.descriptor;
    need(sha256_hex(descriptor.context_bytes) == CONTEXT);
    const auto registration = bytes(descriptor.registration_file);
    need(registration == Bytes(descriptor.registration_file_bytes.begin(), descriptor.registration_file_bytes.end()) &&
        sha256_hex(registration) == h::hex(descriptor.registration_file_sha256));
    const std::array<OwnerInputContract, 3> jobs{
        load_owner_contract(argv[6]), load_owner_contract(argv[7]), load_owner_contract(argv[8])};
    const auto job_identity = check_jobs(jobs);
    const auto dependencies = h::unhex(argv[9]);
    const auto& key = descriptor.key;
    for (size_t i = 0; i < 3; ++i)
        need(jobs[0].server_certificate_sha256[i] == h::hex(key.server_certificates[i]));
    result_path = std::filesystem::absolute(argv[10]);
    need(mkdir(result_path.c_str(), 0700) == 0);
    stage("existing-qualification-history-open");
    auto journal = h::EpochJournal::open_existing(role.local_directory, role.trusted_anchor_directory,
        key, descriptor.registration_digest);
    const auto initial = journal.snapshot();
    need(initial.phase == h::Phase::Ready && initial.sequence == 0 && initial.seen_nullifiers.empty() &&
        initial.checkpoint == descriptor.initial_checkpoint);
    stage("public-transport-sealing");
    // Bubblewrap deliberately closes inherited descriptors. Standard SCM_RIGHTS
    // transfers a reference to the one public sealed inode without copying it.
    // The transport confers no model authority: actual seals/hash/point admission
    // below are mandatory even for a hostile socket peer.
    const int pk_fd = receive_public_pk_fd(party, jobs[0].run_nonce);
    std::shared_ptr<const SealedTraceArtifact> pk;
    try { pk = SealedTraceArtifact::adopt_sealed_fd(pk_fd); }
    catch (...) { close(pk_fd); throw; }
    close(pk_fd);
    const auto vk = bytes("/app/vk.bin");
    stage("stock-PK-all-point-admission-started");
    const auto query_store = packed::GzipQueryStore::admit(pk, vk, {3, 12949818, 16777216},
        {PK_GZ, PK, pk->decoder_identity(), VK, 1749414110, 2608842576});
    stage("stock-PK-all-point-admission-complete");
    stage("actual-R1CS-all-row-admission-started");
    const auto model = packed::PackedModel::admit_compressed("/app/model", query_store, "/app/vk.bin", MODEL, rows());
    stage("actual-R1CS-all-row-admission-complete");
    auto recipe = PrefixRecipe::load("/app/PREFIX-RECIPE.bin", RECIPE, 12949821, 3);
    TraceBinding trace{TRACE, SOURCE, MODEL, LAYOUT, "/app/layout.txt.gz", {0,1,2}, 12949821, 3,
        "0edbd4f22706d54a56ec5a670a2cf89f7075dd286130b3f64dbc73767cdef95c", 2576450912ULL,
        "b69d19619ebe92e5512ad268b6ba299f2e04255d504aeac1a2d3cca55ef68942", 62346077, recipe};
    const auto tail = bytes("/app/native-tail.bin");
    h::AttemptBinding binding{};
    binding.attempt = h::unhex(jobs[0].run_nonce); binding.cohort = h::unhex(jobs[0].cohort_identity);
    binding.owner_contracts = job_identity; binding.model = h::unhex(MODEL); binding.source = h::unhex(SOURCE);
    binding.dependencies = dependencies; binding.matrix = h::unhex(MATRIX); binding.trace = h::unhex(TRACE);
    binding.layout = h::unhex(LAYOUT); binding.input_map = f::FinancialConstruction::input_map_identity(model);
    binding.prefix_recipe = h::unhex(RECIPE); binding.validation_policy = f::FinancialValidatedAssignment::policy_identity();
    binding.admitted_head = h::unhex(HEAD); binding.old_point = fixed_hex<36>(POINT); binding.old_state = fixed_hex<112>(STATE);
    binding.old_reserve = 6000000000; binding.old_spk = fixed_hex<37>(OLD_SPK);
    binding.immutable_tail = h::unhex(h::qualification::TAIL_SHA);
    binding.native_parameters = f::FinancialConstruction::native_parameters_identity();
    stage("interparty-addresses-started");
    Names names(party, 3, "127.0.0.1", network_port); CryptoPlayer player(names);
    stage("interparty-TLS-ready");
    MascotContext context(player, [](const char* phase) { stage(phase); });
    stage("financial-trace-preflight-and-lock-started");
    const auto construction = f::FinancialConstruction::construct(context, model, "/app/trace.txt.gz", trace,
        jobs, tail, journal, binding, owner_port);
    stage("authenticated-financial-construction-complete");
    auto validated = f::FinancialValidatedAssignment::validate(context, construction);
    stage("complete-financial-assignment-validated");
    const auto validation_identity = validated.binding_identity(), challenge = validated.public_challenge();
    const auto residual_count = validated.residual_count();
    need(residual_count == 13127204);
    auto prepared = f::FinancialHistoryAccess::prepare(context, construction, validated);
    stage("durable-PREPARED-complete");
    auto verified = f::prove_and_verify_financial(context, std::move(validated), std::move(prepared),
        "/app/model/model.meta", "/app/vk.bin", "/app/verifier", result_path / "private-candidate.bin");
    stage("independent-Ark-financial-verification-complete");
    const auto released = f::FinancialHistoryAccess::release_verified(context, std::move(verified), std::move(prepared));
    stage("all-three-durable-EGRESS-complete");
    write_bytes("released-core.bin", released.core());
    write_bytes("released-proof.bin", released.aggregate_proof());
    write_bytes("released-projection.bin", released.projection());
    std::ofstream output(result_path / "PUBLIC-RESULT.json");
    output << "{\"schema\":\"kpi-financial-qualification-party/v1\",\"status\":\"VERIFIED_AND_DURABLE_EGRESS\","
        "\"scope\":\"" << SCOPE << "\",\"registered_financial_service\":false,\"party\":" << party
        << ",\"model_sha256\":\"" << MODEL << "\",\"trace_sha256\":\"" << TRACE
        << "\",\"construction_sha256\":\"" << construction.binding_identity()
        << "\",\"validation_sha256\":\"" << validation_identity << "\",\"residual_count\":" << residual_count
        << ",\"actual_R1CS_rows\":13093029,\"trace_assertions\":33896,\"context_byte_assertions\":276,\"historical_NF_assertions\":0"
        << ",\"public_challenge\":\"" << challenge << "\",\"effects_sha256\":\"" << h::hex(released.packet().effects)
        << "\",\"core_sha256\":\"" << sha256_hex(released.core())
        << "\",\"proof_sha256\":\"" << sha256_hex(released.aggregate_proof())
        << "\",\"projection_sha256\":\"" << sha256_hex(released.projection())
        << "\",\"egress_binding_sha256\":\"" << h::hex(released.binding_identity())
        << "\",\"payment_privacy_qualified\":false,\"native_settlement_performed\":false}\n";
    output.close(); need(bool(output)); stage("complete", "verified"); return 0;
}
}  // namespace
int main(int argc, char** argv) {
    try {
        initialize_bn254_field(); initialize_bn254_groups();
        if (argc == 5 && std::string(argv[1]) == "check-contracts") {
            (void) check_jobs({load_owner_contract(argv[2]), load_owner_contract(argv[3]), load_owner_contract(argv[4])});
            std::cout << "FINANCIAL_CONTRACTS_PASS\n"; return 0;
        }
        if (argc > 1 && std::string(argv[1]) == "qualify") return qualify(argc, argv);
        need(false);
    } catch (const mac_fail&) {
        try { stage(current_phase.c_str(), "mac-refused"); } catch (...) {}
    } catch (...) {
        try { stage(current_phase.c_str(), "refused"); } catch (...) {}
    }
    std::cerr << "KPI_FINANCIAL_QUALIFICATION_REFUSED\n"; return 1;
}
