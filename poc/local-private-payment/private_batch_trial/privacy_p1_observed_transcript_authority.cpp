#include "privacy_p1_observed_transcript_authority.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <limits>
#include <linux/magic.h>
#include <memory>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <optional>
#include <set>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <string_view>
#include <utility>
#include <vector>

namespace kpb::measurement::p1_observed_transcript {
namespace {

constexpr std::array<unsigned char, 8> MAGIC{
    'K', 'P', 'B', 'P', '1', 'C', '0', '3'};
constexpr std::size_t HEADER_BYTES = 112;
constexpr std::size_t MAX_CHUNK_BYTES = 1U << 16;
constexpr unsigned SEMANTIC_COUNT = 17;
constexpr std::uint64_t INSTRUMENTED_MASK = (1U << SEMANTIC_COUNT) - 1;
constexpr std::uint64_t SELECTED_SCALAR_SITE_BITMAP = (1U << 22) - 1;
constexpr unsigned PEER_NONE = 0xff;

enum class RecordType : std::uint8_t {
    Hello = 1,
    Data = 2,
    ProjectionSeal = 3,
    Completeness = 4,
    End = 5,
    Fork = 6,
};

enum class Phase : std::uint8_t {
    Hello,
    Records,
    Completeness,
    End,
    Finished,
};

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char value) { return value != 0; });
}

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

std::uint32_t be32(const unsigned char* value) {
    std::uint32_t result = 0;
    for (unsigned index = 0; index < 4; ++index)
        result = (result << 8) | value[index];
    return result;
}

std::uint64_t be64(const unsigned char* value) {
    std::uint64_t result = 0;
    for (unsigned index = 0; index < 8; ++index)
        result = (result << 8) | value[index];
    return result;
}

void append_u64(std::vector<unsigned char>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

void append(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

Digest hash(std::span<const unsigned char> bytes) {
    Digest result{};
    need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr &&
         nonzero(result));
    return result;
}

class HashState final {
    struct Deleter {
        void operator()(EVP_MD_CTX* value) const { EVP_MD_CTX_free(value); }
    };
    std::unique_ptr<EVP_MD_CTX, Deleter> context_{EVP_MD_CTX_new()};
    bool finished_{};

public:
    HashState() {
        need(context_ != nullptr &&
             EVP_DigestInit_ex(context_.get(), EVP_sha256(), nullptr) == 1);
    }
    HashState(const HashState&) = delete;
    HashState& operator=(const HashState&) = delete;
    HashState(HashState&&) noexcept = default;
    HashState& operator=(HashState&&) noexcept = default;

    void update(std::span<const unsigned char> bytes) {
        need(!finished_ && (!bytes.empty() ? bytes.data() != nullptr : true) &&
             EVP_DigestUpdate(context_.get(), bytes.data(), bytes.size()) == 1);
    }

    void update(std::string_view value) {
        update({reinterpret_cast<const unsigned char*>(value.data()),
                value.size()});
    }

    Digest finish() {
        need(!finished_);
        finished_ = true;
        Digest result{};
        unsigned size = 0;
        need(EVP_DigestFinal_ex(context_.get(), result.data(), &size) == 1 &&
             size == result.size() && nonzero(result));
        return result;
    }
};

Digest hash_fd(int fd, std::uint64_t size) {
    HashState state;
    std::array<unsigned char, 1U << 16> buffer{};
    std::uint64_t offset = 0;
    while (offset < size) {
        const auto requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), size - offset));
        ssize_t count;
        do {
            count = ::pread(fd, buffer.data(), requested,
                            static_cast<off_t>(offset));
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        state.update({buffer.data(), static_cast<std::size_t>(count)});
        offset += static_cast<std::uint64_t>(count);
    }
    return state.finish();
}

void need_worker(const WorkerBinding& worker) {
    for (const auto* value : {
             &worker.source_identity, &worker.build_identity,
             &worker.runtime_identity, &worker.assets_identity,
             &worker.pinned_executable_identity, &worker.launcher_identity})
        need(nonzero(*value));
}

WorkerBinding p1_worker(const RunBinding& binding) {
    const auto index = static_cast<unsigned>(ManifestComponent::P1Capture) - 1;
    need(index < binding.finite_manifest.entries.size());
    const auto& entry = binding.finite_manifest.entries[index];
    need(entry.component == ManifestComponent::P1Capture);
    return {
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

[[maybe_unused]] void validate_plan(const StaticTranscriptPlan& plan) {
    validate_measurement_run_binding(plan.binding);
    need((plan.round == 1 || plan.round == 2) &&
         plan.fixed_fd == (plan.round == 1 ? 23U : 28U));
    need_worker(plan.p1_worker);
    need(plan.p1_worker == p1_worker(plan.binding) &&
         plan.p1_worker.source_identity == plan.binding.capture_source &&
         plan.p1_worker.build_identity == plan.binding.capture_build &&
         plan.p1_worker.runtime_identity == plan.binding.capture_runtime &&
         plan.p1_worker.launcher_identity == plan.binding.capture_launcher &&
         plan.p1_capture_source_identity == plan.binding.capture_source &&
         plan.p1_capture_build_identity == plan.binding.capture_build);
    for (const auto* value : {
             &plan.accepted_head_identity, &plan.selected_main_identity,
             &plan.p1_capture_source_identity,
             &plan.p1_capture_build_identity, &plan.model_preimage_identity,
             &plan.query_store_identity, &plan.scalar_manifest_identity,
             &plan.online_options_identity, &plan.ot_parameters_identity,
             &plan.mascot_secrets_policy_identity,
             &plan.player_virtual_surface_identity,
             &plan.expected_hello_payload_sha256,
             &plan.archive_filesystem_identity})
        need(nonzero(*value));
    need(plan.ot_extension == OtExtensionProfile::SoftSpoken ||
         plan.ot_extension == OtExtensionProfile::Kos);
    need(plan.mascot_secrets_policy ==
             MascotSecretsPolicy::FreshRegeneration ||
         plan.mascot_secrets_policy == MascotSecretsPolicy::PinnedValidCache);
}

void need_anonymous_disk_file(const struct stat& value) {
    need(S_ISREG(value.st_mode) && value.st_nlink == 0 &&
         (value.st_mode & 0777) == 0600 && value.st_size >= 0);
}

struct OpenedFile {
    int fd{-1};
    std::uint64_t device{};
    std::uint64_t inode{};
};

[[maybe_unused]] OpenedFile open_anonymous_disk_file() {
    int directory = ::open(
        "/var/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    need(directory >= 0);
    try {
        struct stat root{};
        struct statfs filesystem{};
        need(::fstat(directory, &root) == 0 && S_ISDIR(root.st_mode) &&
             ::fstatfs(directory, &filesystem) == 0 &&
             filesystem.f_type != TMPFS_MAGIC &&
             filesystem.f_type != RAMFS_MAGIC);
        int fd = ::openat(directory, ".",
                          O_TMPFILE | O_RDWR | O_CLOEXEC | O_NOFOLLOW,
                          0600);
        need(fd >= 0);
        struct stat value{};
        try {
            need(::fstat(fd, &value) == 0);
            need_anonymous_disk_file(value);
            need(value.st_size == 0 && value.st_dev == root.st_dev &&
                 (::fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDWR &&
                 (::fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
        } catch (...) {
            close_fd(fd);
            throw;
        }
        close_fd(directory);
        return {
            .fd = fd,
            .device = static_cast<std::uint64_t>(value.st_dev),
            .inode = static_cast<std::uint64_t>(value.st_ino),
        };
    } catch (...) {
        close_fd(directory);
        throw;
    }
}

int reopen_read_only(int fd) {
    std::array<char, 64> path{};
    const int size = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", fd);
    need(size > 0 && static_cast<std::size_t>(size) < path.size());
    int result = ::open(path.data(), O_RDONLY | O_CLOEXEC);
    need(result >= 0);
    try {
        need((::fcntl(result, F_GETFL) & O_ACCMODE) == O_RDONLY &&
             (::fcntl(result, F_GETFD) & FD_CLOEXEC) != 0);
        return result;
    } catch (...) {
        close_fd(result);
        throw;
    }
}

struct Counter {
    std::uint64_t messages{};
    std::uint64_t chunks{};
    std::uint64_t bytes{};
};

void increase(std::uint64_t& value, std::uint64_t amount) {
    need(value <= std::numeric_limits<std::uint64_t>::max() - amount);
    value += amount;
}

struct ParserResult {
    std::uint64_t raw_wire_bytes{};
    std::uint64_t record_count{};
    std::uint64_t peer_messages{};
    std::uint64_t peer_chunks{};
    std::uint64_t peer_payload_bytes{};
    std::uint64_t peer_wire_bytes{};
    std::uint64_t fork_messages{};
    std::uint64_t fork_wire_bytes{};
    Digest raw_wire_sha256{};
    Digest ordered_peer_vector_sha256{};
    Digest ordered_fork_vector_sha256{};
};

class Parser final {
    struct Message {
        bool open{};
        RecordType type{};
        std::uint8_t semantic{};
        std::uint8_t direction{};
        std::uint8_t peer{};
        std::array<unsigned char, 32> fork{};
        std::uint64_t id{};
        std::uint64_t next_chunk{};
        std::uint64_t payload_bytes{};
        std::uint64_t chunks{};
        std::unique_ptr<HashState> payload_hash;
    } message_;

    const StaticTranscriptPlan& plan_;
    Phase phase_{Phase::Hello};
    std::vector<unsigned char> header_;
    std::vector<unsigned char> payload_;
    std::uint32_t payload_target_{};
    std::uint64_t next_sequence_{};
    std::uint64_t next_message_{};
    std::uint64_t first_monotonic_ns_{};
    std::uint64_t last_monotonic_ns_{};
    std::uint64_t last_before_frame_{};
    std::array<Counter, SEMANTIC_COUNT> counters_{};
    std::array<std::uint64_t, 3> owner_offset_bytes_{};
    std::array<std::uint64_t, 3> owner_preprocessing_bytes_{};
    std::uint8_t owner_offset_mask_{};
    std::uint8_t owner_preprocessing_mask_{};
    std::uint64_t scalar_site_bitmap_{};
    std::uint8_t scalar_expected_semantic_{};
    std::uint64_t scalar_expected_bytes_{};
    bool mac_key_recorded_{};
    unsigned proof_stage_{};
    std::array<unsigned char, 130> base_a_{};
    std::array<unsigned char, 258> base_b2_{};
    Digest projection_digest_{};
    bool saw_projection_data_{};
    bool saw_projection_seal_{};
    bool saw_completeness_{};
    bool saw_end_{};
    std::set<std::array<unsigned char, 32>> forks_{{}};
    HashState raw_hash_;
    HashState peer_vector_hash_;
    HashState fork_vector_hash_;
    ParserResult result_{};

    RecordType type() const {
        return static_cast<RecordType>(header_.at(8));
    }

    std::array<unsigned char, 32> header_fork() const {
        std::array<unsigned char, 32> result{};
        std::copy_n(header_.begin() + 48, result.size(), result.begin());
        return result;
    }

    static bool random_site(unsigned site) {
        return site == 1 || site == 7 || site == 20 || site == 21;
    }

    void validate_message_start() {
        const auto selected_type = type();
        const auto semantic = header_[9];
        const auto direction = header_[10];
        const auto peer = header_[11];
        const auto flags = header_[12];
        const auto message_id = be64(header_.data() + 32);
        const auto chunk = be32(header_.data() + 40);
        const auto fork = header_fork();
        need(message_id == next_message_ && chunk == 0 &&
             (flags == 1 || flags == 3) && forks_.contains(fork));
        if (scalar_expected_semantic_ != 0)
            need(selected_type == RecordType::Data);

        switch (phase_) {
        case Phase::Hello:
            need(selected_type == RecordType::Hello && semantic == 1 &&
                 direction == 3 && peer == PEER_NONE && flags == 3 &&
                 fork == std::array<unsigned char, 32>{} &&
                 payload_target_ == 332);
            break;
        case Phase::Records:
            need(selected_type == RecordType::Data ||
                 selected_type == RecordType::Fork ||
                 selected_type == RecordType::ProjectionSeal);
            if (selected_type == RecordType::Fork)
                need(semantic == 2 && direction == 3 && peer == PEER_NONE &&
                     flags == 3 && payload_target_ == 96);
            if (selected_type == RecordType::ProjectionSeal)
                need(semantic == 9 && direction == 3 && peer == PEER_NONE &&
                     flags == 3 && fork == std::array<unsigned char, 32>{} &&
                     payload_target_ == 32);
            break;
        case Phase::Completeness:
            need(selected_type == RecordType::Completeness && semantic == 9 &&
                 direction == 3 && peer == PEER_NONE && flags == 3 &&
                 fork == std::array<unsigned char, 32>{} &&
                 payload_target_ == 496);
            break;
        case Phase::End:
            need(selected_type == RecordType::End && semantic == 9 &&
                 direction == 3 && peer == PEER_NONE && flags == 3 &&
                 fork == std::array<unsigned char, 32>{} &&
                 payload_target_ == 0);
            break;
        case Phase::Finished:
            refuse();
        }

        if (selected_type == RecordType::Data) {
            if (semantic == 2) {
                need((direction == 1 || direction == 2) &&
                     (peer == 0 || peer == 2));
            } else if (semantic == 1) {
                need(direction == 2 && peer <= 2 &&
                     (owner_offset_mask_ & (1U << peer)) == 0);
            } else if (semantic == 11) {
                need(direction == 1 && peer <= 2 &&
                     (owner_preprocessing_mask_ & (1U << peer)) == 0);
            } else {
                need(direction == 3 && peer == PEER_NONE);
            }
            if (semantic == 14)
                need(!mac_key_recorded_);
            else if (semantic != 2)
                need(mac_key_recorded_);
            if (scalar_expected_semantic_ != 0)
                need(semantic == scalar_expected_semantic_);
            else
                need(semantic != 3 && semantic != 4 &&
                     semantic != 5 && semantic != 6);
        }

        message_.open = true;
        message_.type = selected_type;
        message_.semantic = semantic;
        message_.direction = direction;
        message_.peer = peer;
        message_.fork = fork;
        message_.id = message_id;
        message_.next_chunk = 0;
        message_.payload_bytes = 0;
        message_.chunks = 0;
        message_.payload_hash = std::make_unique<HashState>();
    }

    void validate_continuation() {
        const auto flags = header_[12];
        need(message_.open && type() == message_.type &&
             header_[9] == message_.semantic &&
             header_[10] == message_.direction &&
             header_[11] == message_.peer &&
             header_fork() == message_.fork &&
             be64(header_.data() + 32) == message_.id &&
             be32(header_.data() + 40) == message_.next_chunk &&
             (flags == 0 || flags == 2));
    }

    void start_frame() {
        need(header_.size() == HEADER_BYTES &&
             std::equal(MAGIC.begin(), MAGIC.end(), header_.begin()) &&
             header_[13] == 0 && header_[14] == 0 && header_[15] == 0);
        const auto encoded_type = header_[8];
        const auto semantic = header_[9];
        const auto direction = header_[10];
        const auto peer = header_[11];
        const auto flags = header_[12];
        const auto monotonic_ns = be64(header_.data() + 16);
        const auto sequence = be64(header_.data() + 24);
        payload_target_ = be32(header_.data() + 44);
        need(encoded_type >= 1 && encoded_type <= 6 &&
             semantic >= 1 && semantic <= SEMANTIC_COUNT &&
             direction >= 1 && direction <= 3 && flags <= 3 &&
             payload_target_ <= MAX_CHUNK_BYTES &&
             sequence == next_sequence_ && monotonic_ns > 0 &&
             monotonic_ns >= last_monotonic_ns_ &&
             ((direction == 3 && peer == PEER_NONE) ||
              (direction != 3 && peer <= 2)));
        last_before_frame_ = last_monotonic_ns_;
        if (first_monotonic_ns_ == 0) first_monotonic_ns_ = monotonic_ns;
        last_monotonic_ns_ = monotonic_ns;
        need(next_sequence_ != std::numeric_limits<std::uint64_t>::max());
        ++next_sequence_;
        if (!message_.open) validate_message_start();
        else validate_continuation();
        payload_.clear();
        payload_.reserve(payload_target_);
    }

    void add_vector_event(HashState& state, std::string_view domain,
                          const Digest& payload_hash) {
        std::vector<unsigned char> encoded;
        encoded.insert(encoded.end(), domain.begin(), domain.end());
        append_u64(encoded, message_.id);
        encoded.push_back(message_.semantic);
        encoded.push_back(message_.direction);
        encoded.push_back(message_.peer);
        append(encoded, message_.fork);
        append_u64(encoded, message_.payload_bytes);
        append_u64(encoded, message_.chunks);
        append(encoded, payload_hash);
        state.update(encoded);
    }

    void finish_data_message(const Digest& payload_hash) {
        auto& lane = counters_.at(message_.semantic - 1);
        increase(lane.messages, 1);
        if (message_.semantic == 2) {
            increase(result_.peer_messages, 1);
            add_vector_event(peer_vector_hash_, "KPB_P1_PEER_EVENT_V1\n",
                             payload_hash);
        } else if (message_.semantic == 1) {
            need(message_.chunks == 1 && message_.peer <= 2 &&
                 message_.payload_bytes > 0 &&
                 message_.payload_bytes % 32 == 0);
            owner_offset_mask_ |= static_cast<std::uint8_t>(
                1U << message_.peer);
            owner_offset_bytes_[message_.peer] = message_.payload_bytes;
        } else if (message_.semantic == 11) {
            need(message_.peer <= 2 && message_.payload_bytes > 0 &&
                 message_.payload_bytes % 32 == 0);
            owner_preprocessing_mask_ |= static_cast<std::uint8_t>(
                1U << message_.peer);
            owner_preprocessing_bytes_[message_.peer] =
                message_.payload_bytes;
        } else if (message_.semantic == 17) {
            need(message_.chunks == 1 && payload_.size() == 16 &&
                 payload_[0] == 1 &&
                 (payload_[1] == 1 || payload_[1] == 2) &&
                 payload_[12] == 0 && payload_[13] == 0 &&
                 payload_[14] == 0 && payload_[15] == 0);
            const unsigned site =
                (static_cast<unsigned>(payload_[2]) << 8) | payload_[3];
            const auto count = be64(payload_.data() + 4);
            need(site >= 1 && site <= 22 && count > 0 &&
                 random_site(site) == (payload_[1] == 2) &&
                 count <= std::numeric_limits<std::uint64_t>::max() / 32);
            scalar_site_bitmap_ |= std::uint64_t{1} << (site - 1);
            scalar_expected_semantic_ = payload_[1] == 1 ? 3 : 5;
            scalar_expected_bytes_ = count * 32;
        } else if (message_.semantic == scalar_expected_semantic_) {
            need(message_.payload_bytes == scalar_expected_bytes_);
            if (scalar_expected_semantic_ == 3)
                scalar_expected_semantic_ = 4;
            else if (scalar_expected_semantic_ == 5)
                scalar_expected_semantic_ = 6;
            else {
                scalar_expected_semantic_ = 0;
                scalar_expected_bytes_ = 0;
            }
        } else if (message_.semantic == 14) {
            need(message_.chunks == 1 && message_.payload_bytes == 32);
            mac_key_recorded_ = true;
        } else if (message_.semantic == 15) {
            need(message_.chunks == 1 && !payload_.empty());
            const auto stage = payload_[0];
            if (stage == 1) {
                need(proof_stage_ == 0 && payload_.size() == 521);
                std::copy_n(payload_.begin() + 1, base_a_.size(),
                            base_a_.begin());
                proof_stage_ = 1;
            } else if (stage == 2) {
                need(proof_stage_ == 2 && payload_.size() == 781);
                proof_stage_ = 3;
            } else if (stage == 3) {
                need(proof_stage_ == 5 && payload_.size() == 261);
                proof_stage_ = 6;
            } else if (stage == 4) {
                need(proof_stage_ == 6 && payload_.size() == 261 &&
                     std::equal(base_a_.begin(), base_a_.end(),
                                payload_.begin() + 1));
                proof_stage_ = 7;
            } else {
                refuse();
            }
        } else if (message_.semantic == 16) {
            need(message_.chunks == 1 && payload_.size() == 259);
            const auto stage = payload_[0];
            if (stage == 1) {
                need(proof_stage_ == 1);
                std::copy_n(payload_.begin() + 1, base_b2_.size(),
                            base_b2_.begin());
                proof_stage_ = 2;
            } else if (stage == 4) {
                need(proof_stage_ == 7 &&
                     std::equal(base_b2_.begin(), base_b2_.end(),
                                payload_.begin() + 1));
                proof_stage_ = 8;
            } else {
                refuse();
            }
        } else if (message_.semantic == 13) {
            need(proof_stage_ == 3 && message_.chunks == 1 &&
                 message_.payload_bytes == 64);
            proof_stage_ = 4;
        } else if (message_.semantic == 12) {
            need(proof_stage_ == 4 && message_.chunks == 1 &&
                 message_.payload_bytes == 130);
            proof_stage_ = 5;
        } else if (message_.semantic == 7) {
            need(proof_stage_ == 8 && message_.chunks == 1 &&
                 message_.payload_bytes == 130);
            proof_stage_ = 9;
        } else if (message_.semantic == 8) {
            need(proof_stage_ == 9 && message_.chunks == 1 &&
                 message_.payload_bytes == 129);
            proof_stage_ = 10;
        } else if (message_.semantic == 9) {
            need(!saw_projection_data_ && message_.chunks == 1 &&
                 message_.payload_bytes == 10685);
            projection_digest_ = payload_hash;
            saw_projection_data_ = true;
        } else if (message_.semantic == 10) {
            need(message_.payload_bytes > 0 &&
                 message_.payload_bytes % 32 == 0);
        }
    }

    void finish_fork_message(const Digest& payload_hash) {
        need(payload_.size() == 96 &&
             std::equal(message_.fork.begin(), message_.fork.end(),
                        payload_.begin()));
        std::array<unsigned char, 32> child{};
        std::copy_n(payload_.begin() + 32, child.size(), child.begin());
        need(child != std::array<unsigned char, 32>{} &&
             forks_.insert(child).second);
        increase(result_.fork_messages, 1);
        add_vector_event(fork_vector_hash_, "KPB_P1_FORK_EVENT_V1\n",
                         payload_hash);
    }

    void validate_completeness() {
        need(payload_.size() == 496 && be32(payload_.data()) == 9 &&
             be32(payload_.data() + 4) == SEMANTIC_COUNT);
        std::uint64_t total_messages = 0;
        std::uint64_t total_chunks = 0;
        std::uint64_t total_bytes = 0;
        for (unsigned semantic = 0; semantic < SEMANTIC_COUNT; ++semantic) {
            const auto offset = 32 + semantic * 24;
            const Counter encoded{
                .messages = be64(payload_.data() + offset),
                .chunks = be64(payload_.data() + offset + 8),
                .bytes = be64(payload_.data() + offset + 16),
            };
            const auto& actual = counters_[semantic];
            need(encoded.messages == actual.messages &&
                 encoded.chunks == actual.chunks &&
                 encoded.bytes == actual.bytes);
            increase(total_messages, actual.messages);
            increase(total_chunks, actual.chunks);
            increase(total_bytes, actual.bytes);
        }
        need(be64(payload_.data() + 8) == total_messages &&
             be64(payload_.data() + 16) == total_chunks &&
             be64(payload_.data() + 24) == total_bytes &&
             be64(payload_.data() + 440) == INSTRUMENTED_MASK &&
             be64(payload_.data() + 448) == owner_offset_mask_ &&
             be64(payload_.data() + 456) == owner_preprocessing_mask_ &&
             be64(payload_.data() + 464) == scalar_site_bitmap_ &&
             be64(payload_.data() + 472) == next_sequence_ - 1 &&
             be64(payload_.data() + 480) == first_monotonic_ns_ &&
             be64(payload_.data() + 488) == last_before_frame_ &&
             owner_offset_mask_ == 0x07 &&
             owner_preprocessing_mask_ == 0x07 &&
             scalar_site_bitmap_ == SELECTED_SCALAR_SITE_BITMAP &&
             scalar_expected_semantic_ == 0);
        for (unsigned owner = 0; owner < 3; ++owner)
            need(owner_offset_bytes_[owner] > 0 &&
                 owner_offset_bytes_[owner] <=
                     std::numeric_limits<std::uint64_t>::max() / 5 &&
                 owner_preprocessing_bytes_[owner] ==
                     5 * owner_offset_bytes_[owner]);
        const auto exact_lane = [&](unsigned semantic,
                                    std::uint64_t messages,
                                    std::uint64_t chunks,
                                    std::uint64_t bytes) {
            const auto& lane = counters_.at(semantic - 1);
            need(lane.messages == messages && lane.chunks == chunks &&
                 lane.bytes == bytes);
        };
        exact_lane(13, 1, 1, 64);
        exact_lane(12, 1, 1, 130);
        exact_lane(7, 1, 1, 130);
        exact_lane(8, 1, 1, 129);
        exact_lane(9, 1, 1, 10685);
        exact_lane(14, 1, 1, 32);
        exact_lane(15, 4, 4, 1824);
        exact_lane(16, 2, 2, 518);
        const auto& bindings = counters_.at(16);
        const auto& auth_shares = counters_.at(2);
        const auto& auth_macs = counters_.at(3);
        const auto& random_shares = counters_.at(4);
        const auto& random_macs = counters_.at(5);
        need(auth_shares.messages == auth_macs.messages &&
             auth_shares.bytes == auth_macs.bytes &&
             random_shares.messages == random_macs.messages &&
             random_shares.bytes == random_macs.bytes &&
             auth_shares.messages <=
                 std::numeric_limits<std::uint64_t>::max() -
                     random_shares.messages &&
             bindings.messages == auth_shares.messages +
                 random_shares.messages &&
             bindings.chunks == bindings.messages &&
             bindings.messages <=
                 std::numeric_limits<std::uint64_t>::max() / 16 &&
             bindings.bytes == 16 * bindings.messages);
    }

    void finish_message() {
        const auto payload_hash = message_.payload_hash->finish();
        switch (message_.type) {
        case RecordType::Hello:
            need(payload_.size() == 332 &&
                 payload_[0] == plan_.round && payload_[1] == 1 &&
                 payload_[2] == 0 && payload_[3] == plan_.fixed_fd &&
                 hash(payload_) == plan_.expected_hello_payload_sha256);
            phase_ = Phase::Records;
            break;
        case RecordType::Data:
            finish_data_message(payload_hash);
            break;
        case RecordType::Fork:
            finish_fork_message(payload_hash);
            break;
        case RecordType::ProjectionSeal:
            need(saw_projection_data_ && !saw_projection_seal_ &&
                 payload_.size() == projection_digest_.size() &&
                 std::equal(projection_digest_.begin(),
                            projection_digest_.end(), payload_.begin()) &&
                 proof_stage_ == 10);
            saw_projection_seal_ = true;
            phase_ = Phase::Completeness;
            break;
        case RecordType::Completeness:
            need(saw_projection_seal_ && !saw_completeness_);
            validate_completeness();
            saw_completeness_ = true;
            phase_ = Phase::End;
            break;
        case RecordType::End:
            need(saw_completeness_ && !saw_end_);
            saw_end_ = true;
            phase_ = Phase::Finished;
            break;
        }
        message_.payload_hash.reset();
        message_.open = false;
        need(next_message_ != std::numeric_limits<std::uint64_t>::max());
        ++next_message_;
    }

    void finish_frame() {
        need(payload_.size() == payload_target_ && message_.open);
        const auto digest = hash(payload_);
        need(std::equal(digest.begin(), digest.end(), header_.begin() + 80));
        message_.payload_hash->update(payload_);
        increase(message_.payload_bytes, payload_.size());
        increase(message_.chunks, 1);
        increase(result_.record_count, 1);
        if (message_.type == RecordType::Data) {
            auto& lane = counters_.at(message_.semantic - 1);
            increase(lane.chunks, 1);
            increase(lane.bytes, payload_.size());
            if (message_.semantic == 2) {
                increase(result_.peer_chunks, 1);
                increase(result_.peer_payload_bytes, payload_.size());
                increase(result_.peer_wire_bytes,
                         HEADER_BYTES + payload_.size());
            }
        } else if (message_.type == RecordType::Fork) {
            increase(result_.fork_wire_bytes,
                     HEADER_BYTES + payload_.size());
        }
        const bool last = (header_[12] & 2) != 0;
        ++message_.next_chunk;
        if (last) finish_message();
        header_.clear();
        payload_.clear();
        payload_target_ = 0;
    }

public:
    explicit Parser(const StaticTranscriptPlan& plan) : plan_(plan) {
        peer_vector_hash_.update("KPB_P1_ORDERED_PEER_VECTOR_V1\n");
        fork_vector_hash_.update("KPB_P1_ORDERED_FORK_VECTOR_V1\n");
    }

    void consume(std::span<const unsigned char> bytes) {
        need(phase_ != Phase::Finished && !bytes.empty());
        raw_hash_.update(bytes);
        increase(result_.raw_wire_bytes, bytes.size());
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            if (header_.size() < HEADER_BYTES) {
                const auto amount = std::min(
                    HEADER_BYTES - header_.size(), bytes.size() - offset);
                header_.insert(header_.end(), bytes.begin() + offset,
                               bytes.begin() + offset + amount);
                offset += amount;
                if (header_.size() == HEADER_BYTES) {
                    start_frame();
                    if (payload_target_ == 0) finish_frame();
                }
                continue;
            }
            need(payload_.size() < payload_target_);
            const auto amount = std::min<std::size_t>(
                payload_target_ - payload_.size(), bytes.size() - offset);
            payload_.insert(payload_.end(), bytes.begin() + offset,
                            bytes.begin() + offset + amount);
            offset += amount;
            if (payload_.size() == payload_target_) finish_frame();
        }
    }

    ParserResult finish_eof() {
        need(phase_ == Phase::Finished && saw_end_ && !message_.open &&
             header_.empty() && payload_.empty() &&
             result_.raw_wire_bytes > 0 && result_.record_count > 0 &&
             result_.peer_messages > 0 && mac_key_recorded_ &&
             proof_stage_ == 10 && saw_projection_data_);
        result_.raw_wire_sha256 = raw_hash_.finish();
        result_.ordered_peer_vector_sha256 = peer_vector_hash_.finish();
        result_.ordered_fork_vector_sha256 = fork_vector_hash_.finish();
        return result_;
    }
};

} // namespace

struct ObservedTranscriptPlanAuthority::Storage {
    StaticTranscriptPlan plan;
    int fd{-1};
    std::uint64_t device{};
    std::uint64_t inode{};
    std::atomic_bool live{true};
    ~Storage() { close_fd(fd); }
};

struct ObservedTranscriptWriterAuthority::Storage {
    StaticTranscriptPlan plan;
    int fd{-1};
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint64_t size{};
    Parser parser;
    std::atomic_bool live{true};
    bool poisoned{};
    explicit Storage(const StaticTranscriptPlan& selected)
        : plan(selected), parser(plan) {}
    ~Storage() { close_fd(fd); }
};

struct ObservedTranscriptCompletionAuthority::Storage {
    StaticTranscriptPlan plan;
    int fd{-1};
    std::uint64_t device{};
    std::uint64_t inode{};
    ParserResult result;
    bool writer_closed{};
    std::atomic_bool live{true};
    ~Storage() { close_fd(fd); }
};

ObservedTranscriptPlanAuthority::ObservedTranscriptPlanAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}

ObservedTranscriptPlanAuthority::ObservedTranscriptPlanAuthority(
        ObservedTranscriptPlanAuthority&&) noexcept = default;
ObservedTranscriptPlanAuthority::~ObservedTranscriptPlanAuthority() = default;

ObservedTranscriptWriterAuthority
ObservedTranscriptPlanAuthority::begin_capture() && {
    need(storage_ != nullptr && storage_->live.exchange(false) &&
         storage_->fd >= 0);
    auto result = std::make_unique<ObservedTranscriptWriterAuthority::Storage>(
        storage_->plan);
    result->fd = std::exchange(storage_->fd, -1);
    result->device = storage_->device;
    result->inode = storage_->inode;
    return ObservedTranscriptWriterAuthority(std::move(result));
}

#ifdef KPB_P1_OBSERVED_TRANSCRIPT_TEST_SETUP
ObservedTranscriptPlanAuthority
ObservedTranscriptPlanAuthority::test_only_mint(StaticTranscriptPlan plan) {
    validate_plan(plan);
    auto opened = open_anonymous_disk_file();
    auto storage = std::make_unique<Storage>();
    storage->plan = std::move(plan);
    storage->fd = std::exchange(opened.fd, -1);
    storage->device = opened.device;
    storage->inode = opened.inode;
    return ObservedTranscriptPlanAuthority(std::move(storage));
}
#endif

ObservedTranscriptWriterAuthority::ObservedTranscriptWriterAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}

ObservedTranscriptWriterAuthority::ObservedTranscriptWriterAuthority(
        ObservedTranscriptWriterAuthority&&) noexcept = default;
ObservedTranscriptWriterAuthority::~ObservedTranscriptWriterAuthority() =
    default;

void ObservedTranscriptWriterAuthority::append(
        std::span<const unsigned char> bytes) {
    need(storage_ != nullptr && storage_->live.load() &&
         !storage_->poisoned && storage_->fd >= 0 && !bytes.empty());
    try {
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const auto count = ::write(storage_->fd, bytes.data() + offset,
                                       bytes.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            need(count > 0);
            const auto amount = static_cast<std::uint64_t>(count);
            need(storage_->size <=
                 std::numeric_limits<std::uint64_t>::max() - amount);
            storage_->size += amount;
            offset += static_cast<std::size_t>(count);
        }
        storage_->parser.consume(bytes);
    } catch (...) {
        storage_->poisoned = true;
        refuse();
    }
}

ObservedTranscriptCompletionAuthority
ObservedTranscriptWriterAuthority::finish_after_kernel_eof() && {
    need(storage_ != nullptr && storage_->live.exchange(false) &&
         !storage_->poisoned && storage_->fd >= 0);
    int read_only = -1;
    try {
        auto parsed = storage_->parser.finish_eof();
        struct stat before{};
        need(::fstat(storage_->fd, &before) == 0);
        need_anonymous_disk_file(before);
        need(static_cast<std::uint64_t>(before.st_dev) == storage_->device &&
             static_cast<std::uint64_t>(before.st_ino) == storage_->inode &&
             static_cast<std::uint64_t>(before.st_size) == storage_->size &&
             parsed.raw_wire_bytes == storage_->size &&
             ::fsync(storage_->fd) == 0 &&
             hash_fd(storage_->fd, storage_->size) ==
                 parsed.raw_wire_sha256);
        read_only = reopen_read_only(storage_->fd);
        struct stat after{};
        need(::fstat(read_only, &after) == 0);
        need_anonymous_disk_file(after);
        need(static_cast<std::uint64_t>(after.st_dev) == storage_->device &&
             static_cast<std::uint64_t>(after.st_ino) == storage_->inode &&
             static_cast<std::uint64_t>(after.st_size) == storage_->size &&
             hash_fd(read_only, storage_->size) == parsed.raw_wire_sha256);
        close_fd(storage_->fd);
        struct stat sealed{};
        need(::fstat(read_only, &sealed) == 0);
        need_anonymous_disk_file(sealed);
        need(static_cast<std::uint64_t>(sealed.st_dev) == storage_->device &&
             static_cast<std::uint64_t>(sealed.st_ino) == storage_->inode &&
             static_cast<std::uint64_t>(sealed.st_size) == storage_->size &&
             hash_fd(read_only, storage_->size) == parsed.raw_wire_sha256);

        auto completion =
            std::make_unique<ObservedTranscriptCompletionAuthority::Storage>();
        completion->plan = storage_->plan;
        completion->fd = std::exchange(read_only, -1);
        completion->device = storage_->device;
        completion->inode = storage_->inode;
        completion->result = parsed;
        completion->writer_closed = true;
        return ObservedTranscriptCompletionAuthority(std::move(completion));
    } catch (...) {
        close_fd(read_only);
        storage_->poisoned = true;
        refuse();
    }
}

ObservedTranscriptCompletionAuthority::ObservedTranscriptCompletionAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}

ObservedTranscriptCompletionAuthority::ObservedTranscriptCompletionAuthority(
        ObservedTranscriptCompletionAuthority&&) noexcept = default;
ObservedTranscriptCompletionAuthority::~ObservedTranscriptCompletionAuthority() =
    default;

#ifdef KPB_P1_OBSERVED_TRANSCRIPT_TEST_SETUP
ObservedTranscriptCompletionAuthority::TestOnlySummary
ObservedTranscriptCompletionAuthority::test_only_summary() const {
    need(storage_ != nullptr && storage_->live.load() && storage_->fd >= 0);
    struct stat value{};
    need(::fstat(storage_->fd, &value) == 0);
    return {
        .plan = storage_->plan,
        .raw_wire_bytes = storage_->result.raw_wire_bytes,
        .record_count = storage_->result.record_count,
        .peer_messages = storage_->result.peer_messages,
        .peer_chunks = storage_->result.peer_chunks,
        .peer_payload_bytes = storage_->result.peer_payload_bytes,
        .peer_wire_bytes = storage_->result.peer_wire_bytes,
        .fork_messages = storage_->result.fork_messages,
        .fork_wire_bytes = storage_->result.fork_wire_bytes,
        .raw_wire_sha256 = storage_->result.raw_wire_sha256,
        .ordered_peer_vector_sha256 =
            storage_->result.ordered_peer_vector_sha256,
        .ordered_fork_vector_sha256 =
            storage_->result.ordered_fork_vector_sha256,
        .read_only =
            (::fcntl(storage_->fd, F_GETFL) & O_ACCMODE) == O_RDONLY,
        .anonymous_disk_backed = S_ISREG(value.st_mode) &&
            value.st_nlink == 0 && (value.st_mode & 0777) == 0600,
        .writer_closed = storage_->writer_closed,
    };
}

std::vector<unsigned char>
ObservedTranscriptCompletionAuthority::test_only_read_all() const {
    need(storage_ != nullptr && storage_->live.load() && storage_->fd >= 0 &&
         storage_->result.raw_wire_bytes <=
             std::numeric_limits<std::size_t>::max());
    std::vector<unsigned char> result(
        static_cast<std::size_t>(storage_->result.raw_wire_bytes));
    std::size_t offset = 0;
    while (offset < result.size()) {
        ssize_t count;
        do {
            count = ::pread(storage_->fd, result.data() + offset,
                            result.size() - offset,
                            static_cast<off_t>(offset));
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        offset += static_cast<std::size_t>(count);
    }
    return result;
}
#endif

} // namespace kpb::measurement::p1_observed_transcript
