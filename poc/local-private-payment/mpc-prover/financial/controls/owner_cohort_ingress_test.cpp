#include "../../owner_cohort_ingress.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <condition_variable>
#include <concepts>
#include <cstring>
#include <exception>
#include <mutex>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using kpi::mpc::OwnerCohortIngressState;

namespace {

template<class T>
concept ExposesArrivalOrder = requires(const T& value) {
    value.arrival_order();
};

template<class T>
concept ExposesOwnerRoute = requires(const T& value) {
    value.route_for_owner(0);
};

void refuses(auto callable) {
    bool caught = false;
    try { callable(); }
    catch (const std::runtime_error&) { caught = true; }
    assert(caught);
}

void every_arrival_order_reaches_one_seal() {
    static_assert(!ExposesArrivalOrder<OwnerCohortIngressState>);
    static_assert(!ExposesOwnerRoute<OwnerCohortIngressState>);
    std::array<unsigned, 3> order{0, 1, 2};
    do {
        OwnerCohortIngressState state({64, 64, 64});
        for (const auto role : order) state.authenticated(role);
        state.require_full_authentication();
        state.upload_complete(0, 64);
        state.upload_complete(1, 64);
        state.upload_complete(2, 64);
        state.seal();
        assert(state.sealed());
        refuses([&] { state.seal(); });
    } while (std::next_permutation(order.begin(), order.end()));
}

void incomplete_duplicate_wrong_size_and_noncanonical_refuse() {
    {
        OwnerCohortIngressState state({64, 64, 64});
        state.authenticated(2);
        refuses([&] { state.authenticated(2); });
        refuses([&] { state.upload_complete(0, 64); });
        refuses([&] { state.seal(); });
    }
    {
        OwnerCohortIngressState state({64, 64, 64});
        state.authenticated(1); state.authenticated(0); state.authenticated(2);
        refuses([&] { state.upload_complete(1, 64); });
        refuses([&] { state.upload_complete(0, 63); });
        state.upload_complete(0, 64);
        refuses([&] { state.upload_complete(0, 64); });
    }
    refuses([] { OwnerCohortIngressState state({64, 0, 64}); });
    refuses([] { OwnerCohortIngressState state({64, 96, 64}); });
}

void write_exact(int fd, const unsigned char* data, std::size_t size) {
    while (size) {
        const auto count = ::send(fd, data, size, MSG_NOSIGNAL);
        assert(count > 0);
        data += count; size -= static_cast<std::size_t>(count);
    }
}

void read_exact(int fd, unsigned char* data, std::size_t size) {
    while (size) {
        const auto count = ::recv(fd, data, size, 0);
        assert(count > 0);
        data += count; size -= static_cast<std::size_t>(count);
    }
}

struct Listener {
    int fd{-1};
    std::uint16_t port{};
    Listener() {
        fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert(fd >= 0);
        int one = 1;
        assert(::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one,
                            sizeof(one)) == 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        assert(::bind(fd, reinterpret_cast<sockaddr*>(&address),
                      sizeof(address)) == 0);
        socklen_t size = sizeof(address);
        assert(::getsockname(fd, reinterpret_cast<sockaddr*>(&address),
                             &size) == 0);
        port = ntohs(address.sin_port);
        assert(::listen(fd, 3) == 0);
    }
    ~Listener() { if (fd >= 0) (void)::close(fd); }
};

struct ArrivalGate {
    std::array<unsigned, 3> order{};
    std::size_t index{};
    std::mutex mutex;
    std::condition_variable changed;
    void wait(unsigned role) {
        std::unique_lock lock(mutex);
        changed.wait(lock, [&] { return order[index] == role; });
    }
    void advance() {
        {
            std::lock_guard lock(mutex);
            ++index;
        }
        changed.notify_all();
    }
};

int connect_to(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    assert(::connect(fd, reinterpret_cast<sockaddr*>(&address),
                     sizeof(address)) == 0);
    return fd;
}

void actual_three_server_three_client_common_ingress() {
    std::array<Listener, 3> listeners;
    std::array<ArrivalGate, 3> gates;
    gates[0].order = {2, 0, 1};
    gates[1].order = {1, 2, 0};
    gates[2].order = {0, 1, 2};
    std::mutex failures_mutex;
    std::vector<std::exception_ptr> failures;
    const auto guarded = [&](auto callable) {
        try { callable(); }
        catch (...) {
            std::lock_guard lock(failures_mutex);
            failures.push_back(std::current_exception());
        }
    };

    std::array<std::thread, 3> servers;
    for (std::size_t server = 0; server < servers.size(); ++server) {
        servers[server] = std::thread([&, server] { guarded([&] {
            std::array<int, 3> clients{-1, -1, -1};
            for (std::size_t count = 0; count < clients.size(); ++count) {
                const int fd = ::accept4(listeners[server].fd, nullptr,
                                         nullptr, SOCK_CLOEXEC);
                assert(fd >= 0);
                unsigned char role{};
                read_exact(fd, &role, 1);
                assert(role < clients.size() && clients[role] == -1);
                clients[role] = fd;
                const unsigned char specification =
                    static_cast<unsigned char>(0x40 + role);
                // This immediate public specification is the liveness-critical
                // production behavior. Waiting for the full cohort here would
                // deadlock sequential upstream Client construction.
                write_exact(fd, &specification, 1);
            }
            for (std::size_t role = 0; role < clients.size(); ++role) {
                unsigned char acknowledgment{};
                read_exact(clients[role], &acknowledgment, 1);
                assert(acknowledgment == 0x70 + role);
                const unsigned char upload = 0x55;
                write_exact(clients[role], &upload, 1);
                std::array<unsigned char, 64> frame{};
                read_exact(clients[role], frame.data(), frame.size());
                assert(std::all_of(frame.begin(), frame.end(),
                    [role](unsigned char byte) { return byte == 0x20 + role; }));
                assert(::close(clients[role]) == 0);
            }
        }); });
    }

    std::array<std::thread, 3> owners;
    for (unsigned role = 0; role < owners.size(); ++role) {
        owners[role] = std::thread([&, role] { guarded([&] {
            std::array<int, 3> sockets{-1, -1, -1};
            for (std::size_t server = 0; server < sockets.size(); ++server) {
                gates[server].wait(role);
                sockets[server] = connect_to(listeners[server].port);
                const unsigned char wire_role = static_cast<unsigned char>(role);
                write_exact(sockets[server], &wire_role, 1);
                unsigned char specification{};
                read_exact(sockets[server], &specification, 1);
                assert(specification == 0x40 + role);
                gates[server].advance();
            }
            for (const auto fd : sockets) {
                const unsigned char acknowledgment =
                    static_cast<unsigned char>(0x70 + role);
                write_exact(fd, &acknowledgment, 1);
            }
            for (const auto fd : sockets) {
                unsigned char upload{};
                read_exact(fd, &upload, 1);
                assert(upload == 0x55);
                std::array<unsigned char, 64> frame{};
                frame.fill(static_cast<unsigned char>(0x20 + role));
                write_exact(fd, frame.data(), frame.size());
                assert(::close(fd) == 0);
            }
        }); });
    }
    for (auto& owner : owners) owner.join();
    for (auto& server : servers) server.join();
    if (!failures.empty()) std::rethrow_exception(failures.front());
}

} // namespace

int main() {
    every_arrival_order_reaches_one_seal();
    incomplete_duplicate_wrong_size_and_noncanonical_refuse();
    actual_three_server_three_client_common_ingress();
}
