#include "owner_connections.hpp"
#include "Networking/ServerSocket.h"
#include <charconv>
#include <deque>
#include <map>
#include <stdexcept>

namespace kpi::mpc {
namespace owner_transport_detail {
// Adapted from pinned MP-SPDZ ServerSocket/AnonymousServerSocket. Retain the
// stock accept/client-ID framing and TLS transport. Replace only the timed
// empty-queue wait with Signal::wait(), guarded by the same condition loop.
class PatientSocket final : public ServerSocket {
    std::deque<std::string> pending_;
    void process_client(const std::string& client) override {
        if (clients.contains(client)) throw std::runtime_error("duplicate-owner-connection");
        pending_.push_back(client);
    }
public:
    explicit PatientSocket(int port) : ServerSocket(port) {}
    int next(std::string& client) {
        data_signal.lock();
        try {
            while (pending_.empty()) data_signal.wait();
            client = pending_.front(); pending_.pop_front();
            const int fd = clients.at(client); data_signal.unlock(); return fd;
        } catch (...) { data_signal.unlock(); throw; }
    }
    void remove(const std::string& client) {
        data_signal.lock(); clients.erase(client); data_signal.unlock();
    }
};
} // namespace owner_transport_detail
struct PatientOwnerConnections::Impl {
    const int party;
    int port_base = 0;
    ssl_service io;
    std::unique_ptr<client_ctx> context;
    std::unique_ptr<owner_transport_detail::PatientSocket> server;
    std::map<int, std::unique_ptr<client_socket>> sockets;
    explicit Impl(int p) : party(p) {
        if (p < 0 || p > 2) throw std::runtime_error("owner-server-role");
    }
};
PatientOwnerConnections::PatientOwnerConnections(int party) : impl_(std::make_unique<Impl>(party)) {}
PatientOwnerConnections::~PatientOwnerConnections() = default;
void PatientOwnerConnections::start_listening(int port_base) {
    if (impl_->server || port_base < 1024 || port_base > 65533)
        throw std::runtime_error("owner-listen-port-range-or-reuse");
    impl_->port_base = port_base;
    impl_->server = std::make_unique<owner_transport_detail::PatientSocket>(port_base + impl_->party);
    impl_->server->init();
}
int PatientOwnerConnections::get_client_connection(int port_base) {
    if (!impl_->server || port_base != impl_->port_base)
        throw std::runtime_error("owner-listener-missing");
    std::string client; const int fd = impl_->server->next(client);
    int owner{}; const auto parsed = std::from_chars(client.data(), client.data() + client.size(), owner);
    if (client.size() != 1 || parsed.ec != std::errc{} || parsed.ptr != client.data() + client.size() ||
        owner < 0 || owner > 2 || impl_->sockets.contains(owner)) {
        close(fd); throw std::runtime_error("owner-connection-role");
    }
    if (!impl_->context) impl_->context = std::make_unique<client_ctx>("P" + std::to_string(impl_->party));
    impl_->sockets.emplace(owner, std::make_unique<client_socket>(impl_->io, *impl_->context, fd,
        "C" + std::to_string(owner), "P" + std::to_string(impl_->party), false));
    return owner;
}
client_socket* PatientOwnerConnections::get_socket(int owner) { return impl_->sockets.at(owner).get(); }
void PatientOwnerConnections::close_connection(int owner) {
    if (impl_->sockets.erase(owner) != 1) throw std::runtime_error("owner-connection-not-active");
    impl_->server->remove(std::to_string(owner));
}
} // namespace kpi::mpc
