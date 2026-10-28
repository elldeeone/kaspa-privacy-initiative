// PUBLIC operational control only. Include the actual implementation to test
// its anonymous queued socket without creating TLS/private keys or MPC state.
#include "../owner_connections.cpp"
#include "Tools/octetStream.h"
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const int port = std::stoi(argv[1]);
    kpi::mpc::owner_transport_detail::PatientSocket server(port); server.init();
    std::atomic<bool> completed{false};
    std::string received;
    std::thread wait([&] {
        const int fd = server.next(received); close(fd); completed = true;
    });
    // The stock client wait exits at60 seconds. This decisive control waits
    // beyond that boundary, checks no synthetic client was admitted, then uses
    // the unchanged stock client-ID frame to complete the actual socket wait.
    std::this_thread::sleep_for(std::chrono::seconds(65));
    if (completed) std::terminate();
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) std::terminate();
    octetStream(std::string("0")).Send(fd); close(fd); wait.join();
    if (!completed || received != "0") return 3;
    std::cout << "{\"schema\":\"kpi-public-owner-idle-wait-control/v1\",\"status\":\"PASS\","
                 "\"idle_seconds\":65,\"stock_boundary_seconds\":60,\"private_input_or_tls_or_mpc\":false}\n";
}
