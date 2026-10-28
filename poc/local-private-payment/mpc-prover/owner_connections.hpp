#pragma once
#include "Networking/ssl_sockets.h"
#include "ExternalIO/Client.h"
#include <memory>

namespace kpi::mpc {
// Source-coherent external owner transport. The queued connection wait is
// unbounded: scheduling alone cannot abort an already durable private attempt.
// CA/CN authentication and the independent DER/contract checks stay mandatory.
class PatientOwnerConnections {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    explicit PatientOwnerConnections(int party);
    ~PatientOwnerConnections();
    PatientOwnerConnections(const PatientOwnerConnections&) = delete;
    PatientOwnerConnections& operator=(const PatientOwnerConnections&) = delete;
    void start_listening(int port_base);
    int get_client_connection(int port_base);
    client_socket* get_socket(int owner);
    void close_connection(int owner);
};
} // namespace kpi::mpc
