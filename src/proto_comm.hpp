#pragma once

#include <zmq.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <thread>

#include "common.h"
#include "src/util/proto_util.hpp"
#include "src/proto/multicast_control.pb.h"

#include "asylo_sgx.hpp"

class ProtoSocket {
public:
    // Non-owning pointer, TODO use unique_ptr instead )
    ProtoSocket(zmq::socket_t* socket, uint64_t id);

    void connect(std::string endpoint);
    void bind(std::string endpoint);

    MulticastMessage::ControlMessage recv();
    void recv(MulticastMessage::ControlMessage* msg);

    void send(MulticastMessage::ControlMessage& msg);

    void send_error(uint64_t error_code);
    void send_join(std::string addr, int node_type);
    void send_assign_id(uint64_t new_id);
    void send_exec_code(std::string code);
    void send_assign_parent(std::string parent_addr);

    void send_raw_str(std::string str); // TODO temporary shim: Should be replaced
                                        // with situation-specific proto msgs
    void send_raw_bytes(std::string str); // TODO temporary shim ^
    void send_raw_bytes(std::string bytes, bool route_up);

    void send_interrupt(int type);

    void send_heartbeat(std::string addr_, int subtree_count);

    std::string get_endpoint();


    // TODO: THIS IS TEMPORARY AND SHOULD PROBABLY
    // GO IN A SEPARATE CLASS. Also, we should make these
    // data members private.
    uint64_t last_heartbeat;
    int subtree_size;


private:
    virtual MulticastMessage::ControlMessage recv_proto();
    virtual void send_proto(MulticastMessage::ControlMessage& msg);

    zmq::socket_t* socket_;
    uint64_t id_;

    bool log_to_file_;
    std::ofstream log_file_;

    std::string endpoint_;
};

namespace MulticastMessage {
    std::string unpack_join(MulticastMessage::ControlMessage& msg, int* node_type);
    std::string unpack_exec_code(MulticastMessage::ControlMessage&& msg);
    std::string unpack_raw_str(MulticastMessage::ControlMessage&& msg);
    std::string unpack_raw_bytes(MulticastMessage::ControlMessage& msg);

    std::string unpack_assign_parent(MulticastMessage::ControlMessage &msg);
}

int64_t get_timestamp();
