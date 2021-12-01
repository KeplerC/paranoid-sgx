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
    void send_join(std::string addr);
    void send_assign_id(uint64_t new_id);
    void send_exec_code(std::string code);
    void send_raw_str(std::string str); // TODO temporary shim: Should be replaced
                                        // with situation-specific proto msgs
    void send_raw_bytes(std::string str); // TODO temporary shim ^
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
    // hella memory leaks
    std::string unpack_join(MulticastMessage::ControlMessage&& msg);
    std::string unpack_exec_code(MulticastMessage::ControlMessage&& msg);
    std::string unpack_raw_str(MulticastMessage::ControlMessage&& msg);
    std::string unpack_raw_bytes(MulticastMessage::ControlMessage&& msg);
    // TODO move the serialization methods here?
    //ControlMessage* pack_join(std::string addr);
}
