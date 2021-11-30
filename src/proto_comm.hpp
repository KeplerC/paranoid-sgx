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
    ProtoSocket(zmq::socket_t* socket, uint64_t id)
        : socket_(socket), id_(id), log_(true) {};

    void connect(std::string endpoint);
    void bind(std::string endpoint);

    MulticastMessage::ControlMessage recv();
    void recv(MulticastMessage::ControlMessage* msg);

    void send(MulticastMessage::ControlMessage& msg);

    void send_error(uint64_t error_code);
    void send_join(std::string addr);
    void send_assign_id(uint64_t new_id);
    void send_exec_code(std::string code);
private:
    virtual MulticastMessage::ControlMessage recv_proto();
    virtual void send_proto(MulticastMessage::ControlMessage& msg);

    zmq::socket_t* socket_;
    uint64_t id_;
    bool log_;
};

namespace MulticastMessage {
    // hella memory leaks
    std::string* unpack_join(MulticastMessage::ControlMessage& msg);
    std::string* unpack_exec_code(MulticastMessage::ControlMessage& msg);

    std::string unpack_join(ProtoSocket& sock);
    std::string unpack_exec_code(ProtoSocket& sock);
    // TODO move the serialization methods here?
    //ControlMessage* pack_join(std::string addr);
}
