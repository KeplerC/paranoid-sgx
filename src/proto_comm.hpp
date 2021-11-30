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
        : socket_(socket), id_(id) {};

    void connect(std::string endpoint);
    void bind(std::string endpoint);

    MulticastMessage::ControlMessage* recv();
    void recv(MulticastMessage::ControlMessage* msg);

    void send(const MulticastMessage::ControlMessage* msg);

    void send_error(uint64_t error_code);
    void send_join();
    void send_assign_id(uint64_t new_id);
    void send_give_addr(std::string addr);
    void send_exec_code(std::string code);

private:
    MulticastMessage::ControlMessage* recv_proto();
    std::string recv_string();
    void send_string(const std::string& s);
    void send_proto(MulticastMessage::ControlMessage& msg);

    zmq::socket_t* socket_;
    uint64_t id_;
};
