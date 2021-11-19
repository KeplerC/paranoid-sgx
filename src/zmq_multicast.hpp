#pragma once

#include <zmq.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <function>

#include <zmq.hpp>
#include "common.h"
#include "src/util/proto_util.hpp"
#include "src/proto/multicast_control.pb.h"

#include "asylo_sgx.hpp"

class MulticastHandler {
public:
    // TODO: std::function<> is easy to use but notoriously slow, replace later
    MulticastHandler(zmq::socket_t* socket, uint64_t id,
                     std::function<)
        : socket_(socket), id_(id) {};

    MulticastMessage::ControlMessage* recv();
    void recv(MulticastMessage::ControlMessage* msg);
  //void recv_forward(std::function<void(MulticastMessage::ControlMessage* msg)> dst);

    void send(const MulticastMessage::ControlMessage* msg);
    void send_error(uint64_t error_code);
    void send_join();
    void send_assign_id(uint64_t new_id);
    void send_give_addr(std::string addr);

private:
    MulticastMessage::ControlMessage* recv_proto();
    std::string recv_string();
    void send_string(const std::string& s);
    void send_proto(MulticastMessage::ControlMessage& msg);

    zmq::socket_t* socket_;
    uint64_t id_;
};
