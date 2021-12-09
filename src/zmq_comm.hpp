#pragma once
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <zmq.hpp>
#include <chrono>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_split.h"
#include "asylo/client.h"
#include "asylo/crypto/sha256_hash_util.h"
#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/util/logging.h"
#include "asylo/util/status_macros.h"
#include <thread>
#include <mutex>
#include <zmq.hpp>
#include "hot_msg_pass.h"
#include "common.h"
#include "kvs_include/capsule.h"
#include "src/proto/hello.pb.h"
#include "src/util/proto_util.hpp"

#include "proto_comm.hpp"
#include "asylo_sgx.hpp"

// #include "asylo/identity/enclave_assertion_authority_config.proto.h"
#include "asylo/identity/enclave_assertion_authority_configs.h"

#define MAX_CHILD_ROUTERS 2

class ZmqComm {
public:
    ZmqComm(std::string ip, unsigned thread_id);
    [[noreturn]] void run();

protected:
    unsigned thread_id_;
    zmq::context_t context_;
    std::string port_;
    std::string addr_;
    std::string seed_server_ip_;
    std::string seed_server_join_port_;
    std::string seed_server_mcast_port_;

    int enclave_seq_number_;
    std::string coordinator_;

    std::vector<zmq::pollitem_t> pollitems_;

    virtual void net_setup() = 0;
    virtual void net_handler() = 0;
    void poll();

    zmq::message_t string_to_message(const std::string& s) {
        zmq::message_t msg(s.size());
        memcpy(msg.data(), s.c_str(), s.size());
        return msg;
    }

    std::string message_to_string(const zmq::message_t& message) {
        return std::string(static_cast<const char*>(message.data()), message.size());
    }

    std::string recv_string(zmq::socket_t* socket) {
        zmq::message_t message;
        socket->recv(&message);
        return this->message_to_string(message);
    }

    void send_string(const std::string& s, zmq::socket_t* socket) {
        socket->send(string_to_message(s));
    }

};

class ZmqServer: public ZmqComm {
public:
    ZmqServer(std::string ip, unsigned thread_id);
private:
    int max_child_routers;

    zmq::socket_t zsock_join_;
    zmq::socket_t zsock_msg_; // socket for new mcast messages
    zmq::socket_t zsock_control_;
    zmq::socket_t zsock_result_;

    ProtoSocket socket_join_;
    ProtoSocket socket_msg_; // socket for new mcast messages
    ProtoSocket socket_control_;
    ProtoSocket socket_result_;

    std::vector<std::string> router_addresses_;
    std::vector<zmq::socket_t*> router_sockets_;

    std::vector<std::string> client_addresses_;
    std::vector<zmq::socket_t*> client_sockets_;


    void net_setup() override;
    void net_handler() override;

    std::string serialize_group_addresses();
    std::vector<std::string> deserialize_group_addresses(std::string);
};

class ZmqRouter: public ZmqComm {
public:
    ZmqRouter(std::string ip, unsigned thread_id);
private:
    int max_child_routers;

    zmq::socket_t zsock_join_;
    zmq::socket_t zsock_from_server_;

    ProtoSocket socket_join_;
    ProtoSocket socket_from_server_;

    zmq::socket_t* parent_socket_;
    std::vector<zmq::socket_t*> router_sockets_;
    std::vector<zmq::socket_t*> client_sockets_;

    void net_setup() override;
    void net_handler() override;
};

class ZmqClient: public ZmqComm {
public:
    ZmqClient(std::string ip, unsigned thread_id, Asylo_SGX* sgx);
private:
    Asylo_SGX* sgx_;

    zmq::socket_t zsock_join_;
    zmq::socket_t zsock_from_server_;
    zmq::socket_t zsock_send_; //a socket to server to multicast

    ProtoSocket socket_join_;
    ProtoSocket socket_from_server_;
    ProtoSocket socket_send_;

    void net_setup() override;
    void net_handler() override;
};

class ZmqJsClient: public ZmqComm {
public:
    ZmqJsClient(std::string ip, unsigned thread_id, Asylo_SGX* sgx);
private:
    Asylo_SGX* sgx_;

    zmq::socket_t zsock_join_;
    zmq::socket_t zsock_from_server_;
    zmq::socket_t zsock_code_;
    zmq::socket_t zsock_send_; //a socket to server to multicast

    ProtoSocket socket_join_;
    ProtoSocket socket_from_server_;
    ProtoSocket socket_code_;
    ProtoSocket socket_send_;

    void net_setup() override;
    void net_handler() override;
};
