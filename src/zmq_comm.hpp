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

class ZmqComm {
public:
    ZmqComm(std::string ip, unsigned thread_id,
            std::initializer_list<zmq::pollitem_t> poll_sockets)
            : thread_id_(thread_id)
            , context_(1)
            , seed_server_ip_(NET_SEED_ROUTER_IP)
            , seed_server_join_port_(std::to_string(NET_SERVER_JOIN_PORT))
            , seed_server_mcast_port_(std::to_string(NET_SERVER_MCAST_PORT))
            , enclave_seq_number_(0)
            , coordinator_("")
            , pollitems_(poll_sockets) {
        port_ = std::to_string(NET_CLIENT_BASE_PORT + thread_id);
        addr_ = "tcp://" + ip +":" + port_;
    }

    [[noreturn]] void run() {
        net_setup();
        while (true) {
            poll();
            net_handler();
        }
    }

protected:
    unsigned thread_id_;
    zmq::context_t context_;
    std::string port_;
    std::string addr_;
    std::string seed_server_ip_;
    std::string seed_server_join_port_;
    std::string seed_server_mcast_port_;

    int enclave_seq_number_;
    std::vector<std::string> group_addresses_;
    std::vector<zmq::socket_t*> group_sockets_;

    zmq::socket_t* parent_socket_;
    std::vector<zmq::socket_t*> child_sockets_;
    std::string coordinator_;

    std::vector<zmq::pollitem_t> pollitems_;

    virtual void net_setup() = 0;
    virtual void net_handler() = 0;

    void poll() {
        zmq::poll(pollitems_.data(), pollitems_.size(), 0);
    }

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

    std::string serialize_group_addresses() {
        std::string ret;
        for( const std::string& s : group_addresses_ ) {
            ret += GROUP_ADDR_DELIMIT + s;
        }
        return ret;
    }

    std::vector<std::string> deserialize_group_addresses(std::string group_addresses) {
        std::vector<std::string> ret = absl::StrSplit(group_addresses, "@@@", absl::SkipEmpty());
        return ret;
    }
};

class ZmqServer: public ZmqComm {
public:
    ZmqServer(std::string ip, unsigned thread_id);
private:
    zmq::socket_t zsock_join_;
    zmq::socket_t zsock_msg_; // socket for new mcast messages
    zmq::socket_t zsock_control_;
    zmq::socket_t zsock_result_;

    ProtoSocket socket_join_;
    ProtoSocket socket_msg_; // socket for new mcast messages
    ProtoSocket socket_control_;
    ProtoSocket socket_result_;

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

class ZmqRouter: public ZmqComm {
public:
    ZmqRouter(std::string ip, unsigned thread_id);
private:
    zmq::socket_t zsock_join_; // socket for join requests
    zmq::socket_t zsock_msg_; // socket for new mcast messages
    zmq::socket_t zsock_control_;
    zmq::socket_t zsock_result_;

    ProtoSocket socket_join_;
    ProtoSocket socket_msg_; // socket for new mcast messages
    ProtoSocket socket_control_;
    ProtoSocket socket_result_;

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
