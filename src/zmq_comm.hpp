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

#include "asylo_sgx.hpp"

// #include "asylo/identity/enclave_assertion_authority_config.proto.h"
#include "asylo/identity/enclave_assertion_authority_configs.h"

class zmq_comm {
public:
    zmq_comm(std::string ip, unsigned thread_id, Asylo_SGX* sgx) :
            m_thread_id(thread_id), m_sgx(sgx), context(1) {
            m_port = std::to_string(NET_CLIENT_BASE_PORT + thread_id);
            m_addr = "tcp://" + ip +":" + m_port;
    }

    [[noreturn]] virtual void run() = 0;

   // [[noreturn]] void run_server();
   // [[noreturn]] void run_client();
   // [[noreturn]] void run_router();
   // [[noreturn]] void run_js_client();

protected:
    unsigned m_thread_id;
    Asylo_SGX* m_sgx;
    zmq::context_t context;
    std::string m_port;
    std::string m_addr;
    std::string m_seed_server_ip = NET_SEED_ROUTER_IP;
    std::string m_seed_server_join_port = std::to_string(NET_SERVER_JOIN_PORT);
    std::string m_seed_server_mcast_port = std::to_string(NET_SERVER_MCAST_PORT);

    int m_enclave_seq_number = 0;
    std::vector<std::string> group_addresses;
    std::vector<zmq::socket_t*> group_sockets;

    zmq::socket_t* parent_socket;
    std::vector<zmq::socket_t*> child_sockets;
    std::string m_coordinator = "";

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

    std::string serialize_group_addresses(){
        std::string ret;
        for( const std::string& s : group_addresses ) {
            ret += GROUP_ADDR_DELIMIT + s;
        }
        return ret;
    }

    std::vector<std::string> deserialize_group_addresses(std::string group_addresses){
        std::vector<std::string> ret = absl::StrSplit(group_addresses, "@@@", absl::SkipEmpty());
        return ret;
    }
};

class ZmqServer: public zmq_comm {
public:
    ZmqServer(std::string ip, unsigned thread_id, Asylo_SGX* sgx) :
        zmq_comm(ip, thread_id, sgx) {}
    [[noreturn]] void run() override;
private:

};

class ZmqClient: public zmq_comm {
public:
    ZmqClient(std::string ip, unsigned thread_id, Asylo_SGX* sgx) :
        zmq_comm(ip, thread_id, sgx) {}
    [[noreturn]] void run() override;
private:

};

class ZmqRouter: public zmq_comm {
public:
    ZmqRouter(std::string ip, unsigned thread_id, Asylo_SGX* sgx) :
        zmq_comm(ip, thread_id, sgx) {}
    [[noreturn]] void run() override;
private:

};

class ZmqJsClient: public zmq_comm {
public:
    ZmqJsClient(std::string ip, unsigned thread_id, Asylo_SGX* sgx);
    [[noreturn]] void run() override;
private:
    zmq::socket_t socket_from_server;
    zmq::socket_t socket_code;
    zmq::socket_t socket_join;
    zmq::socket_t socket_send;
};
