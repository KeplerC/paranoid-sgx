#ifndef ZMQ_HPP
#define ZMQ_HPP
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
#include "capsuleDBcpp/cdb_network_client.hh"

// #include "asylo/identity/enclave_assertion_authority_config.proto.h"
#include "asylo/identity/enclave_assertion_authority_configs.h"



class zmq_comm {
public:
    zmq_comm(std::string ip, unsigned thread_id, Asylo_SGX* sgx){
            m_port = std::to_string(NET_CLIENT_BASE_PORT + thread_id);
            m_recv_code_port = std::to_string(NET_WORKER_LISTEN_FOR_TASK_BASE_PORT + thread_id);
            m_addr = "tcp://" + ip +":" + m_port;
            m_thread_id = thread_id;
            LOGI << "[thread created with recv_code_port] " << m_recv_code_port;
            m_sgx = sgx;
        }

    // TODO: TEMP FIX CHANGE LATER
    // Overloaded constructor for CapsuleDB instance (no enclave) 
    zmq_comm(std::string ip, unsigned thread_id, CapsuleDBNetworkClient* db, char*){
            m_port = std::to_string(NET_CLIENT_BASE_PORT + thread_id);
            m_recv_code_port = std::to_string(NET_WORKER_LISTEN_FOR_TASK_BASE_PORT + thread_id);
            m_addr = "tcp://" + ip +":" + m_port;
            m_thread_id = thread_id;
            LOGI << "[CapsuleDB thread created with recv_code_port] " << m_recv_code_port;
            m_db = db;
        }

    [[noreturn]] void run_server();
    [[noreturn]] void run_client();
    [[noreturn]] void run_js_client();
    [[noreturn]] void run_cdb_client();
private:
    std::string m_port;
    std::string m_recv_code_port;
    std::string m_addr;
    std::string m_seed_server_ip = NET_SEED_ROUTER_IP;
    std::string m_seed_server_join_port = std::to_string(NET_SERVER_JOIN_PORT);
    std::string m_seed_server_mcast_port = std::to_string(NET_SERVER_MCAST_PORT);
    unsigned m_thread_id;
    Asylo_SGX* m_sgx;
    CapsuleDBNetworkClient* m_db;

    int m_enclave_seq_number = 0;
    std::vector<std::string> group_addresses;
    std::vector<zmq::socket_t*> group_sockets;
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

#endif
