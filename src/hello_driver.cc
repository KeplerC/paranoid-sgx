/*
 *
 * Copyright 2018 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <iostream>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_split.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/util/logging.h"
#include "src/hello.pb.h"
#include <thread>
#include <zmq.hpp>

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");
ABSL_FLAG(std::string, names, "",
          "A comma-separated list of names to pass to the enclave");




class Asylo_SGX{
public:
    Asylo_SGX(std::string enclave_name){
        this->m_name = enclave_name;
    }

    void init(){
        // Part 1: Initialization
        asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
        auto manager_result = asylo::EnclaveManager::Instance();
        if (!manager_result.ok()) {
            LOG(QFATAL) << "EnclaveManager unavailable: " << manager_result.status();
        }
        this->manager = manager_result.ValueOrDie();
        std::cout << "Loading " << absl::GetFlag(FLAGS_enclave_path) << std::endl;

        // Create an EnclaveLoadConfig object.
        asylo::EnclaveLoadConfig load_config;
        load_config.set_name(this->m_name);

        // Create an SgxLoadConfig object.
        asylo::SgxLoadConfig sgx_config;
        asylo::SgxLoadConfig::FileEnclaveConfig file_enclave_config;
        file_enclave_config.set_enclave_path(absl::GetFlag(FLAGS_enclave_path));
        *sgx_config.mutable_file_enclave_config() = file_enclave_config;
        sgx_config.set_debug(true);

        // Set an SGX message extension to load_config.
        *load_config.MutableExtension(asylo::sgx_load_config) = sgx_config;
        asylo::Status status = this->manager->LoadEnclave(load_config);
        if (!status.ok()) {
            LOG(QFATAL) << "Load " << absl::GetFlag(FLAGS_enclave_path)
                        << " failed: " << status;
        }
        std::cout << "Enclave Initialized" << std::endl;
    }

    void execute(std::vector<std::string>  names){
        this->client = this->manager->GetClient(this->m_name);

        for (const auto &name : names) {
            asylo::EnclaveInput input;
            input.MutableExtension(hello_world::enclave_input_hello)
                    ->set_to_greet(name);

            asylo::EnclaveOutput output;
            asylo::Status status = this->client->EnterAndRun(input, &output);
            if (!status.ok()) {
                LOG(QFATAL) << "EnterAndRun failed: " << status;
            }

            if (!output.HasExtension(hello_world::enclave_output_hello)) {
                LOG(QFATAL) << "Enclave did not assign an ID for " << name;
            }

            std::cout << "Message from enclave: "
                      << output.GetExtension(hello_world::enclave_output_hello)
                              .greeting_message()
                      << std::endl;
        }
    }

    void finalize(){
        asylo::EnclaveFinal final_input;
        asylo::Status status = this->manager->DestroyEnclave(this->client, final_input);
        if (!status.ok()) {
            LOG(QFATAL) << "Destroy " << absl::GetFlag(FLAGS_enclave_path)
                        << " failed: " << status;
        }
    }

    void run(std::vector<std::string>  names){
        init();
        execute(names);
        finalize();
    }
private:
    asylo::EnclaveManager *manager;
    asylo::EnclaveClient *client;
    std::string m_name;
};


class zmq_comm {
public:
    zmq_comm(std::string ip, unsigned thread_id){
        m_port = std::to_string(5555 + thread_id);
        m_addr = "tcp://localhost:" + m_port;
        m_thread_id = thread_id;
    }

    [[noreturn]] void run_server(){
        zmq::context_t context (1);
        // socket for join requests
        zmq::socket_t socket_join (context, ZMQ_PULL);
        socket_join.bind ("tcp://*:" + std::to_string(6666));
        // socket for new mcast messages
        zmq::socket_t socket_msg (context, ZMQ_PULL);
        socket_msg.bind ("tcp://*:" + std::to_string(6667));

        //poll join and mcast messages
        std::vector<zmq::pollitem_t> pollitems = {
                { static_cast<void *>(socket_join), 0, ZMQ_POLLIN, 0 },
                { static_cast<void *>(socket_msg), 0, ZMQ_POLLIN, 0 },
        };
        std::cout << "Start polling" << std::endl;

        while (true) {
            zmq::poll(pollitems.data(), pollitems.size(), 0);
            // Join Request
            if (pollitems[0].revents & ZMQ_POLLIN){
                //Get the address
                std::string msg = this->recv_string(&socket_join);
                std::cout << "Got join request from " + msg << std::endl;
                this->group_addresses.push_back(msg);

                //create a socket to the client and save
                zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
                socket_ptr -> connect (msg);
                this->group_sockets.push_back(socket_ptr);
                this->send_string("Ack Join", socket_ptr);
            }

            //receive new message to mcast
            if (pollitems[1].revents & ZMQ_POLLIN){
                std::string msg = this->recv_string(&socket_msg);
                std::cout << "Received Message " + msg << std::endl;
                //mcast to all the clients
                for (zmq::socket_t* socket : this -> group_sockets) {
                    this->send_string(msg, socket);
                }
            }
        }
    }

    [[noreturn]] void run_client(){
        zmq::context_t context (1);

        zmq::socket_t socket_from_server (context, ZMQ_PULL);
        socket_from_server.bind ("tcp://*:" + m_port);

        //send join request to seed server
        zmq::socket_t* socket_join  = new  zmq::socket_t( context, ZMQ_PUSH);
        socket_join -> connect ("tcp://" + m_seed_server_ip + ":" + m_seed_server_join_port);
        this->send_string(m_addr, socket_join);

        //a socket to server to multicast
        zmq::socket_t* socket_send  = new  zmq::socket_t( context, ZMQ_PUSH);
        socket_send -> connect ("tcp://" + m_seed_server_ip + ":" + m_seed_server_mcast_port);

        // poll for new messages
        std::vector<zmq::pollitem_t> pollitems = {
                { static_cast<void *>(socket_from_server), 0, ZMQ_POLLIN, 0 },
        };

        Asylo_SGX* sgx = new Asylo_SGX(m_port);
        sgx->init();
        //start enclave
        while (true) {
            zmq::poll(pollitems.data(), pollitems.size(), 0);
            // Join Request
            if (pollitems[0].revents & ZMQ_POLLIN) {
                //Get the address
                std::string msg = this->recv_string(&socket_from_server);
                std::cout << "Got message " + msg << std::endl;
                //this -> send_string(m_port + "Got the message ", socket_send);
                std::vector<std::string> names =
                        absl::StrSplit(absl::GetFlag(FLAGS_names), ',');
                sgx->execute(names);
            }
        }
        sgx->finalize();
    }

private:
    std::string m_port;
    std::string m_addr;
    std::string m_seed_server_ip = "localhost";
    std::string m_seed_server_join_port = std::to_string(6666);
    std::string m_seed_server_mcast_port = std::to_string(6667);
    unsigned m_thread_id;

    int m_enclave_seq_number = 0;
    std::vector<std::string> group_addresses;
    std::vector<zmq::socket_t*> group_sockets;

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

void thread_run_zmq_client(unsigned thread_id){
    zmq_comm zs = zmq_comm("localhost", thread_id);
    zs.run_client();
}
void thread_run_zmq_server(unsigned thread_id){
    zmq_comm zs = zmq_comm("localhost", thread_id);
    zs.run_server();
}

int main(int argc, char *argv[]) {
  // Part 0: Setup
    absl::ParseCommandLine(argc, argv);

    if (absl::GetFlag(FLAGS_names).empty()) {
    LOG(QFATAL) << "Must supply a non-empty list of names with --names";
    }

    std::vector<std::thread> worker_threads;

    for (unsigned thread_id = 1; thread_id < 5; thread_id++) {
        worker_threads.push_back(std::thread(thread_run_zmq_client, thread_id));
    }
    sleep(2);

    worker_threads.push_back(std::thread(thread_run_zmq_server, 0));
    sleep(15);

    std::vector<std::string> names =
      absl::StrSplit(absl::GetFlag(FLAGS_names), ',');

    Asylo_SGX* sgx = new Asylo_SGX("hello_enclave");
    sgx->run(names);

    return 0;
}
