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
#include "zmq_comm.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

// #include "asylo/identity/enclave_assertion_authority_config.proto.h"
#include "asylo/identity/enclave_assertion_authority_configs.h"

enum mode_type { RUN_BOTH_CLIENT_AND_SERVER, RUN_CLIENT_ONLY, LISTENER_MODE, COORDINATOR_MODE };

#define PORT_NUM 1234


ABSL_FLAG(std::string, input_file, "",
          "JS input file to execute!");

ABSL_FLAG(int32_t, mode, -1, "Configures which mode to run KVS in");

ABSL_FLAG(std::string, hosts, "", "Comma seperated list of IP addresses");

ABSL_FLAG(std::string, server_address, "", "Address of the KVS coordinator");
ABSL_FLAG(int32_t, port, 0, "Port that the server listens to");

ABSL_FLAG(std::string, scenario, "", "Path to enclave to load");
ABSL_FLAG(std::string, algorithm, "", "Path to enclave to load");
ABSL_FLAG(std::string, coordinator, "", "Path to enclave to load");

ABSL_FLAG(std::string, jobs, "4", "Path to enclave to load");
ABSL_FLAG(std::string, env, "", "Path to enclave to load");
ABSL_FLAG(std::string, env_frame, "", "Path to enclave to load");

ABSL_FLAG(std::string, robot, "", "Path to enclave to load");
ABSL_FLAG(std::string, goal, "", "Path to enclave to load");
ABSL_FLAG(std::string, goal_radius, "", "Path to enclave to load");


ABSL_FLAG(std::string, start, "", "Path to enclave to load");
ABSL_FLAG(std::string, min, "", "Path to enclave to load");
ABSL_FLAG(std::string, max, "", "Path to enclave to load");

ABSL_FLAG(std::string, problem_id, "", "Path to enclave to load");
ABSL_FLAG(std::string, time_limit, "", "Path to enclave to load");
ABSL_FLAG(std::string, check_resolution, "", "Path to enclave to load");

ABSL_FLAG(std::string, discretization, "", "Path to enclave to load");
ABSL_FLAG(std::string, is_float, "", "Path to enclave to load"); 

void thread_run_zmq_client(unsigned thread_id, Asylo_SGX* sgx){
    zmq_comm zs = zmq_comm(NET_CLIENT_IP, thread_id, sgx);
    zs.run_client();
}
void thread_run_zmq_server(unsigned thread_id){
    LOG(INFO) << "[thread_run_zmq_server]"; 
    zmq_comm zs = zmq_comm(NET_SEED_SERVER_IP, thread_id, nullptr);
    zs.run_server();
}
void thread_start_fake_client(Asylo_SGX* sgx){
    sgx->execute();
}

void thread_start_mpl_client(Asylo_SGX* sgx){
    sgx->execute_mpl();
}

void thread_start_coordinator(Asylo_SGX* sgx){
    sgx->execute_coordinator();
}

void thread_start_sync_thread(Asylo_SGX* sgx){
    sgx->start_sync_epoch_thread();
}

void run_clients_only(){
    std::vector <std::thread> worker_threads;
    unsigned long int now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    //start clients
    int num_threads = TOTAL_THREADS + 1;
    for (unsigned thread_id = 1; thread_id < num_threads; thread_id++) {
        Asylo_SGX* sgx = new Asylo_SGX( std::to_string(thread_id));
        sgx->init();
        sgx->setTimeStamp(now);
        sleep(1);
        worker_threads.push_back(std::thread(thread_run_zmq_client, thread_id, sgx));
        worker_threads.push_back(std::thread(thread_start_fake_client, sgx));
    }
    sleep(1 * 1000 * 1000);
    return; 
}
  

void run_client_server() {

    // thread assignments:
    // thread 0: multicast server
    // thread 1: coordinator
    // thread 2-n: clients
    std::vector <std::thread> worker_threads;
    //start clients
    unsigned long int now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    LOG(INFO) << (now);
    for (unsigned thread_id = 1; thread_id < TOTAL_THREADS; thread_id++) {
        Asylo_SGX* sgx = new Asylo_SGX( std::to_string(thread_id));
        sgx->init();
        sgx->setTimeStamp(now);
        sleep(1);
        if(thread_id == 1){
            worker_threads.push_back(std::thread(thread_run_zmq_client, thread_id, sgx));
            worker_threads.push_back(std::thread(thread_start_coordinator, sgx));
        } else{
            worker_threads.push_back(std::thread(thread_run_zmq_client, thread_id, sgx));
            worker_threads.push_back(std::thread(thread_start_fake_client, sgx));
        }

    }
    sleep(2);

    //start server
    worker_threads.push_back(std::thread(thread_run_zmq_server, 0));
    sleep(1 * 1000 * 1000);
    return;
}

void run_listener(){
    // Create a socket (IPv4, TCP)
    std::vector <std::thread> worker_threads;
    std::vector <std::thread> client_threads;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        std::cout << "Failed to create socket. errno: " << errno << std::endl;
        exit(EXIT_FAILURE);
    }

    // Listen to port 9999 on any address
    sockaddr_in sockaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = INADDR_ANY;
    sockaddr.sin_port = htons(PORT_NUM); // htons is necessary to convert a number to
                                // network byte order
    if (bind(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {
        std::cout << "Failed to bind to port " << PORT_NUM << ". errno: " << errno << std::endl;
        exit(EXIT_FAILURE);
    }

    // Start listening. Hold at most 10 connections in the queue
    if (listen(sockfd, 10) < 0) {
        std::cout << "Failed to listen on socket. errno: " << errno << std::endl;
        exit(EXIT_FAILURE);
    }

    while(true){
        // Grab a connection from the queue
        auto addrlen = sizeof(sockaddr);
        int connection = accept(sockfd, (struct sockaddr*)&sockaddr, (socklen_t*)&addrlen);
        if (connection < 0) {
            std::cout << "Failed to grab connection. errno: " << errno << std::endl;
            exit(EXIT_FAILURE);
        }

        hello_world::MP_Lambda_Input lambda_input;

        // Read from the connection
        char buffer[512];
        int bytes_read = 0;
        while(bytes_read < 256){
            bytes_read += read(connection, buffer + bytes_read, 512 - bytes_read);
        }

        LOG(INFO) << "[listener]" << bytes_read;

        lambda_input.ParseFromArray(buffer, bytes_read);

        unsigned long int now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        lambda_input.set_time_start(now);

        for (unsigned thread_id = 0; thread_id < std::stoi(lambda_input.jobs()); thread_id++) {
            Asylo_SGX* sgx = new Asylo_SGX( std::to_string(thread_id));
            sgx->init();
            sgx->setLambdaInput(lambda_input);
            
            sleep(1);

            worker_threads.push_back(std::thread(thread_run_zmq_client, thread_id, sgx));
            client_threads.push_back(std::thread(thread_start_mpl_client, sgx));
        }

        //Wait for client enclaves first
        for (int i=0; i<client_threads.size(); ++i) {
            if (client_threads[i].joinable())
                client_threads.at(i).join();
        }

        //TODO: Figure out a way to kill ZMQ clients 
        LOG(INFO) << "[listener] Finished request";
        exit(0);

        //Send cancellation singnals to ZMQ client threads
        for (int i=0; i<worker_threads.size(); ++i) {
             if (worker_threads[i].joinable())
                worker_threads.at(i).join();
        }
        close(connection);
    }

    // Send a message to the connection
    // send(connection, response.c_str(), response.size(), 0);

    // Close the connections
    close(sockfd);
    return; 
}

void run_coordinator(){
    std::vector <std::thread> worker_threads;
    std::string hosts = absl::GetFlag(FLAGS_hosts);
    std::vector<std::string> hosts_vec = absl::StrSplit(hosts, ',');
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[256];

    hello_world::MP_Lambda_Input lambda_input;
    lambda_input.set_scenario(absl::GetFlag(FLAGS_scenario));
    lambda_input.set_algorithm(absl::GetFlag(FLAGS_algorithm));
    lambda_input.set_coordinator(absl::GetFlag(FLAGS_coordinator));
    lambda_input.set_jobs(absl::GetFlag(FLAGS_jobs));

    lambda_input.set_env(absl::GetFlag(FLAGS_env));
    lambda_input.set_env_frame(absl::GetFlag(FLAGS_env_frame));


    lambda_input.set_robot(absl::GetFlag(FLAGS_robot));
    lambda_input.set_goal(absl::GetFlag(FLAGS_goal));
    lambda_input.set_goal_radius(absl::GetFlag(FLAGS_goal_radius));

    lambda_input.set_start(absl::GetFlag(FLAGS_start));
    lambda_input.set_min(absl::GetFlag(FLAGS_min));
    lambda_input.set_max(absl::GetFlag(FLAGS_max));

    lambda_input.set_problem_id(absl::GetFlag(FLAGS_problem_id));
    lambda_input.set_time_limit(absl::GetFlag(FLAGS_time_limit));
    lambda_input.set_check_resolution(absl::GetFlag(FLAGS_check_resolution));

    lambda_input.set_discretization(absl::GetFlag(FLAGS_discretization));
    lambda_input.set_is_float(absl::GetFlag(FLAGS_is_float));

    int payload_size =  lambda_input.ByteSizeLong(); 
    char *payload = (char *) malloc(payload_size);
    lambda_input.SerializeToArray(payload, payload_size);
    lambda_input.ParseFromArray(payload, payload_size);

    for(std::string host: hosts_vec){

        portno = PORT_NUM;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0){
            LOG(ERROR) << "Opening socket...";
            exit(0);

        }

        server = gethostbyname(host.c_str());
        if (server == NULL) {
            LOG(ERROR) << "Cannot get host: " << host;
            exit(0);
        }
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        bcopy((char *)server->h_addr, 
            (char *)&serv_addr.sin_addr.s_addr,
            server->h_length);
        serv_addr.sin_port = htons(portno);

        if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
            LOG(ERROR) << "Cannot connect to " << host << ":" << portno;
            exit(0);
        }

        n = 0; 
        while(n < payload_size){
            n += write(sockfd, payload + n, payload_size - n);
        }

        if (n < 0) 
            LOG(ERROR) << "ERROR writing to socket";

        close(sockfd);     
        LOG(INFO) << "Sent request to : " << host;
    }

    free(payload); 

    //Initiate ZMQ server 
    worker_threads.push_back(std::thread(thread_run_zmq_server, 0));
    sleep(1 * 1000 * 1000);
    return;
}

int main(int argc, char *argv[]) {
  // Part 0: Setup
    absl::ParseCommandLine(argc, argv);

    uint32_t mode = absl::GetFlag(FLAGS_mode);

    switch(mode){
        case RUN_BOTH_CLIENT_AND_SERVER:
            run_client_server();
            break;
        case RUN_CLIENT_ONLY:
            run_clients_only();
            break;
        case LISTENER_MODE:
            run_listener();
            break; 
        case COORDINATOR_MODE:
            run_coordinator();
            break; 
        default:
            printf("Mode %d is incorrect\n", mode); 
            return 0; 
    }

    return 0; 
}
