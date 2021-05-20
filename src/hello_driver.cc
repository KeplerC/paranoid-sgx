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

// #include "asylo/identity/enclave_assertion_authority_config.proto.h"
#include "asylo/identity/enclave_assertion_authority_configs.h"


ABSL_FLAG(std::string, input_file, "",
          "JS input file to execute!");

ABSL_FLAG(std::string, server_address, "", "Address of the KVS coordinator");
ABSL_FLAG(int32_t, port, 0, "Port that the server listens to");

void thread_run_zmq_client(unsigned thread_id, Asylo_SGX* sgx){
    zmq_comm zs = zmq_comm(NET_CLIENT_IP, thread_id, sgx);
    zs.run_client();
}
void thread_run_zmq_server(unsigned thread_id){
    zmq_comm zs = zmq_comm(NET_SEED_SERVER_IP, thread_id, nullptr);
    zs.run_server();
}
void thread_start_fake_client(Asylo_SGX* sgx){
    sgx->execute();
}

void thread_start_coordinator(Asylo_SGX* sgx){
    sgx->execute_coordinator();
}

void thread_start_sync_thread(Asylo_SGX* sgx){
    sgx->start_sync_epoch_thread();
}

int main(int argc, char *argv[]) {
  // Part 0: Setup
    absl::ParseCommandLine(argc, argv);

//    if (absl::GetFlag(FLAGS_payload).empty()) {
//      LOG(QFATAL) << "Must supply a non-empty string for the DataCapsule payload --payload";
//    }

    if(RUN_BOTH_CLIENT_AND_SERVER) {
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
    } else {
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
    }
    return 0;
}
