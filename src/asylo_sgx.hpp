#pragma once

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
#include "asylo/identity/enclave_assertion_authority_configs.h"


struct enclave_responder_args {
     asylo::EnclaveClient *client;
     HotMsg *hotMsg;
     std::string server_addr;
     uint32_t port; 
};

class Asylo_SGX{
    public:
        Asylo_SGX(std::string enclave_name, asylo::CleansingVector<uint8_t> serialized_signing_key){
        //enclave name has to be unique
        this->m_name = enclave_name;
        this->serialized_signing_key = serialized_signing_key;
    }

        void setTimeStamp(unsigned long int timeStart);
        void setLambdaInput(hello_world::MP_Lambda_Input& input);    
        hello_world::MP_Lambda_Input getLambdaInput();    
        unsigned long int getTimeStamp();
        void run_code(std::string *code);
        void put_ecall(capsule_pdu *dc);
        void init();
        void send_to_sgx(std::string message);
        void execute_coordinator();
        void execute_js_file(std::string input_file);
        void execute_js_code(std::string code);
        void start_sync_epoch_thread();
        void execute();
        void execute_mpl();
        void finalize();
        void run(std::vector<std::string>  names);
        void start_crypt_actor_thread();

    private:
    asylo::EnclaveManager *manager;
    asylo::EnclaveClient *client;
    std::string m_name;
    hello_world::MP_Lambda_Input lambda_input; 
    asylo::CleansingVector<uint8_t> serialized_signing_key;
    HotMsg *circ_buffer_enclave;
    HotMsg *circ_buffer_host; 
    int requestedCallID;
    unsigned long int timeStart;
};