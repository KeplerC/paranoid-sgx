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

#include "asylo/identity/enclave_assertion_authority_configs.h"

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");

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

static void* StartEnclaveResponder( void* hotMsgAsVoidP ) {

    //To be started in a new thread
    struct enclave_responder_args *args = (struct enclave_responder_args *) hotMsgAsVoidP;
    struct enclave_responder_args params;
    params.hotMsg = args->hotMsg;
    params.client = args->client;

    HotMsg *hotMsg = args->hotMsg;

    asylo::EnclaveInput input;
    asylo::EnclaveOutput output;

    input.MutableExtension(hello_world::enclave_responder)->set_responder((long int)  hotMsg);
    input.MutableExtension(hello_world::kvs_server_config)->set_server_address(args->server_addr);
    input.MutableExtension(hello_world::kvs_server_config)->set_port(args->port);
    params.client->EnterAndRun(input, &output);

    return NULL;
}

static void *StartOcallResponder( void *arg ) {

    HotMsg *hotMsg = (HotMsg *) arg;

    int dataID = 0;

    static int i;
    sgx_spin_lock(&hotMsg->spinlock );
    hotMsg->initialized = true;
    sgx_spin_unlock(&hotMsg->spinlock);

    zmq::context_t context (1);
    // to router
    zmq::socket_t* socket_ptr  = new  zmq::socket_t( context, ZMQ_PUSH);
    socket_ptr -> connect ("tcp://" + std::string(NET_SEED_SERVER_IP) + ":6667");
    // to sync server
    zmq::socket_t* socket_ptr_to_sync  = new  zmq::socket_t( context, ZMQ_PUSH);
    socket_ptr_to_sync -> connect ("tcp://" + std::string(NET_SYNC_SERVER_IP) +":" + std::to_string(NET_SYNC_SERVER_PORT));

    while( true )
    {
        if( hotMsg->keepPolling != true ) {
            break;
        }

        HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[dataID];
        if (data_ptr == 0){
            continue;
        }

        sgx_spin_lock( &data_ptr->spinlock );

        if(data_ptr->data){
            //Message exists!
            std::string in_s((char *) data_ptr->data, data_ptr->size);
            free(data_ptr->data); // allocated using malloc

            hello_world::CapsulePDU in_dc;
            in_dc.ParseFromString(in_s);

            switch(data_ptr->ocall_id){
            case OCALL_PUT: {
                // TODO: we do everything inside of the lock, this is slow
                // we can copy the string and process it after we release the lock
                LOGI << "[CICBUF-OCALL] transmitted a data capsule pdu";
                asylo::dumpProtoCapsule(&in_dc);

                std::string out_s;
                in_dc.SerializeToString(&out_s);
                zmq::message_t msg(out_s.size());
                memcpy(msg.data(), out_s.c_str(), out_s.size());
                if(in_dc.payload().key() == COORDINATOR_EOE_KEY){
                    socket_ptr_to_sync->send(msg);
                }else {
                    socket_ptr->send(msg);
                }
                break;
            }
            default:
                printf("Invalid ECALL id: %d\n", data_ptr->ocall_id);
            }
            data_ptr->data = 0;
        }

        data_ptr->isRead      = true;
        sgx_spin_unlock( &data_ptr->spinlock );


        dataID = (dataID + 1) % (MAX_QUEUE_LENGTH - 1);
        for( i = 0; i<3; ++i)
            _mm_pause();
    }
}



void Asylo_SGX::setTimeStamp(unsigned long int timeStart){
    this->timeStart = timeStart;
}

unsigned long int Asylo_SGX::getTimeStamp(){
    return this->timeStart; 
}

void Asylo_SGX::run_code(std::string *code){
    EcallParams *args = (EcallParams *) malloc(sizeof(OcallParams));
    args->ecall_id = ECALL_RUN;
    args->data = (char *) code->c_str(); 
    args->data = (char *) calloc(code->size()+1, sizeof(char));
    memcpy(args->data, code->c_str(), code->size()); 
    HotMsg_requestECall( circ_buffer_enclave, requestedCallID++, args);
}

void Asylo_SGX::put_ecall(capsule_pdu *dc) {
    EcallParams *args = (EcallParams *) malloc(sizeof(OcallParams)); // freed in enclave
    args->ecall_id = ECALL_PUT;
    args->data = dc; 
    HotMsg_requestECall( circ_buffer_enclave, requestedCallID++, args);
}

void Asylo_SGX::init(){
    asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
    auto manager_result = asylo::EnclaveManager::Instance();
    if (!manager_result.ok()) {
        LOG(QFATAL) << "EnclaveManager unavailable: " << manager_result.status();
    }
    this->manager = manager_result.ValueOrDie();
    LOGI  << "Loading " << absl::GetFlag(FLAGS_enclave_path);

    // Create an EnclaveLoadConfig object.
    asylo::EnclaveLoadConfig load_config;
    load_config.set_name(this->m_name);

    // Create a config that initializes the SGX assertion authority.
    *load_config.mutable_config()->add_enclave_assertion_authority_configs() = std::move(asylo::CreateSgxLocalAssertionAuthorityConfig("A 16-byte string")).ValueOrDie();

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
    LOGI << "Enclave " << this->m_name << " Initialized" << std::endl;

    // Initialize the OCALL/ECALL circular buffers for switchless calls 
    circ_buffer_enclave = (HotMsg *) calloc(1, sizeof(HotMsg));   // HOTMSG_INITIALIZER;
    HotMsg_init(circ_buffer_enclave);

    circ_buffer_host = (HotMsg *) calloc(1, sizeof(HotMsg));   // HOTMSG_INITIALIZER;
    HotMsg_init(circ_buffer_host);

    //ID for ECALL requests
    requestedCallID = 0; 

    LOGI << "OCALL and ECALL circular buffers initialized." << std::endl;

    this->client = this->manager->GetClient(this->m_name);

    //Starts Enclave responder
    struct enclave_responder_args e_responder_args = {this->client, circ_buffer_enclave, NET_KEY_DIST_SERVER_IP, NET_KEY_DIST_SERVER_PORT};
    pthread_create(&circ_buffer_enclave->responderThread, NULL, StartEnclaveResponder, (void*)&e_responder_args);

    //Start Host Responder
    pthread_create(&circ_buffer_host->responderThread, NULL, StartOcallResponder, (void*) circ_buffer_host);

}

void Asylo_SGX::send_to_sgx(std::string message){

    this->client = this->manager->GetClient(this->m_name);

    hello_world::CapsulePDU in_dc;
    in_dc.ParseFromString(message);
    if(in_dc.sender() == std::stoi(this->m_name)){
        return;
    }
    capsule_pdu *dc = new capsule_pdu();
    asylo::CapsuleFromProto(dc, &in_dc);

    if (this->m_name == "1") {
        LOGI << "Coordinator " << this->m_name << " puts capsule into CIRBUF-ECALL";
    } else {
        LOGI << "Client (>=2) " << this->m_name << " puts capsule into CIRBUF-ECALL";
    }
    put_ecall(dc);
    //Sleep so that threads have time to process ALL requests
}

void Asylo_SGX::execute_coordinator() {
    asylo::EnclaveInput input;
    asylo::EnclaveOutput output;

    input.MutableExtension(hello_world::is_coordinator)->set_circ_buffer((long int) circ_buffer_host);;
    this->client->EnterAndRun(input, &output);
}

void Asylo_SGX::start_sync_epoch_thread() {
    asylo::EnclaveInput input;
    asylo::EnclaveOutput output;

    input.MutableExtension(hello_world::is_sync_thread)->set_is_sync(1);;
    this->client->EnterAndRun(input, &output);
}

//start a fake client
void Asylo_SGX::execute(){

    //Test OCALL
    asylo::EnclaveInput input;        
    asylo::EnclaveOutput output;
    //Register OCALL buffer to enclave 
    input.MutableExtension(hello_world::buffer)->set_buffer((long int) circ_buffer_host);
    input.MutableExtension(hello_world::buffer)->set_enclave_id(m_name);

    hello_world::MP_Lambda_Input lambda_input;

    lambda_input.set_time_start(timeStart);

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

    *input.MutableExtension(hello_world::lambda_input) = lambda_input;

    asylo::Status status = this->client->EnterAndRun(input, &output);
    if (!status.ok()) {
        LOG(QFATAL) << "EnterAndRun failed: " << status;
    }

    //Load server/port
    input.MutableExtension(hello_world::kvs_server_config)->set_server_address(NET_KEY_DIST_SERVER_IP);
    input.MutableExtension(hello_world::kvs_server_config)->set_port(NET_KEY_DIST_SERVER_PORT);


//        asylo::EnclaveInput input;
//        input.MutableExtension(hello_world::buffer)->set_buffer((long int) circ_buffer_host);
//        input.MutableExtension(hello_world::buffer)->set_enclave_id(m_name);
//
//        asylo::EnclaveOutput output;

//        asylo::Status status = this->client->EnterAndRun(input, &output);
//        if (!status.ok()) {
//            LOG(QFATAL) << "EnterAndRun failed: " << status;
//        }

//        std::string input_js = absl::GetFlag(FLAGS_input_file);
//        std::ifstream t(input_js);
//        std::stringstream buffer;
//        buffer << t.rdbuf();
//
//        std::string code = buffer.str();
    //Execute JS file 
    //run_code(&code);

    //Sleep so that threads have time to process ALL requests
    sleep(1);
}

void Asylo_SGX::finalize(){
    asylo::EnclaveFinal final_input;
    asylo::Status status = this->manager->DestroyEnclave(this->client, final_input);
    StopMsgResponder( circ_buffer_host );
    pthread_join(circ_buffer_host->responderThread, NULL);

    StopMsgResponder( circ_buffer_enclave );
    pthread_join(circ_buffer_enclave->responderThread, NULL);

    free(circ_buffer_host);
    free(circ_buffer_enclave);

    if (!status.ok()) {
        LOG(QFATAL) << "Destroy " << absl::GetFlag(FLAGS_enclave_path)
                    << " failed: " << status;
    }
}

void Asylo_SGX::run(std::vector<std::string>  names){
    init();
    execute();
    finalize();
}