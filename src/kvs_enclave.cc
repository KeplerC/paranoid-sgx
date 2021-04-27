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

#include <cstdint>
#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/escaping.h"
#include "asylo/trusted_application.h"
#include "asylo/util/logging.h"
#include "asylo/util/status.h"
#include "asylo/crypto/aead_cryptor.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/util/status_macros.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_generator.h"
#include "capsule.h"
#include "memtable.hpp"
#include "hot_msg_pass.h"
#include "common.h"
#include "src/proto/hello.pb.h"
#include "src/util/proto_util.hpp"
#include "benchmark.h"
#include "duktape/duktape.h"

//GRPC 
#include "src/translator_server.grpc.pb.h"
#include "asylo/grpc/auth/enclave_channel_credentials.h"
#include "asylo/grpc/auth/sgx_local_credentials_options.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/grpcpp.h"

#include <utility>
#include <unordered_map>

namespace asylo {

    namespace {

        using examples::grpc_server::Translator;
        using examples::grpc_server::RetrieveKeyPairResponse;
        using examples::grpc_server::RetrieveKeyPairRequest;

        const absl::Duration kChannelDeadline = absl::Seconds(5);

        // Makes a GetKeyPair RPC with |request| to the server backed by *|stub|.
        StatusOr<RetrieveKeyPairResponse> RetrieveKeyPair(
            const RetrieveKeyPairRequest &request, Translator::Stub *stub) {
        RetrieveKeyPairResponse response;

        ::grpc::ClientContext context;
        ASYLO_RETURN_IF_ERROR(
            asylo::Status(stub->RetrieveKeyPair(&context, request, &response)));
        return response;
        }
    }

    class HelloApplication : public asylo::TrustedApplication {
    public:
        HelloApplication() : visitor_count_(0) {}

        /*
          We can allocate OCALL params on stack because params are copied to circular buffer.
        */
        void put_ocall(capsule_pdu *dc){
            OcallParams args;
            args.ocall_id = OCALL_PUT;
            args.data = dc;
            HotMsg_requestOCall( buffer, requestedCallID++, &args);

        }

        int HotMsg_requestOCall( HotMsg* hotMsg, int dataID, void *data ) {
            int i = 0;
            const uint32_t MAX_RETRIES = 10;
            uint32_t numRetries = 0;
            int data_index = dataID % (MAX_QUEUE_LENGTH - 1);

            //Request call
            while( true ) {
                HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[data_index];
                sgx_spin_lock( &data_ptr->spinlock );

                if( data_ptr-> isRead == true ) {
                    data_ptr-> isRead  = false;
                    OcallParams *arg = (OcallParams *) data;
                    hello_world::CapsulePDU out_dc;
                    asylo::CapsuleToProto((capsule_pdu *) arg->data, &out_dc);

                    std::string out_s;
                    out_dc.SerializeToString(&out_s);
                    data_ptr->data = primitives::TrustedPrimitives::UntrustedLocalAlloc(out_s.size());
                    data_ptr->size = out_s.size();    
                    memcpy(data_ptr->data, out_s.c_str(), data_ptr->size);

                    data_ptr->ocall_id = arg->ocall_id;
                    sgx_spin_unlock( &data_ptr->spinlock );
                    break;
                }
                //else:
                sgx_spin_unlock( &data_ptr->spinlock );

                numRetries++;
                if( numRetries > MAX_RETRIES ){
                    LOGI << "exceeded tries\n";
                    sgx_spin_unlock( &data_ptr->spinlock );
                    return -1;
                }

                for( i = 0; i<3; ++i)
                    _mm_sleep();
            }

            return numRetries;
        }

        void EnclaveMsgStartResponder( HotMsg *hotMsg )
        {
            int dataID = 0;

            static int i;
            sgx_spin_lock(&hotMsg->spinlock );
            hotMsg->initialized = true;
            sgx_spin_unlock(&hotMsg->spinlock);

            while( true )
            {

                if( hotMsg->keepPolling != true ) {
                    break;
                }

                HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[dataID];

                sgx_spin_lock( &data_ptr->spinlock );
                if (data_ptr == 0){
                    sgx_spin_unlock( &data_ptr->spinlock );
                    continue;
                }

                if(data_ptr->data){
                    //Message exists!
                    EcallParams *arg = (EcallParams *) data_ptr->data;

                    char *code = (char *) arg->data;
                    capsule_pdu *dc = new capsule_pdu(); // freed below
                    CapsuleToCapsule(dc, (capsule_pdu *) arg->data);
                    primitives::TrustedPrimitives::UntrustedLocalFree((capsule_pdu *) arg->data);
                    m_lamport_timer = std::max(m_lamport_timer, dc->timestamp) + 1;
                    switch(arg->ecall_id){
                        case ECALL_PUT:
                            LOGI << "[CICBUF-ECALL] transmitted a data capsule pdu";
                            DUMP_CAPSULE(dc);
                            if (verify_dc(dc, verifying_key)) {
                                LOGI << "dc verification successful.";
                            } else {
                                LOGI << "dc verification failed!!!";
                            }
                            // once received RTS, send the latest EOE
                            if (dc->payload.key == COORDINATOR_RTS_KEY && !is_coordinator) {
                                put(COORDINATOR_EOE_KEY, m_prev_hash, false, false);
                                break;
                            }
                            else if (dc->payload.key == COORDINATOR_EOE_KEY && is_coordinator){
                                std::pair<std::string, int64_t> p;
                                p.first = dc->payload.value;
                                p.second = dc->timestamp;
                                m_eoe_hashes[dc->sender] = p;
                                if(m_eoe_hashes.size() == TOTAL_THREADS - 2) { //minus 2 for server thread and coordinator thread
                                    LOGI << "coordinator received all EOEs, sending report" << serialize_eoe_hashes();
                                    put(COORDINATOR_SYNC_KEY, serialize_eoe_hashes(), false, true);
                                    m_eoe_hashes.clear();
                                }
                            }
                            else if (dc->payload.key == COORDINATOR_SYNC_KEY && !is_coordinator ){
                                compare_eoe_hashes_from_string(dc->payload.value);
                                LOGI << "Received the sync report " << serialize_eoe_hashes();
                                m_prev_hash = dc -> metaHash;
                                // the following writes hash points to the prev sync point
                                std::pair<std::string, int64_t> p;
                                p.first = dc->metaHash;
                                p.second = dc->timestamp;
                                m_eoe_hashes[m_enclave_id] = p;
                            }
                            else {
                                update_client_hash(dc);
                                memtable.put(dc);
                            }
                            break;
                        case ECALL_RUN:
                            duk_eval_string(ctx, code);
                            break;
                        default:
                            LOGI << "Invalid ECALL id: %d\n", arg->ecall_id;
                    }
                    delete dc;
                    primitives::TrustedPrimitives::UntrustedLocalFree(arg);
                    data_ptr->data = 0;
                }

                data_ptr->isRead      = true;
                sgx_spin_unlock( &data_ptr->spinlock );
                dataID = (dataID + 1) % (MAX_QUEUE_LENGTH - 1);
                for( i = 0; i<3; ++i)
                    _mm_pause();
            }
        }

        asylo::Status Initialize(const EnclaveConfig &config){
            return asylo::Status::OkStatus();
        }

        // Fake client
        asylo::Status Run(const asylo::EnclaveInput &input,
                          asylo::EnclaveOutput *output) override {

            m_prev_hash = "init";
            requestedCallID = 0;
            m_lamport_timer = 0;

            // Assign signing and verifying key
            if (input.HasExtension(hello_world::crypto_param)) {
                ASYLO_ASSIGN_OR_RETURN(signing_key,
                        EcdsaP256Sha256SigningKey::CreateFromDer(input.GetExtension(hello_world::crypto_param).key()));
                ASYLO_ASSIGN_OR_RETURN(verifying_key,
                    signing_key->GetVerifyingKey());
            }

            if (input.HasExtension(hello_world::enclave_responder)) {

                //Initialize JS engine
                 ctx = duk_create_heap_default();

                //Register 'put' and 'get' functions
                duk_push_c_function(ctx, js_put, 2 /*nargs*/);
                duk_put_global_string(ctx, "put");

                duk_push_c_function(ctx, js_get, 1 /*nargs*/);
                duk_put_global_string(ctx, "get");

                duk_push_c_function(ctx, js_print, 1 /*nargs*/);
                duk_put_global_string(ctx, "print");

                //Register memtable as global object
                duk_push_pointer(ctx, this); 
                duk_put_global_string(ctx, "ctx");

                std::string server_addr = input.GetExtension(hello_world::kvs_server_config).server_address();
        
                if (server_addr.empty()) {
                    return absl::InvalidArgumentError(
                        "Input must provide a non-empty server address");
                }

                int32_t port = input.GetExtension(hello_world::kvs_server_config).port();
                server_addr = absl::StrCat(server_addr, ":", port);

                LOG(INFO) << "Configured with KVS Address: " << server_addr;

                // The ::grpc::ChannelCredentials object configures the channel authentication
                // mechanisms used by the client and server. This particular configuration
                // enforces that both the client and server authenticate using SGX local
                // attestation.
                std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
                    EnclaveChannelCredentials(
                        asylo::BidirectionalSgxLocalCredentialsOptions());

                // Connect a gRPC channel to the server specified in the EnclaveInput.
                std::shared_ptr<::grpc::Channel> channel =
                    ::grpc::CreateChannel(server_addr, channel_credentials);

                gpr_timespec absolute_deadline = gpr_time_add(
                    gpr_now(GPR_CLOCK_REALTIME),
                    gpr_time_from_micros(absl::ToInt64Microseconds(kChannelDeadline),
                                        GPR_TIMESPAN));
                if (!channel->WaitForConnected(absolute_deadline)) {
                    LOG(INFO) << "Failed to connect to server";  

                    //return absl::InternalError("Failed to connect to server");
                } else {
                    LOG(INFO) << "Successfully connected to server";

                    hello_world::GrpcClientEnclaveInput client_input;
                    hello_world::GrpcClientEnclaveOutput client_output;

                    std::unique_ptr <Translator::Stub> stub = Translator::NewStub(channel);

                    ASYLO_ASSIGN_OR_RETURN(
                            *client_output.mutable_key_pair_response(),
                            RetrieveKeyPair(client_input.key_pair_request(), stub.get()));

                    RetrieveKeyPairResponse resp = *client_output.mutable_key_pair_response();

                    priv_key = resp.private_key();
                    pub_key = resp.public_key();

                    LOG(INFO) << "Worker enclave configured with private key: " << priv_key << " public key: "
                              << pub_key;
                }
                HotMsg *hotmsg = (HotMsg *) input.GetExtension(hello_world::enclave_responder).responder();
                EnclaveMsgStartResponder(hotmsg);
                return asylo::Status::OkStatus();
            }
            else if (input.HasExtension(hello_world::is_coordinator)) {
                LOGI << "[Coordinator] Up and Running";
                m_enclave_id = 1;
                buffer = (HotMsg *) input.GetExtension(hello_world::is_coordinator).circ_buffer();
                is_coordinator = true;
                // ideally, coordinator is a special form of client
                // it does not keep special information, it should maintain the same level of information as other clients

                sleep(3);

                while (true){
                    sleep(EPOCH_TIME);
                    //send request to sync packet
                    put(COORDINATOR_RTS_KEY, "RTS", false, false);
                }
                return asylo::Status::OkStatus();
            } else if (input.HasExtension(hello_world::is_sync_thread)){
                LOGI << "sync running";
                return asylo::Status::OkStatus();
            }
            else{
                is_coordinator = false;
            }


            // SgxIdentity identity = GetSelfSgxIdentity();
            // asylo::sgx::CodeIdentity *y = identity.mutable_code_identity(); 
            // Sha256HashProto *mrenclave = y->mutable_mrenclave();

            // EnclaveIdentity x = SerializeSgxIdentity(identity).ValueOrDie();
            // EnclaveIdentityDescription *enc_desc = x.mutable_description(); 
            // printf("identity_type: %d, %s\n", enc_desc->identity_type(), mrenclave->mutable_hash());
            
            //Then the client wants to put some messages
            buffer = (HotMsg *) input.GetExtension(hello_world::buffer).buffer();

            m_enclave_id = std::stoi(input.GetExtension(hello_world::buffer).enclave_id());
            sleep(3);
            // TODO: there still has some issues when the client starts before the client connects to the server
            // if we want to consider it, probably we need to buffer the messages


            for( uint64_t i=0; i < 1; ++i ) {
                LOGI << "[ENCLAVE] ===CLIENT PUT=== ";
                LOGI << "[ENCLAVE] Generating a new capsule PDU ";
                put("default_key", "default_value");
            }


            sleep(2);


            for( uint64_t i=0; i < 1; ++i ) {
                //dc[i].id = i;
                LOGI << "[ENCLAVE] ===CLIENT GET=== ";
                capsule_pdu tmp_dc = memtable.get("default_key");
                DUMP_CAPSULE((&tmp_dc));
            }

            benchmark();
            return asylo::Status::OkStatus();
        }

    private:
        uint64_t visitor_count_;
        MemTable memtable;
        HotMsg *buffer;
        int requestedCallID;
        int counter;
        duk_context *ctx;
        std::string priv_key;
        std::string pub_key;
        bool is_coordinator;
        int m_enclave_id;
        std::unique_ptr <SigningKey> signing_key;
        std::unique_ptr <VerifyingKey> verifying_key;
        std::string m_prev_hash;
        std::unordered_map<int, std::pair<std::string, int64_t>> m_eoe_hashes;
        int64_t m_lamport_timer;


        void put_internal(capsule_pdu *dc, bool to_memtable = true, bool update_hash = true, bool to_network = true) {
            if(update_hash)
                update_client_hash(dc);
            if(to_memtable)
                memtable.put(dc);
            if(to_network)
                put_ocall(dc);
        }

        void put(std::string key, std::string value, bool to_memtable = true, bool update_hash = true, bool to_network = true) {
            m_lamport_timer += 1;
            capsule_pdu *dc = new capsule_pdu();
            asylo::KvToCapsule(dc, key, value, m_lamport_timer, m_enclave_id, signing_key);
            dc -> prevHash = m_prev_hash;
            m_prev_hash = dc->metaHash;
            DUMP_CAPSULE(dc);
            put_internal(dc, to_memtable, update_hash, to_network);
            delete dc;
        }

        void get(std::string key){
            memtable.get(key);
        }

        std::string serialize_eoe_hashes(){
            std::string ret = "";
            for( const auto& [key, pair] : m_eoe_hashes ) {
               ret +=  std::to_string(key) + "," + pair.first + "," +  std::to_string(pair.second) + "\n";
            }
            return ret;
        }

        static duk_ret_t js_print(duk_context *ctx) {
            LOGI << duk_to_string(ctx, 0);
            return 0;  /* no return value (= undefined) */
        }

        static duk_ret_t js_put(duk_context *ctx){
            std::string key = duk_to_string(ctx, 0);
            std::string val = duk_to_string(ctx, 1);

            duk_eval_string(ctx, "ctx");
            HelloApplication *m = (HelloApplication *) duk_to_pointer(ctx, -1);
            m->put(key, val);
            return 0;           
        }

        static duk_ret_t js_get(duk_context *ctx){
//            capsule_id id = duk_to_int(ctx, 0);
//
//            duk_eval_string(ctx, "ctx");
//            HelloApplication *m = (HelloApplication *) duk_to_pointer(ctx, -1);

//            duk_idx_t obj_idx = duk_push_object(ctx);
//            capsule_pdu *dc = m->get(id);
//
//            duk_push_string(ctx, dc->payload.key.c_str());
//            duk_put_prop_string(ctx, obj_idx, "key");
//
//            duk_push_string(ctx, dc->payload.value.c_str());
//            duk_put_prop_string(ctx, obj_idx, "val");

            return 1;           
        }

        void compare_eoe_hashes_from_string(std::string s){
            // deserialize the string into hash
            std::unordered_map<int, std::pair<std::string, int64_t>> tmp;
            std::stringstream ss(s);
            while(true)
            {
                std::string key, value, ts;
                //try to read key, if there is none, break
                if (!getline(ss, key, ',')) break;
                getline(ss, value, ',');
                getline(ss, ts, '\n');
                std::pair<std::string, int64_t> p;
                p.first = value;
                p.second = std::stoll(ts);
                tmp[std::stoi(key)] = p;
            }

            for( const auto& [key, sync_pt_pair] : tmp ) {
                auto m_current_hash_ts_pair = m_eoe_hashes[key];
                if(sync_pt_pair.first != m_current_hash_ts_pair.first){
                    if(sync_pt_pair.second > m_current_hash_ts_pair.second){
                        LOG(INFO) << "INCONSISTENCY DETECTED! " << key << " " << m_enclave_id;
                        LOG(INFO) << "SYNC " << sync_pt_pair.first << " " << sync_pt_pair.second;
                        LOG(INFO) << "CURRENT " << m_current_hash_ts_pair.first << " " << m_current_hash_ts_pair.second;
                        inconsistency_handler();
                    }
                }
            }

        }

        void update_client_hash(capsule_pdu* dc){
            std::pair<std::string, int64_t> p;
            p.first = dc-> metaHash;
            p.second = dc->timestamp;
            m_eoe_hashes[dc->sender] = p;
        }

        void inconsistency_handler(){
            return;
        }

        M_BENCHMARK_CODE
    };

    TrustedApplication *BuildTrustedApplication() { return new HelloApplication; }

}  // namespace asylo