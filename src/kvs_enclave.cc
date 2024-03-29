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

#include <kvs_enclave.hpp>
#include "kvs_eapp.hpp"

#define USE_KEY_MANAGER

namespace asylo {
        // void KVSClient::put(std::string key, std::string value, bool to_memtable = true, bool update_hash = true, bool to_network = true) {
        //     m_lamport_timer += 1;
        //     capsule_pdu *dc = new capsule_pdu();
        //     asylo::KvToCapsule(dc, key, value, m_enclave_id);
        //     dc -> prevHash = m_prev_hash;
        //     dc -> timestamp = m_lamport_timer;
        //     m_prev_hash = dc->metaHash;
        //     //dc->timestamp = get_current_time();
        //     DUMP_CAPSULE(dc);
        //     put_internal(dc, to_memtable, update_hash, to_network);
        //     delete dc;
        // }

        void KVSClient::put(std::string key, std::string value, std::string msgType = "") {
            m_lamport_timer += 1;
            kvs_payload payload;
            asylo::KvToPayload(&payload, key, value, m_lamport_timer, msgType);
            DUMP_PAYLOAD((&payload));
            // enqueue to pqueue
            pqueue.enqueue(&payload);
            handle();
        }

        void KVSClient::handle() {
            // dequeue msg/txn from pqueue and then handle
            std::vector<kvs_payload> payload_l = pqueue.dequeue(BATCH_SIZE);
            if (payload_l.size() == 0){
                return;
            }
            capsule_pdu *dc = new capsule_pdu();
            asylo::PayloadListToCapsule(dc, &payload_l, m_enclave_id);

            bool success;
            // for return, do not encrypt(at least currently)
            // generate hash for update_hash and/or ocall

            bool encryption_needed = true;
            if(dc->msgType == "PSL_RET") {
                encryption_needed = false;
            }

            success = encrypt_payload_l(dc, encryption_needed);
            if (!success) {
                std::cout << "payload_l encryption failed!!!";
                delete dc;
                return;
            }

            // generate hash and update prev_hash
            success = generate_hash(dc);
            if (!success) {
                std::cout << "hash generation failed!!!";
                delete dc;
                return;
            }
            dc->prevHash = m_prev_hash;
            m_prev_hash = dc->hash;
            DUMP_CAPSULE(dc);
            // sign dc
            //TODO: signing stops working for some reason!!!
            success = sign_dc(dc, signing_key);
            if (!success) {
                std::cout << "sign dc failed!!!";
                delete dc;
                return;
            }

            // to_memtable and/or update_hash based on msgType
            bool to_memtable = (dc->msgType == "")? true : false;

            bool update_hash = (dc->msgType == "" ||
                                dc->msgType == COORDINATOR_SYNC_TYPE )? true : false;

            // store in memtable
            if(to_memtable) {
                for (int i = 0; i < dc->payload_l.size(); i++) {
                    memtable.put(&(dc->payload_l[i]));
                }
            }
            
            // update hash map
            if(update_hash)
                update_client_hash(dc);

            // send dc
            put_ocall(dc);
            
            delete dc;
        }

        kvs_payload KVSClient::get(const std::string &key){
            //TODO: Handle get via capsuleDB
            return memtable.get(key);
            // PSUEDO CODE
            /*
            while (true) {
                if (memtable.contains(key)) {
                    return memtable.get(key);
                }
            }
            */
        }

        bool KVSClient::contains(const std::string &key){
            return memtable.contains(key);
        }

        std::string KVSClient::serialize_eoe_hashes(){
            std::string ret = "";
            for( const auto& [key, pair] : m_eoe_hashes ) {
               ret +=  std::to_string(key) + "," + pair.first + "," +  std::to_string(pair.second) + "\n";
            }
            return ret;
        }

        // capsule_pdu KVSClient::get(std::string key){
        //     return memtable.get(key);
        // }

        asylo::Status KVSClient::Initialize(const EnclaveConfig &config){
            //Initialize JS engine
            ctx = duk_create_heap_default();
            duk_init_mem_interface(ctx); 
            return asylo::Status::OkStatus();
        }

        // Fake client
        asylo::Status KVSClient::Run(const asylo::EnclaveInput &input,
                          asylo::EnclaveOutput *output) {

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
                
#ifdef USE_KEY_MANAGER
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
#endif
                HotMsg *hotmsg = (HotMsg *) input.GetExtension(hello_world::enclave_responder).responder();
                EnclaveMsgStartResponder(hotmsg);
                return asylo::Status::OkStatus();
            }
            else if (input.HasExtension(hello_world::is_coordinator)) {
                std::cout << "[Coordinator] Up and Running";
                LOG(INFO) << "[Coordinator running]";
                m_enclave_id = 1;
                buffer = (HotMsg *) input.GetExtension(hello_world::is_coordinator).circ_buffer();
                is_coordinator = true;
                // ideally, coordinator is a special form of client
                // it does not keep special information, it should maintain the same level of information as other clients

                sleep(3);

                while (true){
                    sleep(EPOCH_TIME);
                    //send request to sync packet
                    put(COORDINATOR_RTS_TYPE, "RTS", COORDINATOR_RTS_TYPE);
                }
                return asylo::Status::OkStatus();
            } else if (input.HasExtension(hello_world::is_actor_thread)){
                while(true){
                    handle();
                }
                return asylo::Status::OkStatus();
            } else {
                is_coordinator = false;
            }

            //Register OCALL buffer
            buffer = (HotMsg *) input.GetExtension(hello_world::buffer).buffer();
            m_enclave_id = std::stoi(input.GetExtension(hello_world::buffer).enclave_id());

            sleep(3);

            if (input.HasExtension(hello_world::lambda_input)){
                return start_eapp(this, input);
            }

            return asylo::Status::OkStatus();
        }



        // void KVSClient::put_internal(capsule_pdu *dc, bool to_memtable = true, bool update_hash = true, bool to_network = true) {
        //     if(update_hash)
        //         update_client_hash(dc);
        //     if(to_memtable)
        //         memtable.put(dc);
        //     if(to_network)
        //         put_ocall(dc);
        // }

        // std::string KVSClient::serialize_eoe_hashes(){
        //     std::string ret = "";
        //     for( const auto& [key, pair] : m_eoe_hashes ) {
        //        ret +=  std::to_string(key) + "," + pair.first + "," +  std::to_string(pair.second) + "\n";
        //     }
        //     return ret;
        // }

        void KVSClient::compare_eoe_hashes_from_string(std::string s){
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
                        // LOG(INFO) << "INCONSISTENCY DETECTED! " << key << " " << m_enclave_id;
                        // LOG(INFO) << "SYNC " << sync_pt_pair.first << " " << sync_pt_pair.second;
                        // LOG(INFO) << "CURRENT " << m_current_hash_ts_pair.first << " " << m_current_hash_ts_pair.second;
                        inconsistency_handler();
                    }
                }
            }

        }

        void KVSClient::update_client_hash(capsule_pdu* dc){
            std::pair<std::string, int64_t> p;
            p.first = dc-> hash;
            p.second = dc->timestamp;
            m_eoe_hashes[dc->sender] = p;
        }

        void KVSClient::inconsistency_handler(){
            return;
        }

        /*
            We can allocate OCALL params on stack because params are copied to circular buffer.
        */
        void KVSClient::put_ocall(capsule_pdu *dc){
            OcallParams args;
            args.ocall_id = OCALL_PUT;
            args.data = dc;
            HotMsg_requestOCall( buffer, requestedCallID++, &args);
        }

    int KVSClient::HotMsg_requestOCall( HotMsg* hotMsg, int dataID, void *data ) {
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
                    std::cout << "exceeded tries\n";
                    sgx_spin_unlock( &data_ptr->spinlock );
                    return -1;
                }

                for( i = 0; i<3; ++i)
                    _mm_sleep();
            }

            return numRetries;
        }

        void KVSClient::EnclaveMsgStartResponder( HotMsg *hotMsg )
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


                if(data_ptr->data) {
                    //Message exists!
                    LOGI << "Received new data!";
                    EcallParams *arg = (EcallParams *) data_ptr->data;
                    if(arg->ecall_id == ECALL_RUN){
                        char *code = (char *) arg->data;
                        LOGI <<"duk eval string";
                        duk_eval_string(ctx, code);
                        data_ptr->data = 0;
                    }
                    else{
                        capsule_pdu *dc = new capsule_pdu(); // freed below
                        CapsuleToCapsule(dc, (capsule_pdu *) arg->data);
                        DUMP_CAPSULE(dc);
                        primitives::TrustedPrimitives::UntrustedLocalFree((capsule_pdu *) arg->data);
                        m_lamport_timer = std::max(m_lamport_timer, dc->timestamp) + 1;
                        switch (arg->ecall_id) {
                            case ECALL_PUT:
                                LOGI << "[CICBUF-ECALL] transmitted a data capsule pdu";
				DUMP_CAPSULE(dc);
                                if (verify_dc(dc, verifying_key)) {
                                    LOGI << "dc verification successful.";
                                } else {
                                    LOGI << "dc verification failed!!!";
                                }
                                // decrypt payload_l
                                if (decrypt_payload_l(dc)) {
                                    LOGI << "dc payload_l decryption successful";
                                } else {
                                    LOGI << "dc payload_l decryption failed!!!";
                                    break;
                                }
                                DUMP_CAPSULE(dc);
                                // once received RTS, send the latest EOE
                                if (dc->msgType == COORDINATOR_RTS_TYPE && !is_coordinator) {
                                    put(COORDINATOR_EOE_TYPE, m_prev_hash, COORDINATOR_EOE_TYPE);
                                    break;
                                } else if (dc->msgType == COORDINATOR_EOE_TYPE && is_coordinator) {
                                    // store EOE for future sync
                                    std::pair <std::string, int64_t> p;
                                    p.first = dc->payload_l[0].value;
                                    p.second = dc->timestamp;
                                    m_eoe_hashes[dc->sender] = p;
                                    // if EOE from all enclaves received, start sync
                                    if (m_eoe_hashes.size() ==
                                        TOTAL_THREADS - 2) { //minus 2 for server thread and coordinator thread
                                        LOGI << "coordinator received all EOEs, sending report" << serialize_eoe_hashes();
                                        put(COORDINATOR_SYNC_TYPE, serialize_eoe_hashes(), COORDINATOR_SYNC_TYPE);
                                        // clear this epoch's EOE
                                        m_eoe_hashes.clear();
                                    }
                                } else if (dc->msgType == COORDINATOR_SYNC_TYPE && !is_coordinator) {
                                    compare_eoe_hashes_from_string(dc->payload_l[0].value);
                                    LOGI << "Received the sync report " << serialize_eoe_hashes();
                                    m_prev_hash = dc->hash;
                                    // the following writes hash points to the prev sync point
                                    std::pair <std::string, int64_t> p;
                                    p.first = dc->hash;
                                    p.second = dc->timestamp;
                                    m_eoe_hashes[m_enclave_id] = p;
                                } else {
                                    update_client_hash(dc);
                                    for (int i = 0; i < dc->payload_l.size(); i++) {
                                        LOGI << "Put key: " << dc->payload_l[i].key << ", val: " << dc->payload_l[i].value;
                                        memtable.put(&(dc->payload_l[i]));
                                    }
                                }
                                break;
                            default:
                                LOGI << "Invalid ECALL id: %d\n", arg->ecall_id;
                        }
                        delete dc;
                        primitives::TrustedPrimitives::UntrustedLocalFree(arg);
                        data_ptr->data = 0;
                    }
                }

                data_ptr->isRead      = true;
                sgx_spin_unlock( &data_ptr->spinlock );
                dataID = (dataID + 1) % (MAX_QUEUE_LENGTH - 1);
                for( i = 0; i<3; ++i)
                    _mm_pause();
            }
        }

        void KVSClient::duk_init_mem_interface(duk_context *ctx) {
            //Register 'put' and 'get' functions
            duk_push_c_function(ctx, js_put, 2 /*nargs*/);
            duk_put_global_string(ctx, "psl_put");

            duk_push_c_function(ctx, js_get, 1 /*nargs*/);
            duk_put_global_string(ctx, "psl_get");

            duk_push_c_function(ctx, js_cdb_put, 2 /*nargs*/);
            duk_put_global_string(ctx, "cdb_put");

            duk_push_c_function(ctx, js_cdb_get, 1 /*nargs*/);
            duk_put_global_string(ctx, "cdb_get");

            duk_push_c_function(ctx, js_print, 1 /*nargs*/);
            duk_put_global_string(ctx, "console_print");

            duk_push_c_function(ctx, js_ret, 1 /*nargs*/);
            duk_put_global_string(ctx, "print");

            //Register memtable as global object
            duk_push_pointer(ctx, this); 
            duk_put_global_string(ctx, "ctx");
        }

        // TODO: No idea how to fix build issues if I uncomment this...
        // M_BENCHMARK_CODE

        TrustedApplication *BuildTrustedApplication() { return new KVSClient; }

}  // namespace asylo
