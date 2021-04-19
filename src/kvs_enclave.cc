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
#include "capsule.h"
#include "memtable.hpp"
#include "hot_msg_pass.h"
#include "common.h"
#include "src/proto/hello.pb.h"
#include "src/util/proto_util.hpp"
#include "benchmark.h"
#include <utility>
#include <unordered_map>

#define EPOCH_TIME 2
namespace asylo {

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
                    printf("exceeded tries\n");
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
                    capsule_pdu *dc = new capsule_pdu(); // freed below
                    CapsuleToCapsule(dc, (capsule_pdu *) arg->data);
                    primitives::TrustedPrimitives::UntrustedLocalFree((capsule_pdu *) arg->data); 
                    switch(arg->ecall_id){
                        case ECALL_PUT:
                            LOG(INFO) << "[CICBUF-ECALL] transmitted a data capsule pdu";
                            DUMP_CAPSULE(dc);
                            // once received RTS, send the latest EOE
                            if (dc->payload.key == COORDINATOR_RTS_KEY && !is_coordinator) {
                                put(COORDINATOR_EOE_KEY, m_prev_hash, false);
                                break;
                            }
                            else if (dc->payload.key == COORDINATOR_EOE_KEY && is_coordinator){
                                std::pair<std::string, int64_t> p;
                                p.first = dc->payload.value;
                                p.second = dc->timestamp;
                                m_eoe_hashes[dc->sender] = p;
                                if(m_eoe_hashes.size() == TOTAL_THREADS - 2) { //minus 2 for server thread and coordinator thread
                                    LOG(INFO) << "coordinator received all EOEs, sending report" << serialize_eoe_hashes();
                                    put(COORDINATOR_SYNC_KEY, serialize_eoe_hashes(), false);
                                    m_eoe_hashes.clear();
                                }
                            }
                            else if (dc->payload.key == COORDINATOR_SYNC_KEY){
                                compare_eoe_hashes_from_string(dc->payload.value);
                                LOG(INFO) << "Received the sync report " << serialize_eoe_hashes();
                            }
                            else {
                                update_client_hash(dc);
                                memtable.put(dc);
                            }
                            break;
                        default:
                            printf("Invalid ECALL id: %d\n", arg->ecall_id);
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

        // Fake client
        asylo::Status Run(const asylo::EnclaveInput &input,
                          asylo::EnclaveOutput *output) override {

            m_prev_hash = "init";
            requestedCallID = 0;

            if (input.HasExtension(hello_world::enclave_responder)) {
                HotMsg *hotmsg = (HotMsg *) input.GetExtension(hello_world::enclave_responder).responder();
                EnclaveMsgStartResponder(hotmsg);
                return asylo::Status::OkStatus();
            }
            else if (input.HasExtension(hello_world::is_coordinator)) {
                LOG(INFO) << "[Coordinator] Up and Running";
                m_enclave_id = 1;
                buffer = (HotMsg *) input.GetExtension(hello_world::is_coordinator).circ_buffer();
                is_coordinator = true;
                // ideally, coordinator is a special form of client
                // it does not keep special information, it should maintain the same level of information as other clients

                sleep(3);

                while (true){
                    sleep(EPOCH_TIME);
                    //send request to sync packet
                    put(COORDINATOR_RTS_KEY, "RTS");
                }
                return asylo::Status::OkStatus();
            } else if (input.HasExtension(hello_world::is_sync_thread)){
                LOG(INFO) << "is sync running";
                return asylo::Status::OkStatus();
            }
            else{
                is_coordinator = false;
            }

            //Then the client wants to put some messages
            buffer = (HotMsg *) input.GetExtension(hello_world::buffer).buffer();
            m_enclave_id = std::stoi(input.GetExtension(hello_world::buffer).enclave_id());
            sleep(3);
            // TODO: there still has some issues when the client starts before the client connects to the server
            // if we want to consider it, probably we need to buffer the messages


            for( uint64_t i=0; i < 1; ++i ) {
                LOG(INFO) << "[ENCLAVE] ===CLIENT PUT=== ";
                LOG(INFO) << "[ENCLAVE] Generating a new capsule PDU ";
                put("default_key", "default_value");
            }


            sleep(2);

            //benchmark();
            for( uint64_t i=0; i < 1; ++i ) {
                //dc[i].id = i;
                LOG(INFO) << "[ENCLAVE] ===CLIENT GET=== ";
                capsule_pdu tmp_dc = memtable.get("default_key");
                DUMP_CAPSULE((&tmp_dc));
            }
            return asylo::Status::OkStatus();
        }

    private:
        uint64_t visitor_count_;
        MemTable memtable;
        HotMsg *buffer;
        int requestedCallID;
        bool is_coordinator;
        int m_enclave_id;
        std::string m_prev_hash;
        std::unordered_map<int, std::pair<std::string, int64_t>> m_eoe_hashes;


        void put_internal(capsule_pdu *dc, bool to_memtable = true, bool to_network = true) {
            update_client_hash(dc);
            if(to_memtable)
                memtable.put(dc);
            if(to_network)
                put_ocall(dc);
        }

        void put(std::string key, std::string value, bool to_memtable = true, bool to_network = true) {
            capsule_pdu *dc = new capsule_pdu();
            asylo::KvToCapsule(dc, key, value, m_enclave_id);
            dc -> prevHash = m_prev_hash;
            m_prev_hash = dc->metaHash;
            //dc->timestamp = get_current_time();
            DUMP_CAPSULE(dc);
            put_internal(dc, to_memtable, to_network);
            delete dc;
        }

        std::string serialize_eoe_hashes(){
            std::string ret = "";
            for( const auto& [key, pair] : m_eoe_hashes ) {
               ret +=  std::to_string(key) + "," + pair.first + "," +  std::to_string(pair.second) + "\n";
            }
            return ret;
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
                        LOG(INFO) << "INCONSISTENCY DETECTED!";
                        LOG(INFO) << "SYNC " << sync_pt_pair.first << " " << sync_pt_pair.second;
                        LOG(INFO) << "CURRENT " << m_current_hash_ts_pair.first << " " << m_current_hash_ts_pair.second;
                        inconsistency_handler();
                    }
                }
            }

        }

        void update_client_hash(capsule_pdu* dc){
            std::pair<std::string, int64_t> p;
            p.first = dc-> prevHash;
            p.second = dc->timestamp;
            m_eoe_hashes[dc->sender] = p;
        }

        void inconsistency_handler(){
            return;
        }


        M_BENCHMARK_HERE
    };

    TrustedApplication *BuildTrustedApplication() { return new HelloApplication; }

}  // namespace asylo