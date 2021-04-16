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

#define EPOCH_TIME 1
#define COORDINATOR_KV_KEY "PARANOID_TS"
#define COORDINATOR_KV_ID 1000000
namespace asylo {

    namespace {
        // Dummy 128-bit AES key.
        constexpr uint8_t kAesKey128[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                          0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
                                          0x12, 0x13, 0x14, 0x15};
        std::unique_ptr <SigningKey> signing_key;

        // Helper function that adapts absl::BytesToHexString, allowing it to be used
        // with ByteContainerView.
        std::string BytesToHexString(ByteContainerView bytes) {
            return absl::BytesToHexString(absl::string_view(
                    reinterpret_cast<const char *>(bytes.data()), bytes.size()));
        }

        // signs the message with ecdsa signing key
        const std::vector <uint8_t> SignMessage(const std::string &message) {
            signing_key = EcdsaP256Sha256SigningKey::Create().ValueOrDie();
            std::vector <uint8_t> signature;
            ASYLO_CHECK_OK(signing_key->Sign(message, &signature));
            return signature;
        }

        // verify the message with ecdsa verfying key
        const Status VerifyMessage(const std::string &message, std::vector <uint8_t> signature) {
            std::unique_ptr <VerifyingKey> verifying_key;
            ASYLO_ASSIGN_OR_RETURN(verifying_key,
                                   signing_key->GetVerifyingKey());
            return verifying_key->Verify(message, signature);
        }

        // Encrypts a message against `kAesKey128` and returns a 12-byte nonce followed
        // by authenticated ciphertext, encoded as a hex string.
        const StatusOr <std::string> EncryptMessage(const std::string &message) {
            std::unique_ptr <AeadCryptor> cryptor;
            ASYLO_ASSIGN_OR_RETURN(cryptor,
                                   AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));

            std::vector <uint8_t> additional_authenticated_data;
            std::vector <uint8_t> nonce(cryptor->NonceSize());
            std::vector <uint8_t> ciphertext(message.size() + cryptor->MaxSealOverhead());
            size_t ciphertext_size;

            ASYLO_RETURN_IF_ERROR(cryptor->Seal(
                    message, additional_authenticated_data, absl::MakeSpan(nonce),
                    absl::MakeSpan(ciphertext), &ciphertext_size));

            return absl::StrCat(BytesToHexString(nonce), BytesToHexString(ciphertext));
        }

        const StatusOr <CleansingString> DecryptMessage(
                const std::string &nonce_and_ciphertext) {
            std::string input_bytes = absl::HexStringToBytes(nonce_and_ciphertext);

            std::unique_ptr <AeadCryptor> cryptor;
            ASYLO_ASSIGN_OR_RETURN(cryptor,
                                   AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));

            if (input_bytes.size() < cryptor->NonceSize()) {
                return Status(
                        error::GoogleError::INVALID_ARGUMENT,
                        absl::StrCat("Input too short: expected at least ",
                                     cryptor->NonceSize(), " bytes, got ", input_bytes.size()));
            }

            std::vector <uint8_t> additional_authenticated_data;
            std::vector <uint8_t> nonce = {input_bytes.begin(),
                                           input_bytes.begin() + cryptor->NonceSize()};
            std::vector <uint8_t> ciphertext = {input_bytes.begin() + cryptor->NonceSize(),
                                                input_bytes.end()};

            // The plaintext is always smaller than the ciphertext, so use
            // `ciphertext.size()` as an upper bound on the plaintext buffer size.
            CleansingVector <uint8_t> plaintext(ciphertext.size());
            size_t plaintext_size;

            ASYLO_RETURN_IF_ERROR(cryptor->Open(ciphertext, additional_authenticated_data,
                                                nonce, absl::MakeSpan(plaintext),
                                                &plaintext_size));

            return CleansingString(plaintext.begin(), plaintext.end());
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
            //                LOG(INFO) << "= Encryption and Decryption =";
            //                std::string result;
            //                ASYLO_ASSIGN_OR_RETURN(result, EncryptMessage(visitor));
            //                LOG(INFO) << "encrypted: " << result;
            //                ASYLO_ASSIGN_OR_RETURN(result, DecryptMessage(result));
            //                LOG(INFO) << "decrypted: " << result;
            //                LOG(INFO) << "= Sign and Verify =";
            //                LOG(INFO) << "signed: " << reinterpret_cast<const char*>(SignMessage(visitor).data());
            //                LOG(INFO) << "verified: " << VerifyMessage(visitor, SignMessage(visitor));
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
                            //printf("[ECALL] dc_id : %d\n", dc->id);
                            LOG(INFO) << "[CICBUF-ECALL] transmitted a data capsule pdu";
                            dumpCapsule(dc);
                            if (dc->payload.key == COORDINATOR_KV_KEY) {
                                std::stringstream ss (dc->payload.value);
                                std::string ts;
                                std::string signed_ts;
                                //first field is timestamp
                                //(use comma separated because we may need csv for signatures in the future)
                                getline(ss, ts, ',');
                                //second field is signature
                                getline(ss, signed_ts, ',');
                                std::vector<unsigned char> vec_signed_ts(signed_ts.begin(), signed_ts.end());
                                //TODO: the verification doesn't work for some weird reason (seg fault at ASYLO_ASSIGN_OR_RETURN)
                                // Do we need to verify here? Or just verifying a capsule is sufficient
                                //VerifyMessage(ts, vec_signed_ts);
                                //LOG(INFO) << VerifyMessage(ts, vec_signed_ts);
                                this->m_latest_sync_hash = ts;
                            }

                            if (is_coordinator){
                                // try a simple way for now: sign a timestamp, the packets beyond this timestamp will be dropped
                                // need fancier mechanisms when we know how to store the hash ptrs
                                // TODO (Hanming): update clients' current headerHash
                            } else {
                                if(dc->syncHash == m_latest_sync_hash)
                                    memtable.put(dc);
                                    // TODO (Hanming): update other clients' current headerHash
                                else
                                    LOG(INFO) << "[DIFFERENT HASH DISCARDED]"<< "dc: "<< dc -> syncHash
                                        << " m_latest: "<< m_latest_sync_hash;
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

            m_latest_sync_hash = "init";
            requestedCallID = 0;
            counter = 0;

            if (input.HasExtension(hello_world::enclave_responder)) {
                HotMsg *hotmsg = (HotMsg *) input.GetExtension(hello_world::enclave_responder).responder();
                EnclaveMsgStartResponder(hotmsg);
                return asylo::Status::OkStatus();
            }
            else if (input.HasExtension(hello_world::is_coordinator)) {
                LOG(INFO) << "[Coordinator] Up and Running";
                buffer = (HotMsg *) input.GetExtension(hello_world::is_coordinator).circ_buffer();
                is_coordinator = true;
                counter = COORDINATOR_KV_ID;
                // ideally, coordinator is a special form of client
                // it does not keep special information, it should maintain the same level of information as other clients

                sleep(3);

                while (true){
                    sleep(EPOCH_TIME);
                    std::string current_time= std::to_string(get_current_time());
                    m_latest_sync_hash = current_time;
                    //reinterpret_cast<const char*>(SignMessage(visitor).data())
                    std::vector<unsigned char> s = SignMessage(current_time);

                    //send signed timestamp to others
                    std::string current_time_signed(s.begin(), s.end());
                    //LOG(INFO) << VerifyMessage(current_time, s);
                    capsule_pdu *dc = new capsule_pdu(); // freed below
                    asylo::KvToCapsule(dc, counter++, COORDINATOR_KV_KEY, current_time + "," + current_time_signed);
                    dc->syncHash = current_time;
                    LOG(INFO) << "[Coordinator] Send out sync msg capsule";
                    dumpCapsule(dc);
                    put_internal(dc);
                    delete dc;
                }
                return asylo::Status::OkStatus();
            } else if (input.HasExtension(hello_world::is_sync_thread)){
                LOG(INFO) << "is sync running";
            }
            else{
                is_coordinator = false;
            }

            //Then the client wants to put some messages
            buffer = (HotMsg *) input.GetExtension(hello_world::buffer).buffer();
            sleep(3);
            // TODO: there still has some issues when the client starts before the client connects to the server
            // if we want to consider it, probably we need to buffer the messages


            for( uint64_t i=0; i < 1; ++i ) {
                LOG(INFO) << "[ENCLAVE] ===CLIENT PUT=== ";
                LOG(INFO) << "[ENCLAVE] Generating a new capsule PDU ";
                //asylo::KvToCapsule(&dc[i], i, "default_key", "original_value");
                put("default_key", "default_value");
            }


            sleep(2);

            for( uint64_t i=0; i < 1; ++i ) {
                //dc[i].id = i;
                LOG(INFO) << "[ENCLAVE] ===CLIENT GET=== ";
                capsule_pdu tmp_dc = memtable.get(i);
                dumpCapsule(&tmp_dc);
            }

            //benchmark();

            return asylo::Status::OkStatus();
        }

    private:
        uint64_t visitor_count_;
        MemTable memtable;
        HotMsg *buffer;
        int requestedCallID;
        int counter;
        bool is_coordinator;
        std::string m_latest_sync_hash;

        void put_internal(capsule_pdu *dc) {
            memtable.put(dc);
            put_ocall(dc);
        }

        void put(std::string key, std::string value) {
            // capsule_pdu *dc = (capsule_pdu *) malloc(sizeof(capsule_pdu));
            capsule_pdu *dc = new capsule_pdu();
            asylo::KvToCapsule(dc, counter++, key, value);
            dc -> syncHash = m_latest_sync_hash;
            //dc->timestamp = get_current_time();
            dumpCapsule(dc);
            put_internal(dc);
            delete dc;
        }

        M_BENCHMARK_HERE
    };

    TrustedApplication *BuildTrustedApplication() { return new HelloApplication; }

}  // namespace asylo