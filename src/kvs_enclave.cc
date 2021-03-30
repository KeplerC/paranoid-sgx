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
#include "capsule.h"
#include "memtable.hpp"
#include "hot_msg_pass.h"
#include "common.h"
#include "src/proto/hello.pb.h"
#include "src/util/proto_util.hpp"

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
                    data_ptr->data = (void *) 1;
                    data_ptr->ocall_id = arg->ocall_id;
                    capsule_pdu *dc = (capsule_pdu *) arg->data;

                    //Must copy to the host since we cannot pass a pointer from enclave
                    memcpy(&data_ptr->dc, dc, sizeof(capsule_pdu));
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
                if (data_ptr == 0){
                    continue;
                }

                sgx_spin_lock( &data_ptr->spinlock );

                if(data_ptr->data){
                    //Message exists!
                    EcallParams *arg = (EcallParams *) data_ptr->data;
                    capsule_pdu *dc = (capsule_pdu *) arg->data;

                    switch(arg->ecall_id){
                        case ECALL_PUT:
                            printf("[ECALL] dc_id : %d\n", dc->id);
                            put((capsule_pdu *) arg->data);
                            LOG(INFO) << "DataCapsule payload.key is " << dc->payload.key;
                            LOG(INFO) << "DataCapsule payload.value is " << dc->payload.value;
                            break;
                        default:
                            printf("Invalid ECALL id: %d\n", arg->ecall_id);
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

        // Fake client
        asylo::Status Run(const asylo::EnclaveInput &input,
                          asylo::EnclaveOutput *output) override {


            if (input.HasExtension(hello_world::enclave_responder)) {
                HotMsg *hotmsg = (HotMsg *) input.GetExtension(hello_world::enclave_responder).responder();
                EnclaveMsgStartResponder(hotmsg);
                return asylo::Status::OkStatus();
            }

            //Then the client wants to put some messages
            buffer = (HotMsg *) input.GetExtension(hello_world::buffer).buffer();
            requestedCallID = 0;

            capsule_pdu dc[10];
            //simulate client do some processing...
            sleep(3);

            for( uint64_t i=0; i < 1; ++i ) {
                //dc[i].id = i;
                asylo::KvToCapsule(&dc[i], i, "input_key", "input_value");
                LOG(INFO) << "DataCapsule payload.key is " << dc[i].payload.key;
                LOG(INFO) << "DataCapsule payload.value is " << dc[i].payload.value;
                put(&dc[i]);
                put_ocall(&dc[i]);
            }
            sleep(2);

            //capsule_pdu dc[10];

            //            for( uint64_t i=0; i < 10; ++i ){
            //                put_ocall(get(i));
            //            }

            return asylo::Status::OkStatus();
        }
    private:
        uint64_t visitor_count_;
        MemTable memtable;
        HotMsg *buffer;
        int requestedCallID;

        /* These functions willl be part of the CAAPI */
        bool put(capsule_pdu *dc) {
            return memtable.put(dc);
        }

        capsule_pdu *get(capsule_id id){
            //capsule_pdu out_dc;
            LOG(INFO) << "DataCapsule id is " << (int)id;
            return memtable.get(id);
        }
    };

    TrustedApplication *BuildTrustedApplication() { return new HelloApplication; }

}  // namespace asylo