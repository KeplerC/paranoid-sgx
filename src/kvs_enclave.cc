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
// #include "absl/container/flat_hash_map.h"
#include "asylo/trusted_application.h"
#include "asylo/util/logging.h"
#include "asylo/util/status.h"
#include "src/proto/hello.pb.h"
#include "asylo/crypto/aead_cryptor.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/util/status_macros.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "gdp.h"
#include "memtable.hpp"

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

        void OnPutCapsule(hello_world::CapsulePDU *capsule_ptr, std::string key, std::string value){
            capsule_ptr->set_dc_ptr(2021);
            //dc_msg->payload_size = 13;
            //memcpy(dc_msg->payload, "Hello World!", dc_msg.payload_size);
        }
    }

    class HelloApplication : public asylo::TrustedApplication {
    public:
        HelloApplication() : visitor_count_(0) {}

        asylo::Status Run(const asylo::EnclaveInput &input,
                          asylo::EnclaveOutput *output) override {
            if (!input.HasExtension(hello_world::enclave_input_hello)) {
                return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                                     "Expected a HelloInput extension on input.");
            }

            //Check if DataCapsule is defined in proto-buf messsage.
            if (!input.HasExtension(hello_world::input_dc)) {
                return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                                     "Expected a DataCapsule extension on input.");
            }

            data_capsule_t *ret;
            data_capsule_t *dc = (data_capsule_t *) input.GetExtension(hello_world::input_dc).dc_ptr();

            LOG(INFO) << "Received DataCapsule is " << (int) dc->id << ", should be 2021!";
            LOG(INFO) << "DataCapsule payload is " << dc->payload << ", should be 'Hello World!";

            for(data_capsule_id i = 0; i < 300; i++){
                dc->id = i;
                memtable.put(dc);
            }

            for(data_capsule_id i = 0; i < 300; i++){
                ret = memtable.get(i);

                if(!ret){
                    LOG(INFO) << "GET FAILED on DataCapsule id: " << (int) i;
                }
            }

            LOG(INFO) << "Hashmap size has size: " << memtable.getSize();

            std::string visitor =
                    input.GetExtension(hello_world::enclave_input_hello).to_greet();

            LOG(INFO) << "Hello " << visitor;

            if (output) {
                LOG(INFO) << "Incrementing visitor count...";
                output->MutableExtension(hello_world::enclave_output_hello)
                        ->set_greeting_message(
                                absl::StrCat("Hello ", visitor, "! You are visitor #",
                                             ++visitor_count_, " to this enclave."));
                OnPutCapsule(output->MutableExtension(hello_world::output_dc), "visitor", "hello");
                LOG(INFO) << "= Encryption and Decryption =";
                std::string result;
                ASYLO_ASSIGN_OR_RETURN(result, EncryptMessage(visitor));
                LOG(INFO) << "encrypted: " << result;
                ASYLO_ASSIGN_OR_RETURN(result, DecryptMessage(result));
                LOG(INFO) << "decrypted: " << result;
                LOG(INFO) << "= Sign and Verify =";
                LOG(INFO) << "signed: " << reinterpret_cast<const char*>(SignMessage(visitor).data());
                LOG(INFO) << "verified: " << VerifyMessage(visitor, SignMessage(visitor));
            }
            return asylo::Status::OkStatus();
        }

    private:
        uint64_t visitor_count_;
        MemTable memtable;
    };

    TrustedApplication *BuildTrustedApplication() { return new HelloApplication; }

}  // namespace asylo