#include "proto_util.hpp"
#include <unistd.h>
#include "asylo/util/logging.h"
// TODO: currently we get timestamp by ocall, we need optimization here
#include <sys/time.h>
#include "../crypto.h"

namespace asylo {

    int64_t get_current_time(){
        struct timeval tp;
        gettimeofday(&tp, NULL);
        return tp.tv_sec * 1000 + tp.tv_usec / 1000;
    }

    std::string get_meta_data_hash(const capsule_pdu *dc, const std::unique_ptr <SigningKey> &signing_key){
        std::string aggregated = std::to_string(dc->timestamp) + std::to_string(dc->sender);
        return SignMessage(aggregated, signing_key);
    }

    bool verify_meta_data_hash(const capsule_pdu *dc, const std::string &signature,
                                const std::unique_ptr <VerifyingKey> &verifying_key){
        std::string aggregated = std::to_string(dc->timestamp) + std::to_string(dc->sender);
        return VerifyMessage(aggregated, signature, verifying_key);
    }

    bool verify_dc(const capsule_pdu *dc, const std::unique_ptr <VerifyingKey> &verifying_key){

        bool meta_result = verify_meta_data_hash(dc, dc->metaHash, verifying_key);
        if (!meta_result) {
            LOGI << "metaHash verification failed!!!";
        }

        return meta_result;
    }

    bool encrypt_payload(capsule_pdu *dc) {
        std::string encrypted_key;
        std::string encrypted_value;
        ASSIGN_OR_RETURN_FALSE(encrypted_key, EncryptMessage(dc->payload.key));
        ASSIGN_OR_RETURN_FALSE(encrypted_value, EncryptMessage(dc->payload.value));
        dc->payload.key = encrypted_key;
        dc->payload.value = encrypted_value;
        return true;
    }

    bool decrypt_payload(capsule_pdu *dc) {
        std::string decrypted_key;
        std::string decrypted_value;
        ASSIGN_OR_RETURN_FALSE(decrypted_key, DecryptMessage(dc->payload.key));
        ASSIGN_OR_RETURN_FALSE(decrypted_value, DecryptMessage(dc->payload.value));
        dc->payload.key = decrypted_key;
        dc->payload.value = decrypted_value;
        return true;
    }

    void KvToCapsule(capsule_pdu *dc, const std::string &key, const std::string &value, const int64_t timer,
                    const int enclave_id, const std::unique_ptr <SigningKey> &signing_key) {
        dc->payload.key = key;
        dc->payload.value = value;
        dc->timestamp = timer;
        dc->sender = enclave_id;
        dc->metaHash = get_meta_data_hash(dc, signing_key);
    }

    void CapsuleToProto(const capsule_pdu *dc, hello_world::CapsulePDU *dcProto){

        dcProto->mutable_payload()->set_key(dc->payload.key);
        dcProto->mutable_payload()->set_value(dc->payload.value);
        dcProto->set_signature(dc->signature);
        dcProto->set_sender(dc->sender);

        dcProto->set_prevhash(dc->prevHash);
        dcProto->set_metahash(dc->metaHash);

        dcProto->set_timestamp(dc->timestamp);

    }

    void CapsuleFromProto(capsule_pdu *dc, const hello_world::CapsulePDU *dcProto) {

        dc->payload.key = dcProto->payload().key();
        dc->payload.value = dcProto->payload().value();
        dc->signature = dcProto->signature();
        dc->sender = dcProto->sender();

        dc->prevHash = dcProto->prevhash();
        dc->metaHash = dcProto->metahash();

        dc->timestamp = dcProto->timestamp();
    }

    void CapsuleToCapsule(capsule_pdu *dc_new, const capsule_pdu *dc) {
        dc_new->payload.key = dc->payload.key;
        dc_new->payload.value = dc->payload.value;
        dc_new->signature = dc->signature;
        dc_new->sender = dc->sender;

        dc_new->prevHash = dc->prevHash;
        dc_new->metaHash = dc->metaHash;

        dc_new->timestamp = dc->timestamp;
    }

    void dumpProtoCapsule(const hello_world::CapsulePDU *dcProto){
        LOGI << "Sender: "<< dcProto->sender() << ", Key: " << dcProto->payload().key() << ", Value: "
                  << dcProto->payload().value() << ", Timestamp: " << (int64_t) dcProto->timestamp() << ", metaHash: " << dcProto->metahash();
    }

} // namespace asylo