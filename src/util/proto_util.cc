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

    bool generate_meta_data_hash(capsule_pdu *dc){
        const std::string aggregated = std::to_string(dc->sender) + std::to_string(dc->timestamp)
                                 + dc->payload.key + dc->payload.value;
        std::vector<uint8_t> digest;
        bool success = DoHash(aggregated, &digest);
        if (!success) return false;
        dc->metaHash = BytesToHexString(digest);
        return true;
    }

    bool sign_dc(capsule_pdu *dc, const std::unique_ptr <SigningKey> &signing_key) {
        std::string aggregated = dc->metaHash + dc->prevHash;
        dc->signature = SignMessage(aggregated, signing_key);
        return true;
    }

    bool verify_meta_data_hash(const capsule_pdu *dc){
        const std::string aggregated = std::to_string(dc->sender) + std::to_string(dc->timestamp)
                                 + dc->payload.key + dc->payload.value;
        std::vector<uint8_t> digest;
        bool success = DoHash(aggregated, &digest);
        if (!success) return false;
        return dc->metaHash == BytesToHexString(digest);
    }

    bool verify_signature(const capsule_pdu *dc, const std::unique_ptr <VerifyingKey> &verifying_key) {
        return VerifyMessage(dc->metaHash + dc->prevHash, dc->signature, verifying_key);
    }

    bool verify_dc(const capsule_pdu *dc, const std::unique_ptr <VerifyingKey> &verifying_key){
        
        // verify metaHash matches
        bool meta_result = verify_meta_data_hash(dc);
        if (!meta_result) {
            LOGI << "metaHash verification failed!!!";
            return false;
        }

        // verify signature
        bool sig_result = verify_signature(dc, verifying_key);
        if (!sig_result) {
            LOGI << "signature verification failed!!!";
            return false;
        }

        // TODO: verify prevHash matches. Need to clean up m_eoe_hash logic before implementation.
        // if (dc->prevHash == "init") return true; // sender's first pdu
        // auto got = m_eoe_hashes->find(dc->sender);
        // if (got == m_eoe_hashes->end()){
        //     LOGI << "prevHash verification failed!!! expected prevHash not found.";
        //     return false;
        // } else {
        //     bool prev_hash_result = got->second.first == dc->prevHash;
        //     if (!prev_hash_result) {
        //         LOGI << "prevHash verification failed!!!";
        //         LOGI << "expected: " << got->second.first;
        //         LOGI << "received: " << dc->prevHash;
        //         return false;
        //     }
        // }

        return true;
    }

    bool encrypt_payload(capsule_pdu *dc) {
        // TODO: encode key value pair to prevent key has comma
        std::string aggregated = dc->payload.key + "," + dc->payload.value;
        std::string encrypted_string;

        //ASSIGN_OR_RETURN_FALSE(encrypted_key, EncryptMessage(dc->payload.key));
        ASSIGN_OR_RETURN_FALSE(encrypted_string, EncryptMessage(aggregated));
        dc->payload.key = "";
        dc->payload.value = encrypted_string;
        return true;
    }

    bool decrypt_payload(capsule_pdu *dc) {
        std::string decrypted_key;
        std::string decrypted_value;
        std::string decrypted_aggregated;
        ASSIGN_OR_RETURN_FALSE(decrypted_aggregated, DecryptMessage(dc->payload.value));
        std::stringstream ss(decrypted_aggregated);

        getline(ss, dc->payload.key, ',');
        getline(ss, dc->payload.value);

        return true;
    }

    void KvToCapsule(capsule_pdu *dc, const std::string &key, const std::string &value, const int64_t timer,
                    const int enclave_id) {
        dc->payload.key = key;
        dc->payload.value = value;
        dc->timestamp = timer;
        dc->sender = enclave_id;
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
                  << dcProto->payload().value() << ", Timestamp: " << (int64_t) dcProto->timestamp() 
                  << ", metaHash: " << dcProto->metahash() << ", prevHash: " << dcProto->prevhash()
                  << ", signature: " << dcProto->signature();
    }

} // namespace asylo