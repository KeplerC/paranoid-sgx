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

    bool generate_hash(capsule_pdu *dc){
        const std::string aggregated = std::to_string(dc->sender) + std::to_string(dc->timestamp)
                                        +dc->payload_in_transit;
        std::vector<uint8_t> digest;
        bool success = DoHash(aggregated, &digest);
        if (!success) return false;
        dc->hash = BytesToHexString(digest);
        return true;
    }

    bool sign_dc(capsule_pdu *dc, const std::unique_ptr <SigningKey> &signing_key) {
        std::string aggregated = dc->hash + dc->prevHash;
        dc->signature = SignMessage(aggregated, signing_key);
        return true;
    }

    bool verify_hash(const capsule_pdu *dc){
        const std::string aggregated = std::to_string(dc->sender) + std::to_string(dc->timestamp)
                                        +dc->payload_in_transit;
        std::vector<uint8_t> digest;
        bool success = DoHash(aggregated, &digest);
        if (!success) return false;
        return dc->hash == BytesToHexString(digest);
    }

    bool verify_signature(const capsule_pdu *dc, const std::unique_ptr <VerifyingKey> &verifying_key) {
        return VerifyMessage(dc->hash + dc->prevHash, dc->signature, verifying_key);
    }

    bool verify_dc(const capsule_pdu *dc, const std::unique_ptr <VerifyingKey> &verifying_key){
        
        // verify hash matches
        bool hash_result = verify_hash(dc);
        if (!hash_result) {
            LOGI << "hash verification failed!!!";
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
        std::string encrypted_aggregated;

        ASSIGN_OR_RETURN_FALSE(encrypted_aggregated, EncryptMessage(aggregated));
        dc->payload_in_transit = encrypted_aggregated;
        return true;
    }

    bool decrypt_payload(capsule_pdu *dc) {
        std::string decrypted_aggregated;
        ASSIGN_OR_RETURN_FALSE(decrypted_aggregated, DecryptMessage(dc->payload_in_transit));
        std::stringstream ss(decrypted_aggregated);

        getline(ss, dc->payload.key, ',');
        getline(ss, dc->payload.value);

        return true;
    }

    void KvToCapsule(capsule_pdu *dc, const std::string &key, const std::string &value, const int64_t timer,
                    const int enclave_id, const std::string &msgType) {
        dc->payload.key = key;
        dc->payload.value = value;
        dc->timestamp = timer;
        dc->sender = enclave_id;
        dc->msgType = msgType;
    }

    void CapsuleToProto(const capsule_pdu *dc, hello_world::CapsulePDU *dcProto){

        dcProto->set_payload_in_transit(dc->payload_in_transit);
        dcProto->set_signature(dc->signature);
        dcProto->set_sender(dc->sender);

        dcProto->set_prevhash(dc->prevHash);
        dcProto->set_hash(dc->hash);

        dcProto->set_timestamp(dc->timestamp);
        dcProto->set_msgtype(dc->msgType);

    }

    void CapsuleFromProto(capsule_pdu *dc, const hello_world::CapsulePDU *dcProto) {

        dc->signature = dcProto->signature();
        dc->sender = dcProto->sender();
        dc->payload_in_transit = dcProto->payload_in_transit();

        dc->prevHash = dcProto->prevhash();
        dc->hash = dcProto->hash();

        dc->timestamp = dcProto->timestamp();
        dc->msgType = dcProto->msgtype();
    }

    void CapsuleToCapsule(capsule_pdu *dc_new, const capsule_pdu *dc) {
        dc_new->payload.key = dc->payload.key;
        dc_new->payload.value = dc->payload.value;
        dc_new->signature = dc->signature;
        dc_new->sender = dc->sender;
        dc_new->payload_in_transit = dc->payload_in_transit;

        dc_new->prevHash = dc->prevHash;
        dc_new->hash = dc->hash;

        dc_new->timestamp = dc->timestamp;
        dc_new->msgType = dc->msgType;
    }

    void dumpProtoCapsule(const hello_world::CapsulePDU *dcProto){
        LOGI << "Sender: "<< dcProto->sender() << ", payload_in_transit: " << dcProto->payload_in_transit() << ", Timestamp: " << (int64_t) dcProto->timestamp()
                  << ", hash: " << dcProto->hash() << ", prevHash: " << dcProto->prevhash()
                  << ", signature: " << dcProto->signature() << " message type: " << dcProto->msgtype();
    }

} // namespace asylo