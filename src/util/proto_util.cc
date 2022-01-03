#include "proto_util.hpp"
#include <unistd.h>
#include "asylo/util/logging.h"
#include "absl/strings/str_split.h"
// TODO: currently we get timestamp by ocall, we need optimization here
#include <sys/time.h>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <sstream>
#include "../crypto.h"
#include "../capsuleDBcpp/index.hh"
#include "../capsuleDBcpp/capsuleBlock.hh"
#include "../common.h"

namespace asylo {

    // Helper functions
    int64_t get_current_time(){
        struct timeval tp;
        gettimeofday(&tp, NULL);
        return tp.tv_sec * 1000 + tp.tv_usec / 1000;
    }

    template <typename T>
    std::string serialize_payload_l(const std::vector<T> &payload_l) {
        std::string payload_l_s;

        std::stringstream toBeSerialized;
        boost::archive::text_oarchive oa(toBeSerialized);
        oa << *payload_l;
        std::string s = toBeSerialized.str();

        return payload_l_s;
    }

    template <typename T>
    std::vector<T> deserialize_payload_l(const std::string &payload_l_s) {
        std::vector<T> payload_l;
        std::ifstream storedPayload(payload_l_s);
        boost::archive::text_iarchive ia(storedPayload);
        ia >> payload_l;
        return payload_l;
    }


    // Begin main functions
    template <typename T>
    bool generate_hash(capsule_pdu<T> *dc){
        const std::string aggregated = std::to_string(dc->sender) + std::to_string(dc->timestamp)
                                        +dc->payload_in_transit;
        std::vector<uint8_t> digest;
        bool success = DoHash(aggregated, &digest);
        if (!success) return false;
        dc->hash = BytesToHexString(digest);
        return true;
    }

    template <typename T>
    bool sign_dc(capsule_pdu<T> *dc, const std::unique_ptr <SigningKey> &signing_key) {
        std::string aggregated = dc->hash + dc->prevHash;
        dc->signature = SignMessage(aggregated, signing_key);
        return true;
    }

    template <typename T>
    bool verify_hash(const capsule_pdu<T> *dc){
        const std::string aggregated = std::to_string(dc->sender) + std::to_string(dc->timestamp)
                                        +dc->payload_in_transit;
        std::vector<uint8_t> digest;
        bool success = DoHash(aggregated, &digest);
        if (!success) return false;
        return dc->hash == BytesToHexString(digest);
    }

    template <typename T>
    bool verify_signature(const capsule_pdu<T> *dc, const std::unique_ptr <VerifyingKey> &verifying_key) {
        return VerifyMessage(dc->hash + dc->prevHash, dc->signature, verifying_key);
    }

    template <typename T>
    bool verify_dc(const capsule_pdu<T> *dc, const std::unique_ptr <VerifyingKey> &verifying_key){
        
        // verify hash matches
        bool hash_result = verify_hash(dc);
        if (!hash_result) {
            LOGI << "hash verification failed!!!";
            return false;
        }
        // LOG(INFO) << "after verify_hash";
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

    template <typename T>
    bool encrypt_payload_l(capsule_pdu<T> *dc) {
        std::string aggregated = serialize_payload_l(dc->payload_l);
        std::string encrypted_aggregated;

        ASSIGN_OR_RETURN_FALSE(encrypted_aggregated, EncryptMessage(aggregated));
        dc->payload_in_transit = encrypted_aggregated;
        return true;
    }

    template <typename T>
    bool decrypt_payload_l(capsule_pdu<T> *dc) {
        std::string decrypted_aggregated;

        ASSIGN_OR_RETURN_FALSE(decrypted_aggregated, DecryptMessage(dc->payload_in_transit));
        // std::cout << "After DecryptMessage: " << decrypted_aggregated << std::endl;
        // std::cout << std::endl;
        dc->payload_l = deserialize_payload_l<std::vector<T>>(decrypted_aggregated);
        return true;
    }

    template <typename T>
    void KvToPayload(kvs_payload *payload, const std::string &key, const std::string &value, const int64_t timer,
                    const std::string &msgType) {
        payload->key = key;
        payload->value = value;
        payload->txn_timestamp = timer;
        payload->txn_msgType = msgType;
    }

    template <typename T>
    void PayloadListToCapsule(capsule_pdu<T> *dc, const std::vector<T> *payload_l, const int enclave_id) {
        dc->payload_l = *payload_l;
        dc->timestamp = payload_l->back().txn_timestamp;
        dc->msgType = payload_l->back().txn_msgType;
        dc->sender = enclave_id;
    }

    template <typename T>
    void CapsuleToProto(const capsule_pdu<T> *dc, hello_world::CapsulePDU *dcProto){

        dcProto->set_payload_in_transit(dc->payload_in_transit);
        dcProto->set_signature(dc->signature);
        dcProto->set_sender(dc->sender);

        dcProto->set_prevhash(dc->prevHash);
        dcProto->set_hash(dc->hash);

        dcProto->set_timestamp(dc->timestamp);
        dcProto->set_msgtype(dc->msgType);

    }

    template <typename T>
    void CapsuleFromProto(capsule_pdu<T> *dc, const hello_world::CapsulePDU *dcProto) {

        dc->signature = dcProto->signature();
        dc->sender = dcProto->sender();
        dc->payload_in_transit = dcProto->payload_in_transit();

        dc->prevHash = dcProto->prevhash();
        dc->hash = dcProto->hash();

        dc->timestamp = dcProto->timestamp();
        dc->msgType = dcProto->msgtype();
    }

    template <typename T>
    void CapsuleToCapsule(capsule_pdu<T> *dc_new, const capsule_pdu<T> *dc) {
        dc_new->payload_l = dc->payload_l;

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