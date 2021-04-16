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

    std::string get_data_hash(std::string key, std::string value){
        return SignMessage(key+value);
    }

    std::string get_meta_data_hash(capsule_pdu *dc){
        std::string aggregated = std::to_string((int)dc->id) + std::to_string(dc->timestamp) + std::to_string(dc->sender) ;
        return SignMessage(aggregated);
    }

    bool verify_data_hash(std::string key, std::string value, std::string signature){
        return VerifyMessage(key + value, signature);
    }

    bool verify_meta_data_hash(capsule_pdu *dc, std::string signature){
        std::string aggregated = std::to_string((int)dc->id) + std::to_string(dc->timestamp) + std::to_string(dc->sender) ;
        return VerifyMessage(aggregated, signature);
    }

    void KvToCapsule(capsule_pdu *dc, const capsule_id id, const std::string key, const std::string value, const int enclave_id) {
        dc->id = id;
        dc->payload.key = key;
        dc->payload.value = value;
        dc->timestamp = get_current_time();
        dc->sender = enclave_id;
        dc->dataHash = get_data_hash(key, value);
        dc->metaHash = get_meta_data_hash(dc);
    }

    void CapsuleToProto(const capsule_pdu *dc, hello_world::CapsulePDU *dcProto){

        dcProto->set_id(dc->id);
        dcProto->mutable_payload()->set_key(dc->payload.key);
        dcProto->mutable_payload()->set_value(dc->payload.value);
        dcProto->set_signature(dc->signature);
        dcProto->set_sender(dc->sender);

        dcProto->set_prevhash(dc->prevHash);
        dcProto->set_metahash(dc->metaHash);
        dcProto->set_datahash(dc->dataHash);
        dcProto->set_synchash(dc->syncHash);

        dcProto->set_timestamp(dc->timestamp);

    }

    void CapsuleFromProto(capsule_pdu *dc, const hello_world::CapsulePDU *dcProto) {

        dc->id = dcProto->id();
        dc->payload.key = dcProto->payload().key();
        dc->payload.value = dcProto->payload().value();
        dc->signature = dcProto->signature();
        dc->sender = dcProto->sender();

        dc->prevHash = dcProto->prevhash();
        dc->metaHash = dcProto->metahash();
        dc->dataHash = dcProto->datahash();
        dc->syncHash = dcProto->synchash();

        dc->timestamp = dcProto->timestamp();
    }

    void CapsuleToCapsule(capsule_pdu *dc_new, const capsule_pdu *dc) {
        dc_new->id = dc->id;
        dc_new->payload.key = dc->payload.key;
        dc_new->payload.value = dc->payload.value;
        dc_new->signature = dc->signature;
        dc_new->sender = dc->sender;

        dc_new->prevHash = dc->prevHash;
        dc_new->metaHash = dc->metaHash;
        dc_new->dataHash = dc->dataHash;
        dc_new->syncHash = dc->syncHash;

        dc_new->timestamp = dc->timestamp;
    }

    void dumpProtoCapsule(const hello_world::CapsulePDU *dcProto){
        LOG(INFO) << "Sender: "<< dcProto->sender() << ",DataCapsule id: " << (int) dcProto->id() << ", Key: " << dcProto->payload().key() << ", Value: "
                  << dcProto->payload().value() << ", Timestamp: " << (int64_t) dcProto->timestamp() << ", dataHash: " << dcProto->datahash() <<  ", metaHash: " << dcProto->metahash();//", syncHash: " << dcProto->synchash();
    }

} // namespace asylo