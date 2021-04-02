#include "proto_util.hpp"
#include <unistd.h>
namespace asylo {

void KvToCapsule(capsule_pdu *dc, const capsule_id id, const std::string key, const std::string value) {
    dc->id = id;
    dc->payload.key = key;
    dc->payload.value = value;
}

void CapsuleToProto(const capsule_pdu *dc, hello_world::CapsulePDU *dcProto){

    dcProto->set_id(dc->id);
    dcProto->mutable_payload()->set_key(dc->payload.key);
    dcProto->mutable_payload()->set_value(dc->payload.value);
    dcProto->set_signature(dc->signature);

    dcProto->set_prevhash(dc->prevHash);
    dcProto->set_metahash(dc->metaHash);
    dcProto->set_datahash(dc->dataHash);

}

void CapsuleFromProto(capsule_pdu *dc, const hello_world::CapsulePDU *dcProto) {

    dc->id = dcProto->id();
    dc->payload.key = dcProto->payload().key();
    dc->payload.value = dcProto->payload().value();
    dc->signature = dcProto->signature();
    
    dc->prevHash = dcProto->prevhash();
    dc->metaHash = dcProto->metahash();
    dc->dataHash = dcProto->datahash();
}

} // namespace asylo