#ifndef _PROTOUTIL_H
#define _PROTOUTIL_H

#include <string>
#include "src/kvs_include/capsule.h"
#include "src/proto/hello.pb.h"
namespace asylo {


void KvToCapsule(capsule_pdu *dc, const std::string key, const std::string value, const int enclave_id);

void CapsuleToProto(const capsule_pdu *dc, hello_world::CapsulePDU *dcProto);

void CapsuleFromProto(capsule_pdu *dc, const hello_world::CapsulePDU *dcProto);

void CapsuleToCapsule(capsule_pdu *dc_new, const capsule_pdu *dc);

void dumpCapsule(const capsule_pdu *dc);

void dumpProtoCapsule(const hello_world::CapsulePDU *dcProto);

int64_t get_current_time();
} // namespace asylo

#endif 