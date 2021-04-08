#ifndef _PROTOUTIL_H
#define _PROTOUTIL_H

#include <string>
#include "src/capsule.h"
#include "src/proto/hello.pb.h"
namespace asylo {


void KvToCapsule(capsule_pdu *dc, const capsule_id id, const std::string key, const std::string value);

void CapsuleToProto(const capsule_pdu *dc, hello_world::CapsulePDU *dcProto);

void CapsuleFromProto(capsule_pdu *dc, const hello_world::CapsulePDU *dcProto);

void CapsuleToCapsule(capsule_pdu *dc_new, capsule_pdu *dc);

void dumpCapsule(capsule_pdu *dc);

int64_t get_current_time();
} // namespace asylo

#endif 