#ifndef _CAPSULE_H_
#define _CAPSULE_H_

#include <string>
#include "common.h"
// Size of DC payload 
#define DC_PAYLOAD_SZ 256

typedef struct {
    std::string key;
    std::string value;
} kvs_payload;

typedef struct {
    
    kvs_payload payload;
    std::string payload_in_transit;
    std::string signature;
    int sender;
    
    std::string prevHash; //Hash ptr to the previous record, not needed for the minimal prototype
    std::string hash;

    int64_t timestamp;

} capsule_pdu;


#define DUMP_CAPSULE(dc) LOGI << "Sender: "<< dc->sender << ", Key: " << dc->payload.key << ", Value: " << dc->payload.value << ", Timestamp: " << (int64_t) dc->timestamp << ", hash: " << dc->hash  << ", prevHash: " << dc->prevHash << ", signature: " << dc->signature << " payload_in_transit: " << dc->payload_in_transit;

#endif 