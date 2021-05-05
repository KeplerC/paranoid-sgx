#ifndef _CAPSULE_H_
#define _CAPSULE_H_

#include <string>
// #include <vector>
#include "common.h"

typedef struct {
    std::string key;
    std::string value;
    int64_t txn_timestamp;
    std::string txn_msgType;
} kvs_payload;

typedef struct {
    
    kvs_payload payload; // TODO: change to vector<kvs_payload> for batching
    std::string payload_in_transit;
    std::string signature;
    int sender;
    
    std::string prevHash; //Hash ptr to the previous record, not needed for the minimal prototype
    std::string hash;

    int64_t timestamp;
    std::string msgType;

} capsule_pdu;


#define DUMP_CAPSULE(dc) LOGI << "DC Sender: "<< dc->sender << ", Key: " << dc->payload.key << ", Value: " << dc->payload.value << ", Timestamp: " << (int64_t) dc->timestamp << ", hash: " << dc->hash  << ", prevHash: " << dc->prevHash << ", signature: " << dc->signature << " payload_in_transit: " << dc->payload_in_transit << " message type: " << dc->msgType;

#define DUMP_PAYLOAD(payload) LOGI << "Payload Key: " << payload->key << ", Value: " << payload->value << ", Timestamp: " << (int64_t) payload->txn_timestamp << ", MsgType: " << payload->txn_msgType;

#endif 