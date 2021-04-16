#ifndef _CAPSULE_H_
#define _CAPSULE_H_

#include <string>
// Size of DC payload 
#define DC_PAYLOAD_SZ 256

// TODO want to make this 256 bit
typedef __int128_t capsule_id;

typedef struct {
    std::string key;
    std::string value;
} kvs_payload;

typedef struct {
    
    capsule_id id;
    kvs_payload payload;
    std::string signature;
    int sender;
    
    std::string prevHash; //Hash ptr to the previous record, not needed for the minimal prototype
    std::string metaHash;
    std::string dataHash;
    std::string syncHash;

    int64_t timestamp;

} capsule_pdu;


#define DUMP_CAPSULE(dc) LOG(INFO) << "Sender: "<< dc->sender << ", DataCapsule id: " << (long) dc->id << ", Key: " << dc->payload.key << ", Value: " << dc->payload.value << ", Timestamp: " << (int64_t) dc->timestamp << ", dataHash: " << dc->dataHash << ", metaHash: " << dc->metaHash; //<< ", syncHash: " << dc->syncHash;

#endif 