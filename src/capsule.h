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
    
    std::string prevHash; //Hash ptr to the previous record, not needed for the minimal prototype
    std::string metaHash;
    std::string dataHash;

    int64_t timestamp;

} capsule_pdu;

#endif 