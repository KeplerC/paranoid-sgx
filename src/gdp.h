#ifndef _GDP_H_
#define _GDP_H_

#include "asylo/crypto/sha256_hash_util.h"

// Size of DC payload 
#define DC_PAYLOAD_SZ 256

// TODO want to make this 256 bit
typedef __int128_t data_capsule_id;


typedef struct {
    data_capsule_id id; 
    char payload[DC_PAYLOAD_SZ];
    int payload_size; 
} data_capsule_t;

#endif 