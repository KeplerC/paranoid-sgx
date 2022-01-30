#include "memtable.hpp"
#include "asylo/util/logging.h"
#include "common.h"

kvs_payload MemTable::get(const std::string &key){
    kvs_payload got; 
    sgx_spin_lock(&mt_spinlock);

    if(memtable.contains(key)){
        got = memtable.at(key);
    } else {
        // LOGI << "Couldn't find key: " << key;
        got.key = ""; 
    }
    sgx_spin_unlock(&mt_spinlock);
    return got;
}

bool MemTable::put(const kvs_payload *payload){
    sgx_spin_lock(&mt_spinlock);
    auto prev_iter = memtable.find(payload->key);

    if(prev_iter != memtable.end()){
        // payload with same key exists
        int64_t prev_timestamp = prev_iter->second.txn_timestamp;
        //the timestamp of this payload is earlier, skip the change
        if (payload->txn_timestamp <= prev_timestamp){
            LOGI << "[EARLIER DISCARDED] Timestamp of incoming payload key: " << payload->key
                      << ", timestamp: " << payload->txn_timestamp << " ealier than "  << prev_timestamp;
            sgx_spin_unlock(&mt_spinlock);
            return false;
        }
        else{
            memtable[payload->key] = *payload;
            LOGI << "[SAME PAYLOAD UPDATED] Timestamp of incoming payload key: " << payload->key
                 << ", timestamp: " << payload->txn_timestamp << " replaces "  << prev_timestamp;
            sgx_spin_unlock(&mt_spinlock);
            return true;
        }
    } else {
        // new key
        memtable[payload->key] = *payload;
    }
    sgx_spin_unlock(&mt_spinlock);
    return true;
}