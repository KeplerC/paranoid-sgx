#include "memtable.hpp"
#include "asylo/util/logging.h"
#include "common.h"
// need to make sure key exists. O/w exception is thrown by at
capsule_pdu MemTable::get(std::string key){
    capsule_pdu got; 
    sgx_spin_lock(&mt_spinlock);

    if(memtable.contains(key)){
        got = memtable.at(key);
    } else {
        LOG(ERROR) << "Couldn't find key: " << key;
        got.payload.key = ""; 
    }
    sgx_spin_unlock(&mt_spinlock);
    return got;
}

bool MemTable::put(capsule_pdu *dc) {
    sgx_spin_lock(&mt_spinlock);
    auto prev_dc_iter = memtable.find(dc->payload.key);

    if(prev_dc_iter != memtable.end()){
        // dc with same key exists
        int64_t prev_timestamp = prev_dc_iter->second.timestamp;
        //the timestamp of this capsule is earlier, skip the change
        // TODO (Hanming): add client id into comparison for same timestamp dc's
        if (dc->timestamp <= prev_timestamp){
            LOGI << "[EARLIER DISCARDED] Timestamp of incoming capsule key: " << dc->payload.key
                      << ", timestamp: " << dc->timestamp << " ealier than "  << prev_timestamp;
            sgx_spin_unlock(&mt_spinlock);
            return false;
        }
        else{
            memtable[dc->payload.key] = *dc;
            LOGI << "[SAME CAPSULE UPDATED] Timestamp of incoming capsule key: " << dc->payload.key
                 << ", timestamp: " << dc->timestamp << " replaces "  << prev_timestamp;
            sgx_spin_unlock(&mt_spinlock);
            return true;
        }
    } else {
        // new key
        memtable[dc->payload.key] = *dc;
    }
    sgx_spin_unlock(&mt_spinlock);
    return true;
}