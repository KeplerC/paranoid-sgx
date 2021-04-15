#include "memtable.hpp"
#include "asylo/util/logging.h"

// need to make sure id exists
// TODO (Hanming): handle the case where id does not exist
capsule_pdu MemTable::get(capsule_id id){
    sgx_spin_lock(&mt_spinlock);
    capsule_pdu got = memtable.at(id);
    sgx_spin_unlock(&mt_spinlock);
    return got;
}

bool MemTable::put(capsule_pdu *dc) {
    sgx_spin_lock(&mt_spinlock);
    auto prev_dc_iter = memtable.find(dc->id);

    if(prev_dc_iter != memtable.end()){
        // dc with same key exists
        int64_t prev_timestamp = prev_dc_iter->second.timestamp;
        //the timestamp of this capsule is earlier, skip the change
        // TODO (Hanming): add client id into comparison for same timestamp dc's
        if (dc->timestamp <= prev_timestamp){
            LOG(INFO) << "[EARLIER DISCARDED] Timestamp of incoming capsule id: " << (int) dc->id << ", key: " << dc->payload.key 
                      << ", timestamp: " << dc->timestamp << " ealier than "  << prev_timestamp;
            sgx_spin_unlock(&mt_spinlock);
            return false;
        }
        else{
            memtable[dc->id] = *dc;
            LOG(INFO) << "[SAME CAPSULE UPDATED] Timestamp of incoming capsule id: " << (int) dc->id << ", key: " << dc->payload.key 
                      << ", timestamp: " << dc->timestamp << " replaces "  << prev_timestamp;
            sgx_spin_unlock(&mt_spinlock);
            return true;
        }
    } else {
        // new key
        memtable[dc->id] = *dc;
    }
    sgx_spin_unlock(&mt_spinlock);
    return true;
}