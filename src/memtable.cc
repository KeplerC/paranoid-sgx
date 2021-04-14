#include "memtable.hpp"
#include "asylo/util/logging.h"

// need to make sure id exists
capsule_pdu MemTable::get(capsule_id id){
    //capsule_pdu out_dc;
    return memtable.at(id);
}

bool MemTable::put(capsule_pdu *dc) {
    auto prev_dc_iter = memtable.find(dc->id);

    if(prev_dc_iter != memtable.end()){
        int64_t prev_timestamp = prev_dc_iter->second.timestamp;
        //the timestamp of this capsule is earlier, skip the change
        // TODO (Hanming): add client id into comparison for same timestamp dc's
        if (dc->timestamp <= prev_timestamp){
            LOG(INFO) << "[EARLIER DISCARDED] Timestamp of incoming capsule id: " << (int) dc->id << ", key: " << dc->payload.key 
                      << ", timestamp: " << dc->timestamp << " ealier than "  << prev_timestamp;
            return false;
        }
        else{
            memtable[dc->id] = *dc;
            LOG(INFO) << "[SAME CAPSULE UPDATED] Timestamp of incoming capsule id: " << (int) dc->id << ", key: " << dc->payload.key 
                      << ", timestamp: " << dc->timestamp << " replaces "  << prev_timestamp;
            //for debugging reason, I separated an else statement
            //remove the else is equivalent
            return true;
        }
    }
    memtable[dc->id] = *dc;
    return true;
}