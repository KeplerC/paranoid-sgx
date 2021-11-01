#include "memtable.hpp"
#include "asylo/util/logging.h"
#include "common.h"
#include "capsuleBlock.cc"

kvs_payload MemTable::get(const std::string &key) {
    // First check if a lock is present. If not, key is not present and can return.
    // If present, wait to get lock and access the data item.
    kvs_payload got;
    if(!locklst.contains(key)) {
        LOGI << "Couldn't find key: " << key;
        got.key = "";
    } else {
        sgx_spinlock_t* lock = locklst.at(key);
        sgx_spin_lock(lock);
        got = memtable.at(key);
        sgx_spin_unlock(lock);
    }
    return got;
}
/* This function finds whether a lock is already present and if not creates a lock and adds to lock list.
 * The lock is then acquired and modifications done to the value.
 * Main philosophy is that concurrent reads and writes on different key values should not stall on the single memtable lock.
 */
bool MemTable::put(const kvs_payload *payload) {
    auto prev_iter_lock = locklst.find(payload->key);
    if(prev_iter_lock != locklst.end()) {
        // key already exists
        sgx_spinlock_t* lock = prev_iter_lock->second;
        sgx_spin_lock(lock);
        auto prev_iter = memtable.find(payload->key);
        // No need to check prev_iter with end since locklst and memtable keys are synchronized
        int64_t prev_timestamp = prev_iter->second.txn_timestamp;
        //the timestamp of this payload is earlier, skip the change
        if (payload->txn_timestamp <= prev_timestamp){
            LOGI << "[EARLIER DISCARDED] Timestamp of incoming payload key: " << payload->key
                      << ", timestamp: " << payload->txn_timestamp << " ealier than "  << prev_timestamp;
            sgx_spin_unlock(lock);
            return false;
        }
        else{
            memtable[payload->key] = *payload;
            write_out_if_full();
            LOGI << "[SAME PAYLOAD UPDATED] Timestamp of incoming payload key: " << payload->key
                 << ", timestamp: " << payload->txn_timestamp << " replaces "  << prev_timestamp;
            sgx_spin_unlock(lock);
            return true;
        }
    } else {
        // key does not exist, create spinlock object and add to lock list.
        sgx_spinlock_t* lock = new sgx_spinlock_t(0);
        locklst[payload->key] = lock; // add new lock to locklst
        sgx_spin_lock(lock);
        memtable[payload->key] = *payload;
        write_out_if_full();
        sgx_spin_unlock(lock);
        return true;
    }
}

void MemTable::write_out_if_full() {
    // TODO - capacity check: number of kv pairs, but should be based on amount of memory
    if (memtable.size() > max_size) {
        // write out entire memtable to level 0 of tree
        Level level_zero = CapsuleIndex.levels.front();
        CapsuleBlock capsule_block (0);
        
        // TODO - how to initialize min/max?
        std::string min_key;
        std::string max_key;

        for ( const auto &p : memtable ) {
            kvs_payload payload = p.second;
            capsule_block.addKVPair(payload.key, payload.value, payload.txn_timestamp)
            min_key = min(min_key, p.first);
            max_key = max(max_key, p.first);
        } 

        capsule_block.setMinKey(min_key);
        capsule_block.setMaxKey(max_key);

        std::string record_hash = capsule_block.writeOut();
        
        level_zero.addBlock(&capsule_block, record_hash);
    }
}

