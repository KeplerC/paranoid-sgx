#include "memtable_new.hpp"
#include "asylo/util/logging.h"
#include "../common.h"
#include "src/capsuleDBcpp/capsuleBlock.cc"

kvs_payload MemTable::get(const std::string &key)
{
    // First check if a lock is present. If not, key is not present and can return.
    // If present, wait to get lock and access the data item.
    kvs_payload got;
    if (!locklst.contains(key))
    {
        LOGI << "Couldn't find key: " << key;
        got.key = "";
    }
    else
    {
        std::mutex *lock = locklst.at(key);
        lock.lock();
        got = memtable.at(key);
        lock.unlock();
    }
    return got;
}
/* This function finds whether a lock is already present and if not creates a lock and adds to lock list.
 * The lock is then acquired and modifications done to the value.
 * Main philosophy is that concurrent reads and writes on different key values should not stall on the single memtable lock.
 */
bool MemTable::put(const kvs_payload *payload)
{
    auto prev_iter_lock = locklst.find(payload->key);
    if (prev_iter_lock != locklst.end())
    {
        // key already exists
        std::mutex *lock = prev_iter_lock->second;
        lock.lock();
        auto prev_iter = memtable.find(payload->key);
        // No need to check prev_iter with end since locklst and memtable keys are synchronized
        int64_t prev_timestamp = prev_iter->second.txn_timestamp;
        //the timestamp of this payload is earlier, skip the change
        if (payload->txn_timestamp <= prev_timestamp)
        {
            LOGI << "[EARLIER DISCARDED] Timestamp of incoming payload key: " << payload->key
                 << ", timestamp: " << payload->txn_timestamp << " ealier than " << prev_timestamp;
           lock.unlock();
           return false;
        }
        else
        {
            memtable[payload->key] = *payload;
            write_out_if_full();
            LOGI << "[SAME PAYLOAD UPDATED] Timestamp of incoming payload key: " << payload->key
                 << ", timestamp: " << payload->txn_timestamp << " replaces " << prev_timestamp;
            lock.unlock();
            return true;
        }
    }
    else
    {
        // key does not exist, create spinlock object and add to lock list.
        std::mutex *lock = new sgx_spinlock_t(0);
        locklst[payload->key] = lock; // add new lock to locklst
        lock.lock();
        memtable[payload->key] = *payload;
        write_out_if_full();
        lock.unlock();
        return true;
    }
}

/* This function writes out entire memtable to level 0 of tree if the number of kv pairs exceeds capacity.
 */
void MemTable::write_out_if_full()
{
    // capacity check: number of kv pairs (upperbounds amount of memory when we constrain kv size)
    if (memtable.size() > max_size)
    {
        Level level_zero = CapsuleIndex.levels.front();
        CapsuleBlock capsule_block(0);

        // initialize min/max
        std::string min_key = memtable.begin()->first;
        std::string max_key = memtable.begin()->first;

        for (const auto &p : memtable)
        {
            kvs_payload payload = p.second;
            capsule_block.addKVPair(payload.key, payload.value, payload.txn_timestamp)
                min_key = min(std::string(min_key), std::string(p.first));
            max_key = max(std::string(max_key), std::string(p.first));
        }

        capsule_block.setMinKey(min_key);
        capsule_block.setMaxKey(max_key);

        std::string record_hash = capsule_block.writeOut();

        level_zero.addBlock(&capsule_block, record_hash);
    }
}
