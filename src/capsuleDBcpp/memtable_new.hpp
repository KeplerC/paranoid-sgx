#ifndef _MEMTBL_H
#define _MEMTBL_H

#include "absl/container/flat_hash_map.h"

#include "../sgx_spinlock.h"

class Memtable
{
public:
    int max_size;
    bool put(const kvs_payload *payload);
    kvs_payload get(const std::string &key);
    void write_out_if_full();
    Memtable() {}
    M_BENCHMARK_CODE
private:
    absl::flat_hash_map<std::string, kvs_payload> memtable;
    absl::flat_hash_map<std::string, sgx_spinlock_t *> locklst; // each kv has its own lock.
    absl::btree_set<std::string> sort_cache;                    // stores sorted set of keys to be used when moved to upper levels.(optimization)
};

#endif
