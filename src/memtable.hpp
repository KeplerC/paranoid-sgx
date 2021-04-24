#ifndef _MEMTBL_H
#define _MEMTBL_H

#include "absl/container/flat_hash_map.h"
#include "capsule.h"
#include "sgx_spinlock.h"

class MemTable {
public:
    bool put(capsule_pdu *dc);
    capsule_pdu get(std::string key);
    MemTable(){ mt_spinlock = 0; }
private:
    absl::flat_hash_map<std::string, capsule_pdu> memtable;
    sgx_spinlock_t mt_spinlock;
};

#endif