#ifndef _MEMTBL_H
#define _MEMTBL_H

#include "absl/container/flat_hash_map.h"
#include "capsule.h"
#include "sgx_spinlock.h"

class MemTable {
  public:
    bool put(capsule_pdu *dc);
    capsule_pdu get(capsule_id id);
    MemTable(){ mt_spinlock = 0; }
  private:
    absl::flat_hash_map<capsule_id, capsule_pdu> memtable;
    // TODO (hanming): one spinlock per entry for better performance
    sgx_spinlock_t mt_spinlock;
};

#endif