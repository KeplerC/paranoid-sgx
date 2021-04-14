#ifndef _MEMTBL_H
#define _MEMTBL_H

#include "absl/container/flat_hash_map.h"
#include "capsule.h"

class MemTable {
  public:
    bool put(capsule_pdu *dc);
    capsule_pdu get(capsule_id id);
  private:
    absl::flat_hash_map<capsule_id, capsule_pdu> memtable;
};

#endif