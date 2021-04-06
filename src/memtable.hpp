#ifndef _MEMTBL_H
#define _MEMTBL_H

#include "double_linked_list.hpp"
#include "sgx_spinlock.h"

#define MAX_MEM_SZ 300
#define BUCKET_NUM 5

struct bucket_entry{
  bool valid;
  DoublyLinkedList buckets; 
  sgx_spinlock_t  spinlock;
};

class MemTable {
  public:
    size_t getSize(); 
    bool put(capsule_pdu *dc);
    capsule_pdu *get(capsule_id id);
    __uint32_t hash(capsule_id id);
    MemTable(){
      max_capacity = MAX_MEM_SZ; 
      curr_capacity = 0; 
      memset(memtable, 0, MAX_MEM_SZ/BUCKET_NUM * sizeof(bucket_entry));
    }
  private:
    bucket_entry memtable[MAX_MEM_SZ/BUCKET_NUM];
    size_t max_capacity;  
    size_t curr_capacity; 
};

#endif